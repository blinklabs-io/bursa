// Package chain reads state from the embedded Dingo node. It primarily uses
// the node's loopback Blockfrost REST API and may enrich fields from Dingo's
// local metadata DB when the compatibility API omits them. It never contacts
// any external service.
package chain

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	_ "github.com/glebarez/go-sqlite"
)

// ErrNotFound is returned when the node reports the queried resource does not
// exist (HTTP 404) — e.g. an account/stake credential not yet seen on chain.
// Callers treat it as "empty" rather than a hard failure.
var ErrNotFound = errors.New("chain: resource not found")

var errPageLimitExceeded = errors.New("chain: pagination limit exceeded")

// Client talks to a Blockfrost-compatible API at BaseURL (the local node).
type Client struct {
	BaseURL      string
	http         *http.Client
	dingoDataDir string
}

type ClientOption func(*Client)

// WithDingoDataDir enables read-only local metadata lookups for chain state
// that the embedded Blockfrost compatibility API does not expose.
func WithDingoDataDir(dir string) ClientOption {
	return func(c *Client) {
		c.dingoDataDir = dir
	}
}

// NewClient builds a client for the node's loopback Blockfrost port.
func NewClient(port uint, opts ...ClientOption) *Client {
	return NewClientURL(fmt.Sprintf("http://127.0.0.1:%d", port), opts...)
}

// NewClientURL builds a client for an explicit base URL (used in tests).
func NewClientURL(baseURL string, opts ...ClientOption) *Client {
	c := &Client{BaseURL: baseURL, http: &http.Client{Timeout: 10 * time.Second}}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// AccountInfo mirrors GET /api/v0/accounts/{stake_address}.
type AccountInfo struct {
	StakeAddress       string  `json:"stake_address"`
	Active             bool    `json:"active"`
	Registered         bool    `json:"registered"`
	ActiveEpoch        *int64  `json:"active_epoch"`
	ControlledAmount   string  `json:"controlled_amount"`
	RewardsSum         string  `json:"rewards_sum"`
	WithdrawableAmount string  `json:"withdrawable_amount"`
	PoolID             *string `json:"pool_id"`
	DRepID             *string `json:"drep_id"`
}

// Amount is one asset entry in a UTxO (unit "lovelace" or policy+hexname).
type Amount struct {
	Unit     string `json:"unit"`
	Quantity string `json:"quantity"`
}

// UTxO mirrors one entry of GET /api/v0/addresses/{address}/utxos.
type UTxO struct {
	Address     string   `json:"address"`
	TxHash      string   `json:"tx_hash"`
	OutputIndex int      `json:"output_index"`
	Amount      []Amount `json:"amount"`
	Block       string   `json:"block"`
}

// AddressTx mirrors one entry of GET /api/v0/addresses/{address}/transactions.
type AddressTx struct {
	TxHash      string `json:"tx_hash"`
	TxIndex     int    `json:"tx_index"`
	BlockHeight uint64 `json:"block_height"`
	BlockTime   int64  `json:"block_time"`
}

// Delegation mirrors one entry of GET /api/v0/accounts/{stake}/delegations.
type Delegation struct {
	ActiveEpoch int32  `json:"active_epoch"`
	TxHash      string `json:"tx_hash"`
	Amount      string `json:"amount"`
	PoolID      string `json:"pool_id"`
}

// Reward mirrors one entry of GET /api/v0/accounts/{stake}/rewards.
type Reward struct {
	Epoch  int32  `json:"epoch"`
	Amount string `json:"amount"`
	PoolID string `json:"pool_id"`
}

// PoolInfo describes a stake pool's on-chain parameters, as the wallet needs
// them to present a verified pool readout before delegation. dingo exposes pools
// only through the paginated GET /api/v0/pools/extended list (there is no
// per-pool lookup), so Pool fetches that list and filters by ID; the fields
// mirror one PoolExtendedResponse entry (margin_cost, declared_pledge,
// fixed_cost, live_stake, active_stake).
type PoolInfo struct {
	PoolID         string  `json:"pool_id"`
	Hex            string  `json:"hex"`
	VrfKey         string  `json:"vrf_key"`
	ActiveStake    string  `json:"active_stake"`
	LiveStake      string  `json:"live_stake"`
	DeclaredPledge string  `json:"declared_pledge"`
	FixedCost      string  `json:"fixed_cost"`
	MarginCost     float64 `json:"margin_cost"`
}

// ProtocolParams holds the protocol parameters the wallet needs for delegation:
// the refundable deposits for stake-key registration (key_deposit) and DRep
// registration (drep_deposit). It mirrors the subset of dingo's
// GET /api/v0/epochs/latest/parameters that this feature uses; key_deposit and
// pool_deposit are always present, drep_deposit is null in pre-Conway eras.
type ProtocolParams struct {
	KeyDeposit  string  `json:"key_deposit"`
	PoolDeposit string  `json:"pool_deposit"`
	DRepDeposit *string `json:"drep_deposit"`
}

// DRepInfo describes a delegated representative as returned by
// GET /api/v0/governance/dreps/{drep_id}. It confirms the DRep exists on chain
// (the node 404s an unknown DRep, surfaced as ErrNotFound) and reports whether
// it is currently registered/active.
type DRepInfo struct {
	DRepID     string `json:"drep_id"`
	Hex        string `json:"hex"`
	HasScript  bool   `json:"has_script"`
	Registered bool   `json:"registered"`
	Amount     string `json:"amount"`
	Active     bool   `json:"active"`
	LiveStake  string `json:"live_stake"`
}

type accountAddress struct {
	Address string `json:"address"`
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	if resp == nil {
		return fmt.Errorf("GET %s: nil response", path)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("GET %s: status %d: %s", path, resp.StatusCode, string(body))
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

// pageSize is the node's maximum (and default) rows per list response.
const pageSize = 100

const maxPages = 1000

// getAllPages fetches every page of a list endpoint. The node caps pages at
// pageSize rows; a page with fewer rows is the last one.
func getAllPages[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	return getAllPagesLimit[T](ctx, c, path, maxPages)
}

func getAllPagesLimit[T any](ctx context.Context, c *Client, path string, maxPages int) ([]T, error) {
	if maxPages < 1 {
		return nil, fmt.Errorf("%w: invalid max page count %d", errPageLimitExceeded, maxPages)
	}
	var all []T
	for page := 1; page <= maxPages; page++ {
		var rows []T
		paged := fmt.Sprintf("%s?count=%d&page=%d", path, pageSize, page)
		if err := c.get(ctx, paged, &rows); err != nil {
			return nil, err
		}
		all = append(all, rows...)
		if len(rows) < pageSize {
			return all, nil
		}
	}
	return nil, fmt.Errorf("%w: %s exceeded %d pages", errPageLimitExceeded, path, maxPages)
}

func (c *Client) Account(ctx context.Context, stakeAddr string) (AccountInfo, error) {
	var out AccountInfo
	err := c.get(ctx, "/api/v0/accounts/"+stakeAddr, &out)
	return out, err
}

const (
	dingoDRepTypeAddrKeyHash      = 0
	dingoDRepTypeScriptHash       = 1
	dingoDRepTypeAlwaysAbstain    = 2
	dingoDRepTypeNoConfidence     = 3
	dingoAccountCredentialKeyHash = 0
	dingoAccountCredentialScript  = 1
)

// AccountDRepID reads the account's current vote delegation from Dingo's local
// metadata DB. Dingo v0.58 does not include drep_id in its Blockfrost-compatible
// account response, but it persists the value in account.drep/account.drep_type.
func (c *Client) AccountDRepID(ctx context.Context, stakeAddr string) (*string, error) {
	if c.dingoDataDir == "" {
		return nil, nil
	}
	metadataPath := filepath.Join(c.dingoDataDir, "metadata.sqlite")
	if _, err := os.Stat(metadataPath); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("account drep metadata: %w", err)
	}
	credentialTag, stakingKey, err := stakeCredential(stakeAddr)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", sqliteReadOnlyDSN(metadataPath))
	if err != nil {
		return nil, fmt.Errorf("open account drep metadata: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	var drep nullableBytes
	var drepType sql.NullInt64
	err = db.QueryRowContext(
		ctx,
		`SELECT drep, drep_type FROM account WHERE credential_tag = ? AND staking_key = ? AND active = 1`,
		credentialTag,
		stakingKey,
	).Scan(&drep, &drepType)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query account drep metadata: %w", err)
	}
	if !drepType.Valid {
		return nil, nil
	}
	if drepType.Int64 < 0 {
		return nil, fmt.Errorf("account drep metadata: unknown drep_type %d", drepType.Int64)
	}
	id, ok, err := dingoDRepID(drep.Bytes, uint64(drepType.Int64))
	if err != nil || !ok {
		return nil, err
	}
	return &id, nil
}

func sqliteReadOnlyDSN(path string) string {
	u := url.URL{Scheme: "file", Path: path}
	q := u.Query()
	q.Set("mode", "ro")
	q.Add("_pragma", "busy_timeout(30000)")
	q.Add("_pragma", "foreign_keys(1)")
	u.RawQuery = q.Encode()
	return u.String()
}

func stakeCredential(stakeAddr string) (uint8, []byte, error) {
	addr, err := lcommon.NewAddress(stakeAddr)
	if err != nil {
		return 0, nil, fmt.Errorf("parse stake address: %w", err)
	}
	hash := addr.StakeKeyHash()
	if hash == lcommon.NewBlake2b224(nil) {
		return 0, nil, errors.New("parse stake address: no stake credential")
	}
	var credentialTag uint8
	switch addr.StakingPayload().(type) {
	case lcommon.AddressPayloadKeyHash:
		credentialTag = dingoAccountCredentialKeyHash
	case lcommon.AddressPayloadScriptHash:
		credentialTag = dingoAccountCredentialScript
	default:
		return 0, nil, errors.New("parse stake address: unsupported stake credential")
	}
	return credentialTag, hash.Bytes(), nil
}

func dingoDRepID(drep []byte, drepType uint64) (string, bool, error) {
	switch drepType {
	case dingoDRepTypeAddrKeyHash:
		if len(drep) == 0 {
			return "", false, nil
		}
		if len(drep) != lcommon.AddressHashSize {
			return "", false, fmt.Errorf("account drep metadata: key hash has %d bytes", len(drep))
		}
		return "drep-keyHash-" + hex.EncodeToString(drep), true, nil
	case dingoDRepTypeScriptHash:
		if len(drep) == 0 {
			return "", false, nil
		}
		if len(drep) != lcommon.AddressHashSize {
			return "", false, fmt.Errorf("account drep metadata: script hash has %d bytes", len(drep))
		}
		return "drep-scriptHash-" + hex.EncodeToString(drep), true, nil
	case dingoDRepTypeAlwaysAbstain:
		return "drep_abstain", true, nil
	case dingoDRepTypeNoConfidence:
		return "drep_no_confidence", true, nil
	default:
		return "", false, fmt.Errorf("account drep metadata: unknown drep_type %d", drepType)
	}
}

type nullableBytes struct {
	Bytes []byte
}

func (n *nullableBytes) Scan(value any) error {
	if value == nil {
		n.Bytes = nil
		return nil
	}
	switch v := value.(type) {
	case []byte:
		n.Bytes = append(n.Bytes[:0], v...)
		return nil
	case string:
		n.Bytes = append(n.Bytes[:0], v...)
		return nil
	default:
		return fmt.Errorf("cannot scan %T into nullableBytes", value)
	}
}

func (c *Client) AccountAddresses(ctx context.Context, stakeAddr string) ([]string, error) {
	rows, err := getAllPages[accountAddress](ctx, c, "/api/v0/accounts/"+stakeAddr+"/addresses")
	if err != nil {
		return nil, err
	}
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Address
	}
	return out, nil
}

func (c *Client) AddressUTxOs(ctx context.Context, addr string) ([]UTxO, error) {
	return getAllPages[UTxO](ctx, c, "/api/v0/addresses/"+addr+"/utxos")
}

func (c *Client) AddressTransactions(ctx context.Context, addr string) ([]AddressTx, error) {
	return getAllPages[AddressTx](ctx, c, "/api/v0/addresses/"+addr+"/transactions")
}

func (c *Client) AccountDelegations(ctx context.Context, stakeAddr string) ([]Delegation, error) {
	return getAllPages[Delegation](ctx, c, "/api/v0/accounts/"+stakeAddr+"/delegations")
}

func (c *Client) AccountRewards(ctx context.Context, stakeAddr string) ([]Reward, error) {
	return getAllPages[Reward](ctx, c, "/api/v0/accounts/"+stakeAddr+"/rewards")
}

// ProtocolParams returns the current protocol parameters subset the wallet needs
// for delegation (the refundable deposits). Backed by
// GET /api/v0/epochs/latest/parameters.
func (c *Client) ProtocolParams(ctx context.Context) (ProtocolParams, error) {
	var out ProtocolParams
	err := c.get(ctx, "/api/v0/epochs/latest/parameters", &out)
	return out, err
}

// Pool returns the on-chain parameters for poolID. dingo has no per-pool lookup
// endpoint; it exposes pools only via the paginated GET /api/v0/pools/extended
// list, so Pool walks that list and returns the matching entry. A pool the node
// has not seen yields ErrNotFound — the wallet treats that as "not found by your
// node" and refuses to delegate.
func (c *Client) Pool(ctx context.Context, poolID string) (PoolInfo, error) {
	pools, err := getAllPages[PoolInfo](ctx, c, "/api/v0/pools/extended")
	if err != nil {
		return PoolInfo{}, err
	}
	for _, p := range pools {
		if p.PoolID == poolID {
			return p, nil
		}
	}
	return PoolInfo{}, ErrNotFound
}

// DRep confirms a delegated representative exists on chain and returns its
// registration state. Backed by GET /api/v0/governance/dreps/{drep_id}; an
// unknown DRep yields ErrNotFound. drepID is the bech32 drep1… identifier (the
// node also accepts the predefined "drep_always_abstain" /
// "drep_always_no_confidence" forms, but those are never queried — they have no
// on-chain registration).
func (c *Client) DRep(ctx context.Context, drepID string) (DRepInfo, error) {
	var out DRepInfo
	err := c.get(ctx, "/api/v0/governance/dreps/"+url.PathEscape(drepID), &out)
	return out, err
}
