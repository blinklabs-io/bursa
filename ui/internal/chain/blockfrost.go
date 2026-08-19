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
	"strconv"
	"sync"
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

	poolMu            sync.Mutex
	poolCache         map[string]PoolInfo
	poolCacheComplete bool
	poolCacheUntil    time.Time
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
//
// Note: the node's address-utxos endpoint does NOT populate InlineDatum (it is
// always nil there in dingo); only DataHash is set. To obtain a script UTxO's
// inline datum, fetch the transaction's outputs via TxOutputs and match by
// OutputIndex (the tx-utxos endpoint does populate InlineDatum).
type UTxO struct {
	Address     string   `json:"address"`
	TxHash      string   `json:"tx_hash"`
	OutputIndex int      `json:"output_index"`
	Amount      []Amount `json:"amount"`
	Block       string   `json:"block"`
	DataHash    *string  `json:"data_hash"`
	InlineDatum *string  `json:"inline_datum"`
}

// TxOutput mirrors one output of GET /api/v0/txs/{hash}/utxos. Unlike the
// address-utxos endpoint, this one carries the inline datum (hex-encoded CBOR)
// for script outputs, which the DEX pool parsers need.
type TxOutput struct {
	Address     string   `json:"address"`
	OutputIndex int      `json:"output_index"`
	Amount      []Amount `json:"amount"`
	DataHash    *string  `json:"data_hash"`
	InlineDatum *string  `json:"inline_datum"`
}

// txUTxOsResponse mirrors GET /api/v0/txs/{hash}/utxos.
type txUTxOsResponse struct {
	Hash    string     `json:"hash"`
	Outputs []TxOutput `json:"outputs"`
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

// Reward mirrors one entry of GET /api/v0/accounts/{stake}/rewards. Type is the
// reward kind (e.g. "member"/"leader") when the node reports it; it is optional
// because not every reward source populates it.
type Reward struct {
	Epoch  int32  `json:"epoch"`
	Amount string `json:"amount"`
	PoolID string `json:"pool_id"`
	Type   string `json:"type"`
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
	// LiveSaturation is the pool's live stake as a fraction of the saturation
	// point (1.0 = fully saturated), as reported by /pools/extended. It is 0
	// when the node's list omits it.
	LiveSaturation float64 `json:"live_saturation"`
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
	// AnchorURL is the DRep's on-chain metadata anchor (a pointer to an
	// off-chain document), when the node has one indexed. It is populated by
	// the DReps directory listing (read from Dingo's local metadata DB); the
	// single-DRep HTTP lookup leaves it empty. The wallet never fetches the
	// URL — it is displayed as-is, so browsing stays node-local.
	AnchorURL string `json:"anchor_url,omitempty"`
}

// Genesis mirrors GET /api/v0/genesis: the network's immutable genesis
// parameters. SlotsPerKESPeriod and EpochLength drive the SPO KES-period and
// epoch math; both are served by the embedded node, never an external service.
type Genesis struct {
	EpochLength       int `json:"epoch_length"`
	SlotsPerKESPeriod int `json:"slots_per_kes_period"`
	SlotLength        int `json:"slot_length"`
	MaxKESEvolutions  int `json:"max_kes_evolutions"`
	NetworkMagic      int `json:"network_magic"`
}

// EpochInfo mirrors GET /api/v0/epochs/latest (the fields the wallet uses).
type EpochInfo struct {
	Epoch     uint64 `json:"epoch"`
	StartTime int64  `json:"start_time"`
	EndTime   int64  `json:"end_time"`
}

// AssetAddress mirrors one entry of GET /api/v0/assets/{asset}/addresses: an
// address currently holding some quantity of the asset. Used to resolve an
// ADA Handle NFT to its current holder (see internal/handle).
type AssetAddress struct {
	Address  string `json:"address"`
	Quantity string `json:"quantity"`
}

// AssetInfo mirrors GET /api/v0/assets/{asset}: a native asset's on-chain
// identity, plus whatever CIP-25/68-style on-chain metadata the node has
// indexed for it. OnchainMetadata is left as raw JSON (null when absent)
// rather than a typed struct, since the standard defines no fixed schema
// (name/image/decimals/etc. are all optional, standard-specific keys) —
// callers parse the fields they need defensively.
//
// Dingo v0.58's asset response leaves OnchainMetadata null. When a Dingo data
// directory is configured, Client.Asset fills that gap from the node's locally
// indexed CIP-25 (label 721) transaction metadata.
type AssetInfo struct {
	Asset           string          `json:"asset"`
	PolicyID        string          `json:"policy_id"`
	AssetName       string          `json:"asset_name"`
	AssetNameASCII  string          `json:"asset_name_ascii"`
	Fingerprint     string          `json:"fingerprint"`
	Quantity        string          `json:"quantity"`
	OnchainMetadata json.RawMessage `json:"onchain_metadata"`
}

const cip25MetadataLabel = 721

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

const poolCacheTTL = time.Minute

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

// TxInfo mirrors the subset of GET /api/v0/txs/{hash} the wallet's transaction
// history needs: the authoritative fee and the transaction's block placement.
// An unknown hash yields ErrNotFound.
type TxInfo struct {
	Hash        string `json:"hash"`
	Block       string `json:"block"`
	BlockHeight uint64 `json:"block_height"`
	BlockTime   int64  `json:"block_time"`
	Index       int    `json:"index"`
	Fees        string `json:"fees"`
}

// Transaction fetches a transaction's summary (fee, block placement) from
// GET /api/v0/txs/{hash}.
func (c *Client) Transaction(ctx context.Context, hash string) (TxInfo, error) {
	var out TxInfo
	err := c.get(ctx, "/api/v0/txs/"+url.PathEscape(hash), &out)
	return out, err
}

// TxIO is one input or output of a transaction, as returned by
// GET /api/v0/txs/{hash}/utxos: the address it belongs to and its per-asset
// amounts (unit "lovelace" or policy+hexname, same shape as UTxO.Amount).
type TxIO struct {
	Address     string   `json:"address"`
	Amount      []Amount `json:"amount"`
	TxHash      string   `json:"tx_hash,omitempty"`
	OutputIndex int      `json:"output_index"`
}

// TxUTxOs mirrors GET /api/v0/txs/{hash}/utxos: a transaction's full set of
// inputs and outputs. The wallet diffs these against its own addresses to
// compute a transaction's direction and net amount, entirely from node data.
type TxUTxOs struct {
	Hash    string `json:"hash"`
	Inputs  []TxIO `json:"inputs"`
	Outputs []TxIO `json:"outputs"`
}

// TransactionUTxOs fetches a transaction's inputs and outputs from
// GET /api/v0/txs/{hash}/utxos.
func (c *Client) TransactionUTxOs(ctx context.Context, hash string) (TxUTxOs, error) {
	var out TxUTxOs
	err := c.get(ctx, "/api/v0/txs/"+url.PathEscape(hash)+"/utxos", &out)
	return out, err
}

// BlockTip is the subset of GET /api/v0/blocks/latest the wallet needs: the
// chain's current block height, used to compute a transaction's confirmation
// count (tip height minus the transaction's own block height).
type BlockTip struct {
	Height uint64 `json:"height"`
}

// LatestBlock fetches the chain tip from GET /api/v0/blocks/latest.
func (c *Client) LatestBlock(ctx context.Context) (BlockTip, error) {
	var out BlockTip
	err := c.get(ctx, "/api/v0/blocks/latest", &out)
	return out, err
}

// TxOutputs returns the outputs of a transaction, including each output's
// inline datum (hex CBOR) when present. Used to recover a script UTxO's inline
// datum, which the address-utxos endpoint does not expose.
func (c *Client) TxOutputs(ctx context.Context, txHash string) ([]TxOutput, error) {
	var out txUTxOsResponse
	if err := c.get(ctx, "/api/v0/txs/"+txHash+"/utxos", &out); err != nil {
		return nil, err
	}
	return out.Outputs, nil
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
// list, so Pool scans pages until it finds the requested entry and keeps a
// short-lived index for repeated UI/build verification. A pool the node has not
// seen yields ErrNotFound — the wallet treats that as "not found by your node"
// and refuses to delegate.
func (c *Client) Pool(ctx context.Context, poolID string) (PoolInfo, error) {
	if pool, found, complete := c.cachedPool(poolID); found || complete {
		if found {
			return pool, nil
		}
		return PoolInfo{}, ErrNotFound
	}

	for page := 1; page <= maxPages; page++ {
		var rows []PoolInfo
		paged := fmt.Sprintf("/api/v0/pools/extended?count=%d&page=%d", pageSize, page)
		if err := c.get(ctx, paged, &rows); err != nil {
			return PoolInfo{}, err
		}
		complete := len(rows) < pageSize
		c.cachePools(rows, complete)
		for _, p := range rows {
			if p.PoolID == poolID {
				return p, nil
			}
		}
		if complete {
			return PoolInfo{}, ErrNotFound
		}
	}
	return PoolInfo{}, fmt.Errorf("%w: /api/v0/pools/extended exceeded %d pages", errPageLimitExceeded, maxPages)
}

// Pools returns the full stake-pool directory the node has indexed, drawn from
// the paginated GET /api/v0/pools/extended list (the same source Pool filters).
// It is used by the read-only pool-directory browser; the per-page cache Pool
// maintains is deliberately not consulted or populated here, since the directory
// wants the complete list rather than a single lookup.
func (c *Client) Pools(ctx context.Context) ([]PoolInfo, error) {
	return getAllPages[PoolInfo](ctx, c, "/api/v0/pools/extended")
}

func (c *Client) cachedPool(poolID string) (PoolInfo, bool, bool) {
	c.poolMu.Lock()
	defer c.poolMu.Unlock()
	if c.poolCache == nil || time.Now().After(c.poolCacheUntil) {
		c.poolCache = nil
		c.poolCacheComplete = false
		c.poolCacheUntil = time.Time{}
		return PoolInfo{}, false, false
	}
	pool, found := c.poolCache[poolID]
	return pool, found, c.poolCacheComplete
}

func (c *Client) cachePools(pools []PoolInfo, complete bool) {
	now := time.Now()
	c.poolMu.Lock()
	defer c.poolMu.Unlock()
	if c.poolCache == nil || now.After(c.poolCacheUntil) {
		c.poolCache = make(map[string]PoolInfo)
		c.poolCacheComplete = false
		c.poolCacheUntil = now.Add(poolCacheTTL)
	}
	for _, p := range pools {
		if p.PoolID == "" {
			continue
		}
		c.poolCache[p.PoolID] = p
	}
	if complete {
		c.poolCacheComplete = true
	}
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

// DReps returns the delegated representatives the embedded node has indexed, for
// the read-only DRep-directory browser — the governance analogue of Pools. The
// list is read directly from Dingo's local metadata DB (the same node-local
// source AccountDRepID uses), never an external service. Dingo also serves a
// paginated GET /api/v0/governance/dreps list whose entries carry
// retired/expired status and resolved CIP-119 anchor metadata this local read
// cannot derive; moving to it is tracked separately, since it changes the
// directory's rows and status semantics. Voting power is enriched best-effort
// from the same DB; if that aggregate (which reads internal account/utxo
// tables) fails, the directory still lists every DRep with empty amounts rather
// than failing outright. When no Dingo data dir is configured the directory is
// empty.
func (c *Client) DReps(ctx context.Context) ([]DRepInfo, error) {
	if c.dingoDataDir == "" {
		return nil, nil
	}
	metadataPath := filepath.Join(c.dingoDataDir, "metadata.sqlite")
	if _, err := os.Stat(metadataPath); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("drep directory: %w", err)
	}
	db, err := sql.Open("sqlite", sqliteReadOnlyDSN(metadataPath))
	if err != nil {
		return nil, fmt.Errorf("open drep directory metadata: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	// ORDER BY gives a stable row order so the directory's server-side paging
	// (which slices this list by position) doesn't shift results between
	// successive page requests.
	rows, err := db.QueryContext(
		ctx,
		`SELECT credential_tag, credential, anchor_url, active FROM drep ORDER BY credential_tag, credential`,
	)
	if err != nil {
		return nil, fmt.Errorf("query drep directory: %w", err)
	}
	defer rows.Close()

	var (
		dreps []DRepInfo
		keys  []string // power-map key per entry, in lockstep with dreps
	)
	for rows.Next() {
		var (
			tag    uint8
			cred   []byte
			anchor sql.NullString
			active bool
		)
		if err := rows.Scan(&tag, &cred, &anchor, &active); err != nil {
			return nil, fmt.Errorf("scan drep row: %w", err)
		}
		if len(cred) != lcommon.AddressHashSize {
			continue // skip predefined/malformed credentials
		}
		id, err := drepBech32(tag, cred)
		if err != nil {
			continue
		}
		hexCred := hex.EncodeToString(cred)
		dreps = append(dreps, DRepInfo{
			DRepID:     id,
			Hex:        hexCred,
			HasScript:  tag == dingoAccountCredentialScript,
			Registered: active,
			Active:     active,
			AnchorURL:  anchor.String,
		})
		keys = append(keys, drepPowerKey(tag, hexCred))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate drep rows: %w", err)
	}

	// Enrich with voting power (best-effort — see method doc).
	if powers, perr := drepVotingPowers(ctx, db); perr == nil {
		for i := range dreps {
			amount := powers[keys[i]] // absent → "" → "0" below
			if amount == "" {
				amount = "0"
			}
			dreps[i].Amount = amount
			dreps[i].LiveStake = amount
		}
	}
	return dreps, nil
}

// drepVotingPowers sums each DRep's delegated voting power (delegators' UTxO
// lovelace + rewards) from Dingo's local metadata DB, keyed by drepPowerKey. It
// mirrors Dingo's own GetDRepVotingPower aggregate but batches every DRep in one
// pass. Only credential-based DReps (drep_type 0 key / 1 script) have power;
// the predefined abstain/no-confidence targets are excluded.
func drepVotingPowers(ctx context.Context, db *sql.DB) (map[string]string, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT a.drep_type AS tag, a.drep AS cred,
		       COALESCE(SUM(COALESCE(u.utxo_sum, 0) + COALESCE(CAST(a.reward AS INTEGER), 0)), 0) AS power
		FROM account a
		LEFT JOIN (
			SELECT credential_tag, staking_key,
			       COALESCE(SUM(CAST(amount AS INTEGER)), 0) AS utxo_sum
			FROM utxo
			WHERE deleted_slot = 0
			GROUP BY credential_tag, staking_key
		) u ON u.credential_tag = a.credential_tag AND u.staking_key = a.staking_key
		WHERE a.active = 1 AND a.drep IS NOT NULL AND a.drep_type IN (0, 1)
		GROUP BY a.drep, a.drep_type`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]string)
	for rows.Next() {
		var (
			tag   uint8
			cred  []byte
			power uint64
		)
		if err := rows.Scan(&tag, &cred, &power); err != nil {
			return nil, err
		}
		out[drepPowerKey(tag, hex.EncodeToString(cred))] = strconv.FormatUint(power, 10)
	}
	return out, rows.Err()
}

func drepPowerKey(tag uint8, hexCred string) string {
	return strconv.Itoa(int(tag)) + ":" + hexCred
}

// drepBech32 encodes a DRep credential (Dingo's credential_tag plus the 28-byte
// hash) as a CIP-129 bech32 drep1… identifier. The header byte is produced by
// gouroboros' Drep.String — the same encoder the delegation builder's
// lcommon.Drep values use — rather than a local constant, so the directory
// cannot disagree with the identifiers the wallet builds and the node parses.
// CIP-129 fixes the high nibble at 0x2 for a DRep and puts the credential type
// in the low nibble (0x2 key hash, 0x3 script hash), i.e. 0x22 and 0x23; Dingo
// rejects any other high nibble outright ("invalid DRep voter type").
func drepBech32(tag uint8, hash []byte) (string, error) {
	drep := lcommon.Drep{Credential: hash}
	switch tag {
	case dingoAccountCredentialKeyHash:
		drep.Type = lcommon.DrepTypeAddrKeyHash
	case dingoAccountCredentialScript:
		drep.Type = lcommon.DrepTypeScriptHash
	default:
		return "", fmt.Errorf("drep credential: unknown tag %d", tag)
	}
	return drep.String(), nil
}

// Genesis fetches the network's genesis parameters from the embedded node.
func (c *Client) Genesis(ctx context.Context) (Genesis, error) {
	var out Genesis
	err := c.get(ctx, "/api/v0/genesis", &out)
	return out, err
}

// LatestEpoch fetches the current epoch info from the embedded node.
func (c *Client) LatestEpoch(ctx context.Context) (EpochInfo, error) {
	var out EpochInfo
	err := c.get(ctx, "/api/v0/epochs/latest", &out)
	return out, err
}

// AssetAddresses returns every address currently holding some quantity of
// asset — a Blockfrost-style unit (policy ID concatenated with the hex asset
// name). An asset the node has not seen yields ErrNotFound.
func (c *Client) AssetAddresses(ctx context.Context, asset string) ([]AssetAddress, error) {
	return getAllPages[AssetAddress](ctx, c, "/api/v0/assets/"+asset+"/addresses")
}

// Asset fetches on-chain identity/metadata for a native asset — unit is the
// policy ID concatenated with the hex-encoded asset name, the same "unit"
// used in UTxO amounts — from the node's loopback Blockfrost-compatible API.
// An asset the node has not indexed (never minted, as far as this node has
// seen) yields ErrNotFound.
func (c *Client) Asset(ctx context.Context, unit string) (AssetInfo, error) {
	var out AssetInfo
	if err := c.get(ctx, "/api/v0/assets/"+url.PathEscape(unit), &out); err != nil {
		return out, err
	}
	if len(out.OnchainMetadata) != 0 && string(out.OnchainMetadata) != "null" {
		return out, nil
	}
	metadata, err := c.assetCIP25Metadata(ctx, out.PolicyID, out.AssetName)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return AssetInfo{}, err
		}
		// Metadata enrichment is optional. A core/partially-backfilled Dingo
		// database may not have the API-mode metadata index yet; that must not
		// turn an otherwise successful asset identity lookup into a failure.
		return out, nil
	}
	if len(metadata) != 0 {
		out.OnchainMetadata = metadata
	}
	return out, nil
}

// assetCIP25Metadata reads the latest label-721 entry for an asset from
// Dingo's local metadata index. Dingo indexes transaction metadata but does not
// currently join it into its Blockfrost-compatible asset response.
func (c *Client) assetCIP25Metadata(
	ctx context.Context,
	policyID string,
	assetNameHex string,
) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.dingoDataDir == "" {
		return nil, nil
	}
	metadataPath := filepath.Join(c.dingoDataDir, "metadata.sqlite")
	if _, err := os.Stat(metadataPath); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("asset CIP-25 metadata: %w", err)
	}

	db, err := sql.Open("sqlite", sqliteReadOnlyDSN(metadataPath))
	if err != nil {
		return nil, fmt.Errorf("open asset CIP-25 metadata: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	var hasMetadataLabels int
	err = db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM sqlite_master
			WHERE type = 'table' AND name = 'transaction_metadata_label'
		)`,
	).Scan(&hasMetadataLabels)
	if err != nil {
		return nil, fmt.Errorf("inspect asset CIP-25 metadata index: %w", err)
	}
	if hasMetadataLabels == 0 {
		return nil, nil
	}

	policyIDBytes, err := hex.DecodeString(policyID)
	if err != nil {
		return nil, fmt.Errorf("decode asset metadata policy ID %q: %w", policyID, err)
	}
	assetName, err := hex.DecodeString(assetNameHex)
	if err != nil {
		return nil, fmt.Errorf("decode asset metadata name %q: %w", assetNameHex, err)
	}

	// CIP-25 metadata belongs to the mint transaction. Resolve only label-721
	// rows from transactions that produced an output containing this asset,
	// using Dingo's indexed asset -> UTxO -> transaction relationship. Bursa
	// runs Dingo in API mode, which retains spent output rows; block-history
	// expiry only removes block CBOR and therefore does not break this join.
	rows, err := db.QueryContext(ctx, `
		SELECT metadata.json_value
		FROM transaction_metadata_label AS metadata
		WHERE metadata.label = ?
		  AND metadata.transaction_id IN (
			SELECT DISTINCT utxo.transaction_id
			FROM asset
			INNER JOIN utxo ON utxo.id = asset.utxo_id
			WHERE asset.policy_id = ? AND asset.name = ?
		  )
		ORDER BY metadata.slot DESC, metadata.id DESC`,
		cip25MetadataLabel,
		policyIDBytes,
		assetName,
	)
	if err != nil {
		return nil, fmt.Errorf("query asset CIP-25 metadata: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var labelJSONString string
		if err := rows.Scan(&labelJSONString); err != nil {
			return nil, fmt.Errorf("scan asset CIP-25 metadata: %w", err)
		}
		labelJSON := json.RawMessage(labelJSONString)
		if metadata := extractCIP25AssetMetadata(labelJSON, policyID, assetNameHex); len(metadata) != 0 {
			return metadata, nil
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate asset CIP-25 metadata: %w", err)
	}
	return nil, nil
}

func extractCIP25AssetMetadata(
	labelJSON json.RawMessage,
	policyID string,
	assetNameHex string,
) json.RawMessage {
	var label map[string]json.RawMessage
	if err := json.Unmarshal(labelJSON, &label); err != nil {
		return nil
	}
	var assets map[string]json.RawMessage
	if err := json.Unmarshal(label[policyID], &assets); err != nil {
		return nil
	}

	// CIP-25 v2 uses the asset-name bytes (rendered as hex by Dingo's metadata
	// codec); v1 commonly uses the UTF-8 asset name. Accept both spellings.
	candidates := []string{assetNameHex}
	if assetName, err := hex.DecodeString(assetNameHex); err == nil {
		candidates = append(candidates, string(assetName))
	}
	for _, candidate := range candidates {
		metadata := assets[candidate]
		if len(metadata) == 0 || string(metadata) == "null" {
			continue
		}
		var object map[string]json.RawMessage
		if json.Unmarshal(metadata, &object) == nil {
			return append(json.RawMessage(nil), metadata...)
		}
	}
	return nil
}
