// Package chain is a typed client for the embedded Dingo node's loopback
// Blockfrost REST API. It is the wallet's only data source and never contacts
// any external service — only http://127.0.0.1:<port>.
package chain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ErrNotFound is returned when the node reports the queried resource does not
// exist (HTTP 404) — e.g. an account/stake credential not yet seen on chain.
// Callers treat it as "empty" rather than a hard failure.
var ErrNotFound = errors.New("chain: resource not found")

var errPageLimitExceeded = errors.New("chain: pagination limit exceeded")

// Client talks to a Blockfrost-compatible API at BaseURL (the local node).
type Client struct {
	BaseURL string
	http    *http.Client
}

// NewClient builds a client for the node's loopback Blockfrost port.
func NewClient(port uint) *Client {
	return NewClientURL(fmt.Sprintf("http://127.0.0.1:%d", port))
}

// NewClientURL builds a client for an explicit base URL (used in tests).
func NewClientURL(baseURL string) *Client {
	return &Client{BaseURL: baseURL, http: &http.Client{Timeout: 10 * time.Second}}
}

// AccountInfo mirrors GET /api/v0/accounts/{stake_address}.
type AccountInfo struct {
	StakeAddress       string  `json:"stake_address"`
	Active             bool    `json:"active"`
	ActiveEpoch        *int64  `json:"active_epoch"`
	ControlledAmount   string  `json:"controlled_amount"`
	RewardsSum         string  `json:"rewards_sum"`
	WithdrawableAmount string  `json:"withdrawable_amount"`
	PoolID             *string `json:"pool_id"`
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
