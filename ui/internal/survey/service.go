// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package survey

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/blinklabs-io/bursa/ui/internal/cardanonet"
	"github.com/blinklabs-io/bursa/ui/internal/chain"
	"github.com/blinklabs-io/bursa/ui/internal/spend"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// ErrNotFound is returned for a survey that does not exist or is not valid.
var ErrNotFound = errors.New("survey: not found")

// maxLabelPages bounds the label-17 scan (100 transactions per page). A longer
// history fails the scan rather than yielding silently partial tallies.
const maxLabelPages = 50

// maxCachedTxs bounds the per-transaction fact cache.
const maxCachedTxs = 20000

// Chain is the node surface the service reads. *chain.Client satisfies it.
type Chain interface {
	MetadataByLabel(ctx context.Context, label uint64, maxPages int) ([]chain.LabelMetadata, error)
	Transaction(ctx context.Context, hash string) (chain.TxInfo, error)
	RequiredSigners(ctx context.Context, hash string) ([]string, error)
	LatestEpoch(ctx context.Context) (chain.EpochInfo, error)
	Genesis(ctx context.Context) (chain.Genesis, error)
	DRep(ctx context.Context, drepID string) (chain.DRepInfo, error)
	Pool(ctx context.Context, poolID string) (chain.PoolInfo, error)
	Account(ctx context.Context, stakeAddr string) (chain.AccountInfo, error)
	GovernanceAnchorDocuments(ctx context.Context) ([]chain.AnchorDocument, error)
}

// Service discovers CIP-179 surveys on chain through the embedded node and
// tallies their responses.
type Service struct {
	chain   Chain
	network string
	builder MetadataBuilder

	// fetchBeacon retrieves a quicknet beacon signature from a drand relay. It
	// runs only when the user asks to reveal a sealed survey and consents.
	fetchBeacon func(ctx context.Context, round uint64) ([]byte, error)

	mu      sync.Mutex
	facts   map[string]txFacts
	beacons map[uint64][]byte // verified quicknet signatures by round
}

// NewService builds a service over the node for the named Cardano network.
func NewService(c Chain, network string) *Service {
	return &Service{
		chain: c, network: network,
		facts: make(map[string]txFacts), beacons: make(map[uint64][]byte),
		fetchBeacon: defaultBeaconFetcher(),
	}
}

// Summary is a survey as listed.
type Summary struct {
	ID            string   `json:"id"` // "<tx hash>:<index>"
	TxHash        string   `json:"tx_hash"`
	Index         uint64   `json:"index"`
	Title         string   `json:"title"`
	Description   string   `json:"description"`
	Owner         string   `json:"owner"` // credential hash, hex
	OwnerScript   bool     `json:"owner_script"`
	Roles         []Role   `json:"roles"`
	EndEpoch      uint64   `json:"end_epoch"`
	Status        string   `json:"status"` // open | closed | cancelled
	Sealed        bool     `json:"sealed"`
	Questions     int      `json:"questions"`
	LinkedActions []string `json:"linked_actions"`
	Owned         bool     `json:"owned"` // owned by the active wallet's payment key
}

// Detail is one survey with its questions and, unless cancelled, its tally.
type Detail struct {
	Summary
	Definition Definition `json:"definition"`
	Tally      *Tally     `json:"tally,omitempty"`
}

type txFacts struct {
	height    uint64
	index     int
	blockTime int64
	signers   map[string]bool
}

type clk struct {
	epoch     uint64
	start     int64
	epochSecs int64
}

// epochOf maps a block time to its epoch, counting back from the node's
// current epoch. Epoch length is constant from Shelley on, which is the only
// era CIP-179 transactions exist in.
func (c clk) epochOf(blockTime int64) uint64 {
	if blockTime >= c.start || c.epochSecs <= 0 {
		return c.epoch
	}
	back := uint64((c.start - blockTime + c.epochSecs - 1) / c.epochSecs) //nolint:gosec // positive by the guard
	if back > c.epoch {
		return 0
	}
	return c.epoch - back
}

func (s *Service) clock(ctx context.Context) (clk, error) {
	latest, err := s.chain.LatestEpoch(ctx)
	if err != nil {
		return clk{}, fmt.Errorf("latest epoch: %w", err)
	}
	gen, err := s.chain.Genesis(ctx)
	if err != nil {
		return clk{}, fmt.Errorf("genesis: %w", err)
	}
	return clk{epoch: latest.Epoch, start: latest.StartTime, epochSecs: int64(gen.EpochLength) * int64(gen.SlotLength)}, nil
}

func (s *Service) txFacts(ctx context.Context, hash string) (txFacts, error) {
	s.mu.Lock()
	f, ok := s.facts[hash]
	s.mu.Unlock()
	if ok {
		return f, nil
	}
	tx, err := s.chain.Transaction(ctx, hash)
	if err != nil {
		return txFacts{}, fmt.Errorf("transaction %s: %w", hash, err)
	}
	signers, err := s.chain.RequiredSigners(ctx, hash)
	if err != nil {
		return txFacts{}, fmt.Errorf("required signers %s: %w", hash, err)
	}
	f = txFacts{height: tx.BlockHeight, index: tx.Index, blockTime: tx.BlockTime, signers: make(map[string]bool, len(signers))}
	for _, h := range signers {
		f.signers[strings.ToLower(h)] = true
	}
	s.mu.Lock()
	if len(s.facts) >= maxCachedTxs {
		clear(s.facts)
	}
	s.facts[hash] = f
	s.mu.Unlock()
	return f, nil
}

// proves reports whether the transaction proves control of a key credential
// through required_signers (CIP-179 mechanism A). Script credentials cannot be
// proven that way here.
func (f txFacts) proves(c Credential) bool {
	return !c.Script && f.signers[hex.EncodeToString(c.Hash[:])]
}

// entry is a decoded label-17 transaction.
type entry struct {
	hash    string
	payload Payload
}

// known is one verified survey definition.
type known struct {
	ref       Ref
	tx        string
	height    uint64
	txIndex   int
	def       Definition
	cancelled bool
}

func (k known) id() string { return idOf(k.tx, k.ref.Index) }

func idOf(tx string, index uint64) string { return tx + ":" + strconv.FormatUint(index, 10) }

func parseID(id string) (Ref, bool) {
	tx, idx, ok := strings.Cut(id, ":")
	raw, err := hex.DecodeString(tx)
	i, ierr := strconv.ParseUint(idx, 10, 64)
	if !ok || err != nil || len(raw) != 32 || ierr != nil {
		return Ref{}, false
	}
	r := Ref{Index: i}
	copy(r.TxID[:], raw)
	return r, true
}

// scan reads label 17 and returns the decoded transactions, skipping anything
// that does not decode as a CIP-179 payload.
func (s *Service) scan(ctx context.Context) ([]entry, error) {
	rows, err := s.chain.MetadataByLabel(ctx, Label, maxLabelPages)
	if err != nil {
		return nil, fmt.Errorf("label %d metadata: %w", Label, err)
	}
	out := make([]entry, 0, len(rows))
	for _, r := range rows {
		p, err := Decode(r.CBOR)
		if err != nil {
			continue
		}
		out = append(out, entry{hash: r.TxHash, payload: p})
	}
	return out, nil
}

// definitions returns every verified definition, oldest first, with
// cancellations applied. A definition is verified when its key owner signed the
// transaction and it ends after the epoch it was published in. A script owner
// is never verified: proving one means resolving the native script and checking
// the transaction satisfies it, which this service does not do.
func (s *Service) definitions(ctx context.Context, entries []entry, cl clk) ([]*known, error) {
	var defs []*known
	byRef := map[Ref]*known{}
	for _, e := range entries {
		if e.payload.Kind != KindDefinitions {
			continue
		}
		f, err := s.txFacts(ctx, e.hash)
		if err != nil {
			return nil, err
		}
		raw, err := hex.DecodeString(e.hash)
		if err != nil || len(raw) != 32 {
			continue
		}
		for i, d := range e.payload.Definitions {
			if !f.proves(d.Owner) {
				continue
			}
			if d.EndEpoch <= cl.epochOf(f.blockTime) {
				continue
			}
			k := &known{ref: Ref{Index: uint64(i)}, tx: e.hash, height: f.height, txIndex: f.index, def: d}
			copy(k.ref.TxID[:], raw)
			defs = append(defs, k)
			byRef[k.ref] = k
		}
	}
	for _, e := range entries {
		if e.payload.Kind != KindCancellations {
			continue
		}
		f, err := s.txFacts(ctx, e.hash)
		if err != nil {
			return nil, err
		}
		for _, r := range e.payload.Cancellations {
			k, ok := byRef[r]
			if ok && f.proves(k.def.Owner) && cl.epochOf(f.blockTime) <= k.def.EndEpoch {
				k.cancelled = true
			}
		}
	}
	return defs, nil
}

// walletOwner is the active wallet's payment credential, the owner of surveys it
// creates. It is absent without a wallet.
func (s *Service) walletOwner() (owner [28]byte, ok bool) {
	if s.builder == nil {
		return owner, false
	}
	owner, err := s.builder.WalletCredential(spend.SignerPayment)
	return owner, err == nil
}

func (s *Service) summarize(k *known, cl clk, links map[Ref][]string) Summary {
	owner, haveOwner := s.walletOwner()
	status := "open"
	switch {
	case k.cancelled:
		status = "cancelled"
	case cl.epoch > k.def.EndEpoch:
		status = "closed"
	}
	return Summary{
		ID: k.id(), TxHash: k.tx, Index: k.ref.Index,
		Title: k.def.Title, Description: k.def.Description,
		Owner: hex.EncodeToString(k.def.Owner.Hash[:]), OwnerScript: k.def.Owner.Script,
		Roles: k.def.Roles, EndEpoch: k.def.EndEpoch, Status: status,
		Sealed: k.def.Mode.Sealed, Questions: len(k.def.Questions),
		LinkedActions: links[k.ref],
		Owned:         haveOwner && !k.def.Owner.Script && k.def.Owner.Hash == owner,
	}
}

// links maps each survey to the governance actions whose anchor links to it.
// Per CIP-179 the link only holds when the survey exists and ends in the
// action's expiry epoch; anything else is ignored.
func (s *Service) links(ctx context.Context, defs []*known) (map[Ref][]string, error) {
	docs, err := s.chain.GovernanceAnchorDocuments(ctx)
	if err != nil {
		return nil, fmt.Errorf("governance anchor documents: %w", err)
	}
	end := make(map[Ref]uint64, len(defs))
	for _, k := range defs {
		end[k.ref] = k.def.EndEpoch
	}
	out := map[Ref][]string{}
	for _, d := range docs {
		r, ok := ParseLink(d.Content)
		if !ok {
			continue
		}
		if e, exists := end[r]; exists && e == d.ExpiresEpoch && !slices.Contains(out[r], d.ActionID) {
			out[r] = append(out[r], d.ActionID)
		}
	}
	return out, nil
}

// snapshot is the label-17 history read once: decoded transactions, the
// verified definitions among them, and the epoch clock.
type snapshot struct {
	entries []entry
	defs    []*known
	cl      clk
}

func (s *Service) snapshot(ctx context.Context) (snapshot, error) {
	entries, err := s.scan(ctx)
	if err != nil {
		return snapshot{}, err
	}
	cl, err := s.clock(ctx)
	if err != nil {
		return snapshot{}, err
	}
	defs, err := s.definitions(ctx, entries, cl)
	if err != nil {
		return snapshot{}, err
	}
	return snapshot{entries: entries, defs: defs, cl: cl}, nil
}

func (sn snapshot) find(id string) (*known, bool) {
	ref, ok := parseID(id)
	if !ok {
		return nil, false
	}
	for _, d := range sn.defs {
		if d.ref == ref {
			return d, true
		}
	}
	return nil, false
}

// List returns every valid survey, newest first.
func (s *Service) List(ctx context.Context) ([]Summary, error) {
	sn, err := s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	links, err := s.links(ctx, sn.defs)
	if err != nil {
		return nil, err
	}
	out := make([]Summary, 0, len(sn.defs))
	for _, k := range slices.Backward(sn.defs) {
		out = append(out, s.summarize(k, sn.cl, links))
	}
	return out, nil
}

// Get returns one survey and, unless it was cancelled, its tally.
func (s *Service) Get(ctx context.Context, id string) (Detail, error) {
	sn, err := s.snapshot(ctx)
	if err != nil {
		return Detail{}, err
	}
	k, ok := sn.find(id)
	if !ok {
		return Detail{}, ErrNotFound
	}
	return s.detail(ctx, sn, k)
}

func (s *Service) detail(ctx context.Context, sn snapshot, k *known) (Detail, error) {
	links, err := s.links(ctx, sn.defs)
	if err != nil {
		return Detail{}, err
	}
	d := Detail{Summary: s.summarize(k, sn.cl, links), Definition: k.def}
	if k.cancelled {
		return d, nil
	}
	observed, err := s.observe(ctx, sn.entries, k, sn.cl)
	if err != nil {
		return Detail{}, err
	}
	tally := k.def.Aggregate(observed)
	d.Tally = &tally
	return d, nil
}

// observe collects every response to the survey with its chain placement and
// the outcome of the credential-proof and role checks.
func (s *Service) observe(ctx context.Context, entries []entry, k *known, cl clk) ([]Observed, error) {
	// Beacons are cached by quicknet round only; another chain's survey with the
	// same round number must not be opened with a quicknet beacon.
	var beaconSig []byte
	if k.def.Mode.checkQuicknet() == nil {
		beaconSig = s.cachedBeacon(k.def.Mode.Round)
	}
	verified := map[identity]string{}
	var out []Observed
	for _, e := range entries {
		if e.payload.Kind != KindResponses {
			continue
		}
		var f txFacts
		var haveFacts bool
		for i, r := range e.payload.Responses {
			if r.Survey != k.ref {
				continue
			}
			if !haveFacts {
				var err error
				if f, err = s.txFacts(ctx, e.hash); err != nil {
					return nil, err
				}
				haveFacts = true
			}
			o := Observed{
				TxHash: e.hash, Pos: Position{Height: f.height, TxIndex: f.index, Index: i},
				Epoch: cl.epochOf(f.blockTime), Response: r,
			}
			if !f.proves(r.Credential) {
				o.Reject = "credential not proven by the transaction's required signers"
			} else {
				id := identity{r.Role, r.Credential}
				reject, ok := verified[id]
				if !ok {
					var err error
					if reject, err = s.verifyRole(ctx, r.Role, r.Credential); err != nil {
						return nil, err
					}
					verified[id] = reject
				}
				o.Reject = reject
			}
			if o.Reject == "" && beaconSig != nil && len(r.Sealed) > 0 {
				answers, uerr := UnsealAnswers(r.Sealed, k.def.Mode, beaconSig)
				if uerr != nil {
					o.Reject = "cannot be unsealed: " + uerr.Error()
				}
				o.Unsealed = answers
			}
			out = append(out, o)
		}
	}
	return out, nil
}

// verifyRole checks a claimed role against the node's ledger state. It returns
// a non-empty reason when the credential does not hold the role, and an error
// only when the node could not answer. It reflects the node's current state;
// the end-epoch snapshot CIP-179 describes is not reconstructed.
func (s *Service) verifyRole(ctx context.Context, role Role, c Credential) (string, error) {
	var err error
	switch role {
	case RoleKeyholder:
		return "", nil
	case RoleDRep:
		var info chain.DRepInfo
		if info, err = s.chain.DRep(ctx, hex.EncodeToString(c.Hash[:])); err == nil && info.Retired {
			return "DRep is retired", nil
		}
	case RoleSPO:
		_, err = s.chain.Pool(ctx, lcommon.PoolId(c.Hash).String())
	case RoleStakeholder:
		var acct chain.AccountInfo
		var stake lcommon.Address
		netID, nerr := cardanonet.AddressNetworkID(s.network)
		if nerr != nil {
			return "", nerr
		}
		if stake, err = lcommon.NewAddressFromParts(lcommon.AddressTypeNoneKey, netID, nil, c.Hash[:]); err != nil {
			return "", err
		}
		if acct, err = s.chain.Account(ctx, stake.String()); err == nil && (!acct.Registered || acct.ControlledAmount == "" || acct.ControlledAmount == "0") {
			return "stake credential has no stake", nil
		}
	case RoleCC:
		// The node exposes no committee membership to check a hot credential.
		fallthrough
	default:
		return "role cannot be verified against ledger state", nil
	}
	if errors.Is(err, chain.ErrNotFound) {
		return "credential does not hold the claimed role", nil
	}
	return "", err
}
