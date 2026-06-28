# Staking & Governance (delegation) — design

**Status:** draft for review · **Date:** 2026-06-27 · **Worktree:** `feat/staking-ui`
**UI mockup:** https://claude.ai/code/artifact/eda430f4-5803-4880-9c2c-89c57ffb20a8

## Goal

Let a Bursa full-node wallet user register their stake key, delegate to a stake
pool, direct their governance voting power, and withdraw rewards — from one
screen, in a single transaction where Conway allows it, **without any external
network call** (the embedded node is the only thing that touches the network).

This is sub-project A of the wallet program ([[wallet-program-goal]]). It also
establishes the shared backend capability — attaching certificates and
withdrawals to a transaction — that governance actions (Track C) and stake-pool
operations (Track B) will reuse.

## Scope

**In:**
- Stake-key **registration** (one-time, `key_deposit` ≈ 2 ₳, refundable).
- **Delegate stake** to a pool, chosen by pasting a `pool1…` ID the node verifies.
- **Vote delegation**, four targets:
  1. Always Abstain (predefined DRep)
  2. Always No Confidence (predefined DRep)
  3. A specific DRep (`drep1…`, node-verified)
  4. **Register self as a DRep** (`drep_deposit` ≈ 500 ₳, refundable; optional
     metadata anchor) and delegate own vote to self
- **Withdraw** staking rewards.
- **Smart bundling**: a never-staked wallet's first action bundles registration +
  stake delegation (+ vote delegation, + self-DRep registration) into ONE tx; the
  confirm step itemizes every certificate and deposit.

**Out (later tracks):**
- Voting on individual governance actions; committee hot/cold ops (Track C).
- Pool operation (running a pool: cold/VRF/KES, opcerts) (Track B).
- Browsable pool/DRep directories (would require a standing external source —
  rejected under the consent law).

**Orthogonal:** encrypted wallet persistence / password-only unlock is a separate
wallet-core concern (the Setup/Unlock flow); this feature assumes an unlocked,
spending-enabled wallet.

## Consent / boundary law

No feature here makes an external call. Pool and DRep selection are **paste-ID +
node-verified**: the embedded node confirms existence and returns on-chain params.
Deposits come from the node's protocol parameters. If any future enrichment (e.g.
off-chain pool ticker/name) is added, it must go through the per-use consent gate
— not in this spec.

## UX

The approved mockup defines the screen (Staking & Governance):
1. **Status panel** — stake key registered?, current pool (+ node params), current
   voting power, withdrawable rewards.
2. **Set-up / change form** — paste pool ID → node-verified readout (margin,
   pledge, fixed cost, live stake); 4-way voting-power picker; "Review delegation".
3. **Itemized confirm** — every cert + each deposit (distinguishing the 2 ₳ stake
   deposit from the ~500 ₳ DRep deposit), network fee, total; spending password.
4. **Active state** — status at a glance + "Withdraw rewards" + "Change delegation".

Nav: a new "Staking" entry, gated like Send (needs a synced node + spending-enabled
wallet).

## Architecture

Reuse the proven two-phase `Build → Preview → Confirm(sign+submit)` core that the
Send flow already uses (pending-tx cache keyed by `pending_id`, keystore-password
signing, `SubmitContext`).

### API (new, loopback only)
- `GET  /wallet/pool/{pool_id}` → `PoolInfo` (margin, pledge, fixed cost, live
  stake, …) or 404. Node-backed.
- `GET  /wallet/drep/{drep_id}` → `{ exists, anchor? }` or 404. Node-backed.
- `POST /wallet/delegation` → builds the tx, returns `DelegationPreview`.
- `POST /wallet/delegation/{pending_id}/confirm` (password) → signs + submits → `{ tx_hash }`.

Withdrawal needs no separate endpoint: the "Withdraw rewards" button submits a
`DelegationRequest` with only `withdraw: true` (pool/vote omitted), which produces
a withdrawal-only transaction through the same two endpoints.

### Request / response types
```
DelegationRequest {
  pool_id?:  string                       // omitted = leave stake delegation unchanged
  vote?: {
    type: "abstain" | "no_confidence" | "drep" | "register_self"
    drep_id?: string                      // when type == "drep"
    anchor?:  { url: string, hash: string } // optional, when type == "register_self"
  }
  withdraw?: boolean                       // sweep withdrawable rewards
}
DelegationPreview {
  pending_id: string
  certs:    Cert[]    // { kind, summary, deposit_lovelace? }  — drives the itemized confirm
  fee:      string
  deposit:  string    // total refundable deposit
  withdrawal?: string
  total:    string
}
```

### Backend
`spend.Service` gains `BuildDelegation(ctx, DelegationRequest) (Preview, error)`:
1. Query node for current account state (stake key registered? current pool?
   current vote delegation?) and **protocol params** (`key_deposit`, `drep_deposit`).
2. Compute the **minimal certificate set** from desired-vs-current state (see below).
3. Build via apollo: prefer the combined `RegisterAndDelegateStakeAndVote` when a
   fresh wallet sets pool+vote at once; otherwise the discrete
   `RegisterStake` / `DelegateStake` / `DelegateVote` / `RegisterDRep` /
   `AddWithdrawal`. Map the 4 vote targets to apollo's `Drep` argument.
4. Return an itemized `DelegationPreview`.

`Confirm` reuses the existing sign+submit path unchanged.

**Cert-set computation (pure, unit-testable):** `func plan(current AccountState,
req DelegationRequest, params ProtocolParams) ([]Cert, error)`:
- stake key not registered and (pool or vote requested) → prepend stake registration (+deposit).
- `pool_id` set and differs from current → stake-delegation cert.
- `vote` set → vote-delegation cert; `register_self` additionally → DRep-registration cert (+deposit) and delegates vote to the wallet's own DRep credential.
- `withdraw` → withdrawal of the full withdrawable amount.
Idempotent: requesting the current state yields no certs (UI disables submit).

### Chain client additions (`ui/internal/chain`)
New node-backed methods: `Pool(ctx, poolID)`, `DRep(ctx, drepID)`,
`ProtocolParams(ctx)`. Backed by the embedded node's Blockfrost API
(`/pools/{id}`, governance/DRep endpoint, `/epochs/latest/parameters`).
**Assumption to verify in implementation:** dingo's Blockfrost implements these;
if a DRep-lookup endpoint is absent, fall back to client-side bech32 validation +
surface a clear "couldn't verify; submit may fail" note (still no external call).

### Keys
Vote delegation to self + DRep registration need the wallet's **DRep credential**
(CIP-0105, derivation role 3). Confirm bursa derives a DRep key (the keystore knows
`KeyTypeDRep`); add derivation if missing.

## Assumptions to validate during implementation
1. apollo `Drep` type exposes the predefined **Always Abstain / Always No
   Confidence** variants (apollo v2 has full Conway governance; confirm the exact
   constructor, else build the predefined DRep per CIP-1694).
2. dingo Blockfrost endpoints for pool params, protocol params, and DRep existence.
3. DRep key derivation (role 3) available via the keystore.

## Error handling
- Invalid/unknown pool or DRep ID → inline "not found by your node" on the field;
  no submit.
- Insufficient funds for deposits+fee → explicit message naming the shortfall.
- Already in the requested state → submit disabled with an explanatory note.
- Submit failure → surface the node's reason; the pending tx is discarded.

## Testing
- **Unit:** `plan()` cert-set computation across the state matrix (fresh wallet,
  already-registered, pool change, each vote target, register-self, withdraw,
  no-op). Deposit math from protocol params.
- **API:** handler tests for `/wallet/pool`, `/wallet/drep`, `/wallet/delegation`
  (+confirm) with a fake chain/spend, mirroring existing api tests.
- **Frontend:** Staking screen tests mirroring the Send/Sign screens — pool paste →
  verified readout, voting-power picker, itemized confirm, withdraw, gating.

## Build sequence
1. Chain client node-query methods (+ fake for tests).
2. `plan()` + `BuildDelegation` in `spend.Service` (the shared cert/withdrawal
   capability) + endpoints.
3. Frontend: types → client → hooks → Staking screen → nav/route wiring.
4. Tests at each layer.
