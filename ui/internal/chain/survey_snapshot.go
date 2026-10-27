package chain

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"

	"github.com/blinklabs-io/dingo/database/models"
)

// SurveyRole identifies a CIP-179 responder role.
type SurveyRole uint8

const (
	SurveyRoleDRep SurveyRole = iota
	SurveyRoleSPO
	SurveyRoleCC
	SurveyRoleStakeholder
	SurveyRoleKeyholder
)

// SurveyRoleClaim is one credential and role to evaluate at a survey's
// end-epoch ledger snapshot.
type SurveyRoleClaim struct {
	Role          SurveyRole
	CredentialTag uint8
	Credential    [28]byte
}

type surveySnapshot struct {
	epoch           uint64
	ledgerEpoch     uint64
	capturedSlot    uint64
	boundarySlot    uint64
	totalDelegators uint64
}

type certificatePosition struct {
	slot       uint64
	blockIndex uint64
	certIndex  uint64
}

// SurveyRoleSnapshot evaluates role claims against the authoritative ledger
// state captured when endEpoch closed.
func (c *Client) SurveyRoleSnapshot(
	ctx context.Context,
	endEpoch uint64,
	claims []SurveyRoleClaim,
) (map[SurveyRoleClaim]bool, error) {
	result := make(map[SurveyRoleClaim]bool, len(claims))
	needsSnapshot := false
	for _, claim := range claims {
		switch claim.Role {
		case SurveyRoleKeyholder:
			result[claim] = true
		case SurveyRoleDRep, SurveyRoleSPO, SurveyRoleStakeholder:
			needsSnapshot = true
		case SurveyRoleCC:
			result[claim] = false
		default:
			result[claim] = false
		}
	}
	if !needsSnapshot {
		return result, nil
	}
	if c.dingoDataDir == "" {
		return nil, errors.New("survey role snapshot: Dingo metadata is not configured")
	}
	if endEpoch == math.MaxUint64 {
		return nil, errors.New("survey role snapshot: end epoch overflows snapshot epoch")
	}
	metadataPath := filepath.Join(c.dingoDataDir, "metadata.sqlite")
	if _, err := os.Stat(metadataPath); err != nil {
		return nil, fmt.Errorf("survey role snapshot metadata: %w", err)
	}
	db, err := sql.Open("sqlite", sqliteReadOnlyDSN(metadataPath))
	if err != nil {
		return nil, fmt.Errorf("open survey role snapshot metadata: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin survey role snapshot read: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	snapshot, err := readSurveySnapshot(ctx, tx, endEpoch+1)
	if err != nil {
		return nil, err
	}
	if err := verifySurveyStakeSnapshot(ctx, tx, snapshot); err != nil {
		return nil, err
	}
	if snapshot.ledgerEpoch != endEpoch {
		return nil, fmt.Errorf(
			"survey role snapshot epoch mismatch: captured epoch %d, survey end epoch %d",
			snapshot.ledgerEpoch,
			endEpoch,
		)
	}
	var activePools map[[28]byte]struct{}
	for _, claim := range claims {
		if claim.Role == SurveyRoleSPO && claim.CredentialTag == 0 {
			activePools, err = surveySPOsAtSlot(
				ctx,
				tx,
				snapshot.ledgerEpoch,
				snapshot.capturedSlot,
			)
			if err != nil {
				return nil, err
			}
			break
		}
	}

	for _, claim := range claims {
		var eligible bool
		switch claim.Role {
		case SurveyRoleKeyholder:
			continue
		case SurveyRoleCC:
			continue
		case SurveyRoleStakeholder:
			eligible, err = surveyStakeholderAtSnapshot(ctx, tx, snapshot, claim)
		case SurveyRoleDRep:
			eligible, err = surveyDRepAtSlot(ctx, tx, snapshot.capturedSlot, claim)
		case SurveyRoleSPO:
			if claim.CredentialTag == 0 {
				_, eligible = activePools[claim.Credential]
			}
		default:
			eligible = false
		}
		if err != nil {
			return nil, err
		}
		result[claim] = eligible
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("finish survey role snapshot read: %w", err)
	}
	return result, nil
}

func readSurveySnapshot(ctx context.Context, tx *sql.Tx, epoch uint64) (surveySnapshot, error) {
	var snapshot surveySnapshot
	snapshot.epoch = epoch
	err := tx.QueryRowContext(ctx, `
SELECT snapshot.captured_slot, snapshot.boundary_slot,
       snapshot.total_delegators
FROM reward_snapshot snapshot
JOIN epoch_summary summary ON summary.epoch = snapshot.epoch
  AND summary.snapshot_ready = TRUE
  AND summary.boundary_slot = snapshot.boundary_slot
WHERE snapshot.epoch = ? AND snapshot.snapshot_type = 'mark'
  AND snapshot.authoritative = TRUE
  AND snapshot.calculation_version = ?`, epoch, models.RewardStakeCalculationVersion).Scan(
		&snapshot.capturedSlot,
		&snapshot.boundarySlot,
		&snapshot.totalDelegators,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return surveySnapshot{}, fmt.Errorf("survey role snapshot: authoritative mark snapshot for epoch %d is unavailable", epoch)
	}
	if err != nil {
		return surveySnapshot{}, fmt.Errorf("read survey role snapshot for epoch %d: %w", epoch, err)
	}
	if snapshot.capturedSlot == math.MaxUint64 ||
		snapshot.boundarySlot != snapshot.capturedSlot+1 {
		return surveySnapshot{}, fmt.Errorf("survey role snapshot for epoch %d has invalid slot boundary", epoch)
	}
	var epochID, startSlot, length int64
	err = tx.QueryRowContext(ctx, `
SELECT epoch_id, start_slot, length_in_slots
FROM epoch
WHERE start_slot <= ?
ORDER BY start_slot DESC
LIMIT 1`, snapshot.capturedSlot).Scan(&epochID, &startSlot, &length)
	if errors.Is(err, sql.ErrNoRows) {
		return surveySnapshot{}, fmt.Errorf("survey role snapshot for epoch %d has no containing epoch", epoch)
	}
	if err != nil {
		return surveySnapshot{}, fmt.Errorf("read survey snapshot epoch: %w", err)
	}
	if epochID < 0 || startSlot < 0 || length <= 0 ||
		startSlot > math.MaxInt64-length ||
		snapshot.capturedSlot >= uint64(startSlot+length) {
		return surveySnapshot{}, fmt.Errorf("survey role snapshot for epoch %d has invalid containing epoch", epoch)
	}
	snapshot.ledgerEpoch = uint64(epochID)
	return snapshot, nil
}

func verifySurveyStakeSnapshot(ctx context.Context, tx *sql.Tx, snapshot surveySnapshot) error {
	var raw string
	err := tx.QueryRowContext(ctx, `
SELECT value FROM sync_state
WHERE sync_key = 'dingo:stake-reward:stake-inputs-pending'`).Scan(&raw)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read pending survey stake snapshots: %w", err)
	}
	if err == nil && raw != "" {
		var pending struct {
			Entries []struct {
				Epoch        uint64 `json:"epoch"`
				BoundarySlot uint64 `json:"boundary_slot"`
			} `json:"entries"`
		}
		if err := json.Unmarshal([]byte(raw), &pending); err != nil {
			return fmt.Errorf("decode pending survey stake snapshots: %w", err)
		}
		for _, entry := range pending.Entries {
			if entry.Epoch == snapshot.epoch && entry.BoundarySlot == snapshot.boundarySlot {
				return fmt.Errorf("survey stake snapshot for epoch %d is still being written", snapshot.epoch)
			}
		}
	}
	var count, mismatched uint64
	err = tx.QueryRowContext(ctx, `
SELECT COUNT(*), COALESCE(SUM(
    CASE WHEN captured_slot <> ? OR boundary_slot <> ? THEN 1 ELSE 0 END
), 0)
FROM reward_stake_input
WHERE epoch = ?`, snapshot.capturedSlot, snapshot.boundarySlot, snapshot.epoch).Scan(
		&count,
		&mismatched,
	)
	if err != nil {
		return fmt.Errorf("verify survey stake snapshot for epoch %d: %w", snapshot.epoch, err)
	}
	if mismatched != 0 || count != snapshot.totalDelegators {
		return fmt.Errorf("survey stake snapshot for epoch %d is incomplete", snapshot.epoch)
	}
	return nil
}

func surveyStakeholderAtSnapshot(
	ctx context.Context,
	tx *sql.Tx,
	snapshot surveySnapshot,
	claim SurveyRoleClaim,
) (bool, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT stake, registered, pool_key_hash
FROM reward_stake_input
WHERE epoch = ? AND credential_tag = ? AND staking_key = ?`,
		snapshot.epoch,
		claim.CredentialTag,
		claim.Credential[:],
	)
	if err != nil {
		return false, fmt.Errorf("read survey stakeholder snapshot: %w", err)
	}
	defer rows.Close()
	var found bool
	var eligible bool
	for rows.Next() {
		if found {
			return false, errors.New("survey stakeholder snapshot contains duplicate credential state")
		}
		found = true
		var stake string
		var registered bool
		var pool []byte
		if err := rows.Scan(&stake, &registered, &pool); err != nil {
			return false, fmt.Errorf("scan survey stakeholder snapshot: %w", err)
		}
		amount, err := strconv.ParseUint(stake, 10, 64)
		if err != nil {
			return false, fmt.Errorf("parse survey stakeholder stake: %w", err)
		}
		eligible = registered && len(pool) == 28 && amount > 0
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("read survey stakeholder snapshot: %w", err)
	}
	return eligible, nil
}

func surveyDRepAtSlot(
	ctx context.Context,
	tx *sql.Tx,
	slot uint64,
	claim SurveyRoleClaim,
) (bool, error) {
	var addedSlot uint64
	var active bool
	err := tx.QueryRowContext(ctx, `
SELECT COALESCE(added_slot, 0), COALESCE(active, FALSE)
FROM drep
WHERE credential_tag = ? AND credential = ?`,
		claim.CredentialTag,
		claim.Credential[:],
	).Scan(&addedSlot, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read survey DRep candidate: %w", err)
	}
	var renewed bool
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1 FROM drep_expiry_history
    WHERE credential_tag = ? AND credential = ? AND added_slot > ?
)`, claim.CredentialTag, claim.Credential[:], slot).Scan(&renewed); err != nil {
		return false, fmt.Errorf("read survey DRep expiry history: %w", err)
	}
	if addedSlot <= slot && !renewed {
		return active, nil
	}
	registration, registered, err := latestSurveyDRepEvent(
		ctx, tx, "registration_drep", claim, slot,
	)
	if err != nil || !registered {
		return false, err
	}
	deregistration, deregistered, err := latestSurveyDRepEvent(
		ctx, tx, "deregistration_drep", claim, slot,
	)
	if err != nil {
		return false, err
	}
	return !deregistered || compareCertificatePosition(registration, deregistration) > 0, nil
}

func latestSurveyDRepEvent(
	ctx context.Context,
	tx *sql.Tx,
	table string,
	claim SurveyRoleClaim,
	slot uint64,
) (certificatePosition, bool, error) {
	var position certificatePosition
	err := tx.QueryRowContext(ctx, `
SELECT event.added_slot, COALESCE(tx.block_index, 0),
       COALESCE(certs.cert_index, 0)
FROM `+table+` event
LEFT JOIN certs ON certs.id = event.certificate_id
LEFT JOIN "transaction" tx ON tx.id = certs.transaction_id
WHERE event.credential_tag = ? AND event.drep_credential = ?
  AND event.added_slot <= ?
ORDER BY event.added_slot DESC, COALESCE(tx.block_index, 0) DESC,
         COALESCE(certs.cert_index, 0) DESC, event.id DESC
LIMIT 1`, claim.CredentialTag, claim.Credential[:], slot).Scan(
		&position.slot,
		&position.blockIndex,
		&position.certIndex,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return certificatePosition{}, false, nil
	}
	if err != nil {
		return certificatePosition{}, false, fmt.Errorf("read survey DRep snapshot: %w", err)
	}
	return position, true, nil
}

func compareCertificatePosition(left, right certificatePosition) int {
	if left.slot != right.slot {
		if left.slot < right.slot {
			return -1
		}
		return 1
	}
	if left.blockIndex != right.blockIndex {
		if left.blockIndex < right.blockIndex {
			return -1
		}
		return 1
	}
	if left.certIndex < right.certIndex {
		return -1
	}
	if left.certIndex > right.certIndex {
		return 1
	}
	return 0
}

func surveySPOsAtSlot(
	ctx context.Context,
	tx *sql.Tx,
	epoch uint64,
	slot uint64,
) (map[[28]byte]struct{}, error) {
	rows, err := tx.QueryContext(ctx, `
WITH latest_reg AS (
    SELECT pr.pool_id,
           COALESCE((SELECT lc.slot FROM leios_transaction_context lc WHERE lc.transaction_id = t.id), pr.added_slot) AS added_slot,
           pr.added_slot AS ownership_slot,
           COALESCE(t.block_index, 0) blk_idx,
           COALESCE(c.cert_index, 0) cert_idx,
           ROW_NUMBER() OVER (
               PARTITION BY pr.pool_id
               ORDER BY COALESCE((SELECT lc.slot FROM leios_transaction_context lc WHERE lc.transaction_id = t.id), pr.added_slot) DESC,
                        pr.added_slot DESC, COALESCE(t.block_index, 0) DESC,
                        COALESCE(c.cert_index, 0) DESC, pr.registration_index DESC
           ) rn
    FROM pool_registration pr
    LEFT JOIN certs c ON c.id = pr.certificate_id
    LEFT JOIN "transaction" t ON t.id = c.transaction_id
    WHERE COALESCE((SELECT lc.slot FROM leios_transaction_context lc JOIN certs lc_cert ON lc_cert.transaction_id = lc.transaction_id WHERE lc_cert.id = pr.certificate_id), pr.added_slot) <= ?
),
latest_ret AS (
    SELECT rt.pool_id,
           COALESCE((SELECT lc.slot FROM leios_transaction_context lc WHERE lc.transaction_id = t.id), rt.added_slot) AS added_slot,
           rt.added_slot AS ownership_slot, rt.epoch,
           CASE WHEN rt.certificate_id = 0 THEN 1 ELSE 0 END synthetic_ret,
           COALESCE(t.block_index, 0) blk_idx,
           COALESCE(c.cert_index, 0) cert_idx,
           ROW_NUMBER() OVER (
               PARTITION BY rt.pool_id
               ORDER BY COALESCE((SELECT lc.slot FROM leios_transaction_context lc WHERE lc.transaction_id = t.id), rt.added_slot) DESC,
                        rt.added_slot DESC,
                        CASE WHEN rt.certificate_id = 0 THEN 1 ELSE 0 END DESC,
                        COALESCE(t.block_index, 0) DESC,
                        COALESCE(c.cert_index, 0) DESC
           ) rn
    FROM pool_retirement rt
    LEFT JOIN certs c ON c.id = rt.certificate_id
    LEFT JOIN "transaction" t ON t.id = c.transaction_id
    WHERE COALESCE((SELECT lc.slot FROM leios_transaction_context lc JOIN certs lc_cert ON lc_cert.transaction_id = lc.transaction_id WHERE lc_cert.id = rt.certificate_id), rt.added_slot) <= ?
)
SELECT p.pool_key_hash
FROM pool p
JOIN latest_reg lr ON lr.pool_id = p.id AND lr.rn = 1
LEFT JOIN latest_ret lrt ON lrt.pool_id = p.id AND lrt.rn = 1
WHERE lrt.pool_id IS NULL
   OR lrt.added_slot < lr.added_slot
   OR (lrt.added_slot = lr.added_slot AND lrt.ownership_slot < lr.ownership_slot)
   OR (lrt.added_slot = lr.added_slot AND lrt.ownership_slot = lr.ownership_slot AND lrt.synthetic_ret = 0 AND lrt.blk_idx < lr.blk_idx)
   OR (lrt.added_slot = lr.added_slot AND lrt.ownership_slot = lr.ownership_slot AND lrt.synthetic_ret = 0 AND lrt.blk_idx = lr.blk_idx AND lrt.cert_idx < lr.cert_idx)
   OR lrt.epoch > ?`, slot, slot, epoch)
	if err != nil {
		return nil, fmt.Errorf("read survey SPO snapshot: %w", err)
	}
	defer rows.Close()
	active := make(map[[28]byte]struct{})
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("scan survey SPO snapshot: %w", err)
		}
		if len(raw) != 28 {
			return nil, fmt.Errorf("survey SPO snapshot contains a %d-byte pool hash", len(raw))
		}
		var hash [28]byte
		copy(hash[:], raw)
		active[hash] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read survey SPO snapshot: %w", err)
	}
	return active, nil
}
