package chain

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestSurveyDRepAtSlotUsesCertificateHistory(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "metadata.sqlite"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	for _, stmt := range []string{
		`CREATE TABLE drep (credential_tag integer, credential blob, added_slot integer, active boolean)`,
		`CREATE TABLE drep_expiry_history (credential_tag integer, credential blob, added_slot integer)`,
		`CREATE TABLE registration_drep (id integer primary key, credential_tag integer, drep_credential blob, added_slot integer, certificate_id integer)`,
		`CREATE TABLE deregistration_drep (id integer primary key, credential_tag integer, drep_credential blob, added_slot integer, certificate_id integer)`,
		`CREATE TABLE certs (id integer primary key, transaction_id integer, cert_index integer)`,
		`CREATE TABLE "transaction" (id integer primary key, block_index integer)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	var cred [28]byte
	cred[0] = 1
	claim := SurveyRoleClaim{Role: SurveyRoleDRep, Credential: cred}
	// Registered at slot 100, deregistered at slot 300; the row reflects the
	// current, deregistered state.
	for _, stmt := range []string{
		`INSERT INTO drep VALUES (0, ?, 100, FALSE)`,
		`INSERT INTO registration_drep (credential_tag, drep_credential, added_slot, certificate_id) VALUES (0, ?, 100, 0)`,
		`INSERT INTO deregistration_drep (credential_tag, drep_credential, added_slot, certificate_id) VALUES (0, ?, 300, 0)`,
	} {
		if _, err := db.Exec(stmt, cred[:]); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, tc := range []struct {
		slot uint64
		want bool
	}{{50, false}, {200, true}, {300, false}} {
		got, err := surveyDRepAtSlot(context.Background(), tx, tc.slot, claim)
		if err != nil {
			t.Fatalf("slot %d: %v", tc.slot, err)
		}
		if got != tc.want {
			t.Errorf("slot %d: eligible = %v, want %v", tc.slot, got, tc.want)
		}
	}
}
