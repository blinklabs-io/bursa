package wallet

import (
	"reflect"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/bip32"
	"github.com/btcsuite/btcd/btcutil/bech32"
)

const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func TestDerivePreview(t *testing.T) {
	acct, err := Derive(testMnemonic, "preview", 5)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if !strings.HasPrefix(acct.StakeAddress, "stake_test1") {
		t.Fatalf("stake address = %q, want stake_test1… prefix", acct.StakeAddress)
	}
	if len(acct.ReceiveAddresses) != 5 {
		t.Fatalf("got %d receive addresses, want 5", len(acct.ReceiveAddresses))
	}
	if len(acct.ChangeAddresses) != 5 {
		t.Fatalf("got %d change addresses, want 5", len(acct.ChangeAddresses))
	}
	seen := map[string]bool{}
	for i, a := range acct.ReceiveAddresses {
		if !strings.HasPrefix(a, "addr_test1") {
			t.Fatalf("receive[%d] = %q, want addr_test1… prefix", i, a)
		}
		if seen[a] {
			t.Fatalf("receive[%d] = %q is a duplicate", i, a)
		}
		seen[a] = true
	}
	for i, a := range acct.ChangeAddresses {
		if !strings.HasPrefix(a, "addr_test1") {
			t.Fatalf("change[%d] = %q, want addr_test1… prefix", i, a)
		}
		if seen[a] {
			t.Fatalf("change[%d] = %q duplicates a derived address", i, a)
		}
		seen[a] = true
	}
	w, err := bursa.NewWallet(testMnemonic, bursa.WithNetwork("preview"))
	if err != nil {
		t.Fatalf("NewWallet: %v", err)
	}
	if acct.ReceiveAddresses[0] != w.PaymentAddress {
		t.Fatalf("address[0] = %q, want %q (bursa.NewWallet)", acct.ReceiveAddresses[0], w.PaymentAddress)
	}
	if acct.StakeAddress != w.StakeAddress {
		t.Fatalf("stake = %q, want %q (bursa.NewWallet)", acct.StakeAddress, w.StakeAddress)
	}
}

func TestDeriveDeterministic(t *testing.T) {
	a1, err := Derive(testMnemonic, "preview", 3)
	if err != nil {
		t.Fatalf("Derive #1: %v", err)
	}
	a2, err := Derive(testMnemonic, "preview", 3)
	if err != nil {
		t.Fatalf("Derive #2: %v", err)
	}
	if a1.StakeAddress != a2.StakeAddress {
		t.Fatalf("stake not deterministic: %q vs %q", a1.StakeAddress, a2.StakeAddress)
	}
	for i := range a1.ReceiveAddresses {
		if a1.ReceiveAddresses[i] != a2.ReceiveAddresses[i] {
			t.Fatalf("receive[%d] not deterministic", i)
		}
	}
	for i := range a1.ChangeAddresses {
		if a1.ChangeAddresses[i] != a2.ChangeAddresses[i] {
			t.Fatalf("change[%d] not deterministic", i)
		}
	}
}

func TestDeriveFromMnemonicBytesMatchesStringDerive(t *testing.T) {
	fromString, err := Derive(testMnemonic, "preview", 3)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	fromBytes, err := DeriveFromMnemonicBytes([]byte(testMnemonic), "preview", 3)
	if err != nil {
		t.Fatalf("DeriveFromMnemonicBytes: %v", err)
	}
	if fromBytes.StakeAddress != fromString.StakeAddress {
		t.Fatalf("stake = %q, want %q", fromBytes.StakeAddress, fromString.StakeAddress)
	}
	if len(fromBytes.ReceiveAddresses) != len(fromString.ReceiveAddresses) {
		t.Fatalf("got %d receive addresses, want %d", len(fromBytes.ReceiveAddresses), len(fromString.ReceiveAddresses))
	}
	if len(fromBytes.ChangeAddresses) != len(fromString.ChangeAddresses) {
		t.Fatalf("got %d change addresses, want %d", len(fromBytes.ChangeAddresses), len(fromString.ChangeAddresses))
	}
	for i := range fromString.ReceiveAddresses {
		if fromBytes.ReceiveAddresses[i] != fromString.ReceiveAddresses[i] {
			t.Fatalf("receive[%d] = %q, want %q", i, fromBytes.ReceiveAddresses[i], fromString.ReceiveAddresses[i])
		}
	}
	for i := range fromString.ChangeAddresses {
		if fromBytes.ChangeAddresses[i] != fromString.ChangeAddresses[i] {
			t.Fatalf("change[%d] = %q, want %q", i, fromBytes.ChangeAddresses[i], fromString.ChangeAddresses[i])
		}
	}

	xpubString, err := AccountXpub(testMnemonic)
	if err != nil {
		t.Fatalf("AccountXpub: %v", err)
	}
	xpubBytes, err := AccountXpubFromMnemonicBytes([]byte(testMnemonic))
	if err != nil {
		t.Fatalf("AccountXpubFromMnemonicBytes: %v", err)
	}
	if xpubBytes != xpubString {
		t.Fatalf("xpub = %q, want %q", xpubBytes, xpubString)
	}
}

func TestDeriveInvalidMnemonic(t *testing.T) {
	if _, err := Derive("not a valid mnemonic", "preview", 1); err == nil {
		t.Fatal("expected error for invalid mnemonic, got nil")
	}
}

func TestDeriveInvalidNetwork(t *testing.T) {
	// "mainnte" (typo) must not silently derive testnet addresses.
	if _, err := Derive(testMnemonic, "mainnte", 1); err == nil {
		t.Fatal("expected error for invalid network, got nil")
	}
}

func TestDeriveValidatesInputsBeforeMnemonic(t *testing.T) {
	if _, err := Derive("not a valid mnemonic", "preview", 0); err == nil || !strings.Contains(err.Error(), "windowN") {
		t.Fatalf("Derive invalid window + mnemonic = %v, want window validation error", err)
	}
	if _, err := Derive("not a valid mnemonic", "mainnte", 1); err == nil || !strings.Contains(err.Error(), "unknown network") {
		t.Fatalf("Derive invalid network + mnemonic = %v, want network validation error", err)
	}
	if _, err := DeriveFromMnemonicBytes([]byte("not a valid mnemonic"), "preview", 0); err == nil || !strings.Contains(err.Error(), "windowN") {
		t.Fatalf("DeriveFromMnemonicBytes invalid window + mnemonic = %v, want window validation error", err)
	}
}

func TestDeriveInvalidWindow(t *testing.T) {
	// windowN < 1 must error, not panic (negative cap) or derive nothing.
	for _, n := range []int{-1, 0} {
		if _, err := Derive(testMnemonic, "preview", n); err == nil {
			t.Fatalf("windowN=%d: expected error, got nil", n)
		}
	}
}

// TestDeriveAccountIndexDiffersAndMatchesVectors is the multi-account derivation
// guard: account index 1 must produce a DIFFERENT stake address and receive
// window than account 0, must record its AccountIndex, and must match the
// canonical bursa.NewWallet(WithAccountID) vector for that index.
func TestDeriveAccountIndexDiffersAndMatchesVectors(t *testing.T) {
	acct0, err := DeriveAccount(testMnemonic, "preview", 0, 5)
	if err != nil {
		t.Fatalf("DeriveAccount(0): %v", err)
	}
	acct1, err := DeriveAccount(testMnemonic, "preview", 1, 5)
	if err != nil {
		t.Fatalf("DeriveAccount(1): %v", err)
	}
	if acct0.AccountIndex != 0 || acct1.AccountIndex != 1 {
		t.Fatalf("AccountIndex = %d,%d, want 0,1", acct0.AccountIndex, acct1.AccountIndex)
	}
	if acct0.StakeAddress == acct1.StakeAddress {
		t.Fatalf("account 0 and 1 share stake address %q", acct0.StakeAddress)
	}
	if acct0.ReceiveAddresses[0] == acct1.ReceiveAddresses[0] {
		t.Fatalf("account 0 and 1 share receive[0] %q", acct0.ReceiveAddresses[0])
	}

	// Standard vector: account 1 must match bursa's own account-1 derivation.
	w1, err := bursa.NewWallet(testMnemonic, bursa.WithNetwork("preview"), bursa.WithAccountID(1))
	if err != nil {
		t.Fatalf("NewWallet(account 1): %v", err)
	}
	if acct1.ReceiveAddresses[0] != w1.PaymentAddress {
		t.Fatalf("account1 receive[0] = %q, want %q", acct1.ReceiveAddresses[0], w1.PaymentAddress)
	}
	if acct1.StakeAddress != w1.StakeAddress {
		t.Fatalf("account1 stake = %q, want %q", acct1.StakeAddress, w1.StakeAddress)
	}

	// Derive is the account-0 shorthand and must equal DeriveAccount(…, 0, …).
	acctDefault, err := Derive(testMnemonic, "preview", 5)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if acctDefault.StakeAddress != acct0.StakeAddress {
		t.Fatalf("Derive != DeriveAccount(0): %q vs %q", acctDefault.StakeAddress, acct0.StakeAddress)
	}
}

// TestDeriveAccountRejectsHardenedIndex guards the account-index bound.
func TestDeriveAccountRejectsHardenedIndex(t *testing.T) {
	if _, err := DeriveAccount(testMnemonic, "preview", 1<<31, 1); err == nil {
		t.Fatal("DeriveAccount with hardened index = nil error, want rejection")
	}
	if _, err := AccountXpubForIndexFromMnemonicBytes([]byte(testMnemonic), 1<<31); err == nil {
		t.Fatal("AccountXpubForIndexFromMnemonicBytes hardened index = nil error, want rejection")
	}
}

func TestDeriveFromAccountXpubMatchesMnemonic(t *testing.T) {
	mnemonic := testMnemonic
	fromMnem, err := DeriveFromMnemonicBytes([]byte(mnemonic), "preview", 5)
	if err != nil {
		t.Fatal(err)
	}
	xpub, err := AccountXpubFromMnemonicBytes([]byte(mnemonic))
	if err != nil {
		t.Fatal(err)
	}

	// Hardware wallets use the standard acct_xvk HRP. AccountXpub currently
	// emits root_xvk, so re-label the same payload to cover both accepted forms.
	_, payload, err := bip32.LenientBech32Decode(xpub)
	if err != nil {
		t.Fatal(err)
	}
	acctXpub, err := bech32.Encode("acct_xvk", payload)
	if err != nil {
		t.Fatal(err)
	}

	for _, encoded := range []string{xpub, acctXpub} {
		fromXpub, err := DeriveFromAccountXpub(encoded, "preview", 0, 5)
		if err != nil {
			t.Fatalf("DeriveFromAccountXpub(%q): %v", encoded[:8], err)
		}
		if !reflect.DeepEqual(fromXpub, fromMnem) {
			t.Fatalf("account mismatch for %q HRP:\n xpub: %+v\n mnem: %+v", encoded[:8], fromXpub, fromMnem)
		}
	}
}

func TestDeriveFromAccountXpubRejectsHardenedAccountIndex(t *testing.T) {
	xpub, err := AccountXpubFromMnemonicBytes([]byte(testMnemonic))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DeriveFromAccountXpub(xpub, "preview", 1<<31, 1); err == nil {
		t.Fatal("expected hardened account index to be rejected")
	}
}
