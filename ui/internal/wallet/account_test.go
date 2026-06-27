package wallet

import (
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa"
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
