package cardanonet

import "testing"

func TestNetworkValidationAndAddressIDs(t *testing.T) {
	for _, name := range []string{"preview", "preprod", "mainnet"} {
		if !ValidNetwork(name) {
			t.Fatalf("ValidNetwork(%q) = false, want true", name)
		}
		if _, err := AddressNetworkID(name); err != nil {
			t.Fatalf("AddressNetworkID(%q): %v", name, err)
		}
	}
	if ValidNetwork("mainnte") {
		t.Fatal("ValidNetwork typo = true, want false")
	}
	if _, err := AddressNetworkID("mainnte"); err == nil {
		t.Fatal("AddressNetworkID typo: expected error, got nil")
	}
}
