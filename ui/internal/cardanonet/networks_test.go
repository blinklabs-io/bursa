package cardanonet

import "testing"

func TestNetworkValidationAndAddressIDs(t *testing.T) {
	for _, name := range []string{"preview", "preprod", "mainnet", "musashi", "dijkstra"} {
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

func TestProtocolMagic(t *testing.T) {
	want := map[string]uint32{
		"mainnet": 764824073, "preprod": 1, "preview": 2, "musashi": 164, "dijkstra": 6,
	}
	for name, magic := range want {
		got, err := ProtocolMagic(name)
		if err != nil || got != magic {
			t.Fatalf("ProtocolMagic(%q) = %d, %v; want %d", name, got, err, magic)
		}
	}
	if _, err := ProtocolMagic("nope"); err == nil {
		t.Fatal("ProtocolMagic unknown: expected error")
	}
}
