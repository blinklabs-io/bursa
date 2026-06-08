package cardanonet

import (
	"fmt"
	"strings"

	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

type network struct {
	name             string
	addressNetworkID uint8
}

var supportedNetworks = []network{
	{name: "preview", addressNetworkID: lcommon.AddressNetworkTestnet},
	{name: "preprod", addressNetworkID: lcommon.AddressNetworkTestnet},
	{name: "mainnet", addressNetworkID: lcommon.AddressNetworkMainnet},
}

// SupportedNetworks returns the UI-supported Cardano networks in display order.
func SupportedNetworks() string {
	names := make([]string, len(supportedNetworks))
	for i, n := range supportedNetworks {
		names[i] = n.name
	}
	return strings.Join(names, ", ")
}

// ValidNetwork reports whether name is a supported Cardano network.
func ValidNetwork(name string) bool {
	_, ok := lookup(name)
	return ok
}

// AddressNetworkID returns the ledger address network id for a supported network.
func AddressNetworkID(name string) (uint8, error) {
	n, ok := lookup(name)
	if !ok {
		return 0, fmt.Errorf("unknown network %q: must be one of %s", name, SupportedNetworks())
	}
	return n.addressNetworkID, nil
}

func lookup(name string) (network, bool) {
	for _, n := range supportedNetworks {
		if n.name == name {
			return n, true
		}
	}
	return network{}, false
}
