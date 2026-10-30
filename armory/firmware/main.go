// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Command firmware is the armory-signer bring-up firmware for the USB armory
// Mk II γ. It exercises the SE050 and serves the results over Ethernet over
// USB at http://10.0.0.1/.
package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/usbarmory/tamago/soc/nxp/imx6ul"

	gnet "github.com/usbarmory/go-net"
	usbnet "github.com/usbarmory/go-net/imx-usb"

	"github.com/blinklabs-io/bursa/armory/device"
)

const (
	deviceIP  = "10.0.0.1/24"
	hostIP    = "10.0.0.2"
	deviceMAC = "1a:55:89:a2:69:41"
	hostMAC   = "1a:55:89:a2:69:42"
)

func startNetwork() (err error) {
	iface := &gnet.Interface{
		Stack: gnet.NewGVisorStack(1),
	}

	if err = iface.Init(deviceIP, deviceMAC, hostIP); err != nil {
		return fmt.Errorf("stack, %w", err)
	}

	iface.Stack.EnableICMP()
	net.SocketFunc = iface.Stack.Socket

	ecm := &usbnet.ECM{
		Stack: iface.Stack,
	}

	ecm.HostMAC, _ = net.ParseMAC(hostMAC)
	ecm.DeviceMAC, _ = net.ParseMAC(deviceMAC)

	if err = ecm.Init(); err != nil {
		return fmt.Errorf("ECM, %w", err)
	}

	port := imx6ul.USB1
	port.Init()
	port.DeviceMode()

	// poll endpoints rather than servicing interrupts
	go port.Start(ecm.Device)

	return
}

func main() {
	log.SetFlags(0)

	report := &Report{}

	if err := startNetwork(); err != nil {
		log.Fatalf("network: %v", err)
	}

	// one lock for the SE050 session, shared by every endpoint
	mu := &sync.Mutex{}
	s := &legacy
	s.Mutex = mu
	svc := device.New(mu, report.Logf)
	if network != 0 && chain == "" {
		log.Fatal("a mainnet build needs a chain label")
	}

	svc.SetNetwork(network, chain)
	report.Logf("%s", buildMode)

	if chain == "" {
		report.Logf("network: %s (id %d); other networks' profiles are refused", networkName, network)
	} else {
		report.Logf("network: %s (id %d), chain %s; other chains' profiles are refused", networkName, network, chain)
	}

	if testnetSign != "" {
		report.Logf("%s", testnetSign)
	}

	go runBringup(report, s, svc)

	http.HandleFunc("/{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, report.String())
	})

	routes(svc, s, mu)

	l, err := net.Listen("tcp4", ":80")

	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	log.Fatal(http.Serve(l, nil))
}
