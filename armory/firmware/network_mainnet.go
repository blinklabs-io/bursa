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

//go:build mainnet

package main

import (
	"log"

	"github.com/blinklabs-io/bursa/armory/device"
)

// network is the only network id whose profiles this build serves.
const (
	network     uint8 = 1
	networkName       = "mainnet"
)

// chain is the only chain label ("name@chain") this build serves, set by the
// Makefile from CHAIN. Mainnets share network id 1, so the label keeps one
// chain's profiles per device.
var chain string

// configureScope fixes the image to one mainnet chain.
func configureScope(svc *device.Service, report *Report) {
	if chain == "" {
		log.Fatal("a mainnet build needs a chain label")
	}

	svc.SetNetwork(network, chain)
	report.Logf("network: %s (id %d), chain %s; other chains' profiles are refused", networkName, network, chain)
}
