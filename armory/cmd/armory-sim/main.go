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

// Command armory-sim serves the USB armory device service on a loopback
// address with a virtual SE050 and a file-backed log card, for testing
// hosts (armory-pool, the Bursa signer's armory backend) without hardware.
//
// The chip and card persist in the state directory, so running the
// provisioning image, then the signing image, against one directory
// mirrors reflashing a device. Private keys are stored in plaintext: use
// test keys only.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/blinklabs-io/bursa/armory/device"
	"github.com/blinklabs-io/bursa/armory/profile"
	"github.com/blinklabs-io/bursa/armory/signlog"
	"github.com/blinklabs-io/bursa/armory/signlog/chipstore"
	"github.com/blinklabs-io/bursa/armory/signlog/sdmedium"
)

type options struct {
	listen     string
	state      string
	image      string
	network    string
	chain      string
	cardBlocks uint64
}

func main() {
	var o options

	flag.StringVar(&o.listen, "listen", "127.0.0.1:18080", "loopback address to serve on")
	flag.StringVar(&o.state, "state", "", "directory holding chip.json and card.img (required)")
	flag.StringVar(&o.image, "image", "sign", "image to run: sign, provision or wipe")
	flag.StringVar(&o.network, "network", "testnet", "network the image serves: testnet or mainnet")
	flag.StringVar(&o.chain, "chain", "", "chain of a mainnet image: cardano or prime")
	flag.Uint64Var(&o.cardBlocks, "card-blocks", 1<<17, "size of a new log card image in 512-byte blocks")
	flag.Parse()

	h, err := build(o, log.Printf)
	if err != nil {
		log.Fatal(err)
	}

	srv := &http.Server{
		Addr:    o.listen,
		Handler: h,
		// the firmware server's limits
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	log.Printf("armory-sim: %s image, %s, serving %s; keys in %s are PLAINTEXT test keys", o.image, o.network, o.listen, o.state)
	log.Fatal(srv.ListenAndServe())
}

// build validates o and returns the device handler for the chosen image.
func build(o options, logf func(string, ...any)) (http.Handler, error) {
	if err := loopback(o.listen); err != nil {
		return nil, err
	}

	if o.state == "" {
		return nil, errors.New("-state is required")
	}

	network, chain, err := scope(o.network, o.chain)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(o.state, 0o700); err != nil {
		return nil, err
	}

	// each process keeps the chip in memory and saves it whole, so a second
	// simulator on the same state would overwrite the first one's objects
	if err := lockState(o.state); err != nil {
		return nil, err
	}

	chip, err := openChip(filepath.Join(o.state, "chip.json"))
	if err != nil {
		return nil, err
	}

	mu := &sync.Mutex{}
	svc := device.New(mu, logf)
	svc.SetNetwork(network, chain)

	if err := svc.SetChip(chip); err != nil {
		return nil, fmt.Errorf("chip: %w", err)
	}

	mux := http.NewServeMux()

	switch o.image {
	case "sign":
		svc.RequireSigningLog()

		if err := openSigningLog(mu, svc, chip, filepath.Join(o.state, "card.img"), o.cardBlocks); err != nil {
			logf("signing log: NOT OPEN, signing is refused: %v", err)
			svc.SigningLogFailed(err)
		}

		mux.Handle("/v1/", svc.SigningHandler())
	case "provision":
		mux.Handle("/provision/", svc.ProvisioningHandler())
		mux.Handle("/v1/challenge", svc.ProvisioningHandler())
	case "wipe":
		mux.Handle("/wipe/", svc.WipeHandler())
		mux.Handle("/v1/challenge", svc.WipeHandler())
	default:
		return nil, fmt.Errorf("-image must be sign, provision or wipe, got %q", o.image)
	}

	guarded := device.Guard(device.Address, mux)

	// the device only answers requests addressed to its own link address;
	// the simulator is reached on loopback instead, and refuses any other
	// Host, as a browser sends after DNS rebinding
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !loopbackHost(r.Host) {
			http.Error(w, "unexpected host", http.StatusForbidden)
			return
		}

		r.Host = device.Address
		guarded.ServeHTTP(w, r)
	}), nil
}

// loopbackHost reports whether a request Host names this machine's loopback
// interface: localhost or a loopback IP address, with or without a port.
func loopbackHost(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if strings.EqualFold(host, "localhost") {
		return true
	}

	ip := net.ParseIP(host)

	return ip != nil && ip.IsLoopback()
}

func loopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("-listen: %w", err)
	}

	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("-listen must be a loopback IP address, got %q", host)
	}

	return nil
}

// scope maps the flags to the network id and chain label the firmware
// Makefile sets for the same build.
func scope(network, chain string) (uint8, string, error) {
	switch network {
	case "testnet":
		if chain != "" {
			return 0, "", errors.New("-chain applies only to -network mainnet")
		}

		return 0, "", nil
	case "mainnet":
		if chain != "cardano" && chain != "prime" {
			return 0, "", errors.New("-network mainnet needs -chain cardano or prime")
		}

		return 1, chain + "-mainnet", nil
	default:
		return 0, "", fmt.Errorf("-network must be testnet or mainnet, got %q", network)
	}
}

// openSigningLog opens the log on the card image against the head in the
// chip, as the signing firmware does with the microSD card.
func openSigningLog(lock sync.Locker, svc *device.Service, chip *fileChip, path string, blocks uint64) error {
	card, err := openCard(path, blocks)
	if err != nil {
		return err
	}

	m, err := sdmedium.Open(card)
	if err != nil {
		return err
	}

	w, err := openLog(lock, chip, m)
	if err != nil {
		return err
	}

	// SetSigningLog takes the service lock itself
	svc.SetSigningLog(w, m)

	return nil
}

// openLog opens the log under the chip lock the service shares.
func openLog(lock sync.Locker, chip *fileChip, m signlog.Medium) (*signlog.Writer, error) {
	lock.Lock()
	defer lock.Unlock()

	id, err := chipstore.NewIdentity(chip, profile.IdentityKeyID)
	if err != nil {
		return nil, err
	}

	return signlog.Open(m, chipstore.NewHeadStore(chip, profile.SignLogHeadID), id)
}
