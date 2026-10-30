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

// Command armory-pool is the host side of a pool registration with the USB
// armory signer: it fetches and pins the device keys, has the device witness
// an unsigned transaction body, and has it issue an operational certificate.
// Every device answer is verified before anything is written. Results go to
// stdout, diagnostics to stderr. Like opcert-check it binds its connections
// to the USB network source address.
//
//	armory-pool -identity HEX -profile NAME keys -out-dir DIR [-network preview]
//	armory-pool -identity HEX -profile NAME witness -role pool|stake -tx-file F -out W
//	armory-pool -identity HEX -profile NAME opcert -kes-vkey F -kes-period N -chain-counter N|none -out F
//	armory-pool reward-hex stake_test1...
//	armory-pool address -stake-vkey F [-payment-vkey F] [-type base|reward] [-network preview]
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/blinklabs-io/bursa/armory/device"
)

type client struct {
	http *http.Client
	base string
}

// newClient binds connections to source when it is not empty.
func newClient(base, source string) *client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}

	if source != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(source)}
	}

	return &client{
		base: strings.TrimRight(base, "/"),
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{DialContext: dialer.DialContext},
		},
	}
}

// post sends req as JSON and decodes the JSON answer into resp.
func (c *client) post(path string, req, resp any) error {
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	res, err := c.http.Post(c.base+path, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}

	defer res.Body.Close()

	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("POST %s: %s: %s", path, res.Status, bytes.TrimSpace(b))
	}

	return json.Unmarshal(b, resp)
}

// session is a device connection with the pinned identity.
type session struct {
	c        *client
	identity ed25519.PublicKey
	profile  string
	// hostKey authenticates signing requests when set
	hostKey ed25519.PrivateKey
}

func randomNonce() ([]byte, error) {
	n := make([]byte, 32)
	_, err := rand.Read(n)

	return n, err
}

// inventory fetches the profile's keys and verifies their attestation.
func (s *session) inventory() (map[string]ed25519.PublicKey, error) {
	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}

	var inv device.Inventory

	if err = s.c.post("/v1/inventory", device.InventoryRequest{Nonce: nonce, Profile: s.profile}, &inv); err != nil {
		return nil, err
	}

	return verifyInventory(s.identity, nonce, inv)
}

func (s *session) keys(outDir, network string, out io.Writer) error {
	netID, err := networkID(network)
	if err != nil {
		return err
	}

	keys, err := s.inventory()
	if err != nil {
		return err
	}

	pool, owner := keys["pool"], keys["stake"]

	if err = os.MkdirAll(outDir, 0o700); err != nil {
		return err
	}

	for _, f := range []struct {
		name, typ, desc string
		pub             []byte
	}{
		{"pool-cold.vkey", poolVkeyType, poolVkeyDesc, pool},
		{"owner.vkey", stakeVkeyType, stakeVkeyDesc, owner},
	} {
		if err = os.WriteFile(filepath.Join(outDir, f.name), marshalEnvelope(f.typ, f.desc, vkeyCBOR(f.pub)), 0o600); err != nil {
			return err
		}
	}

	poolID := hash224(pool)

	poolBech, err := toBech32("pool", poolID[:])
	if err != nil {
		return err
	}

	vk, err := toBech32("stake_vk", owner)
	if err != nil {
		return err
	}

	reward, err := rewardAddress(netID, owner)
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "pool id hex %x\n", poolID)
	fmt.Fprintf(out, "pool id bech32 %s\n", poolBech)
	fmt.Fprintf(out, "owner key hash %s\n", hexHash(owner))
	fmt.Fprintf(out, "owner stake_vk %s\n", vk)
	fmt.Fprintf(out, "owner reward address %s\n", reward)

	return nil
}

func (s *session) witness(role, txFile, outFile string, out io.Writer) error {
	if role != "pool" && role != "stake" {
		return fmt.Errorf("unknown role %q (pool or stake)", role)
	}

	data, err := os.ReadFile(txFile)
	if err != nil {
		return err
	}

	tx, err := readTx(data)
	if err != nil {
		return err
	}

	body, err := txBody(tx)
	if err != nil {
		return err
	}

	keys, err := s.inventory()
	if err != nil {
		return err
	}

	nonce, err := randomNonce()
	if err != nil {
		return err
	}

	pub := keys[role]
	req := txBodyRequest(s.profile, role, pub, nonce, body)

	var resp device.SignResponse

	if err = s.sign(req, &resp); err != nil {
		return err
	}

	wit, err := checkTxBody(req, resp, pub)
	if err != nil {
		return err
	}

	if err = os.WriteFile(outFile, marshalEnvelope(witnessType, witnessDesc, wit), 0o600); err != nil {
		return err
	}

	// the request negotiated device.ProtocolSummary, so the summary is covered
	// by the binding signature checked above
	if resp.Summary != "" {
		_, err = fmt.Fprintf(out, "device signed: %s\n", resp.Summary)
	}

	return err
}

func (s *session) opcert(kesFile string, period uint64, chainArg, outFile string, out io.Writer) error {
	var chain uint64

	if chainArg != "none" {
		var err error

		if chain, err = strconv.ParseUint(chainArg, 10, 64); err != nil {
			return fmt.Errorf("invalid -chain-counter %q (a number or none)", chainArg)
		}
	}

	data, err := os.ReadFile(kesFile)
	if err != nil {
		return err
	}

	_, raw, err := readEnvelope(data)
	if err != nil {
		return err
	}

	if len(raw) != 34 || raw[0] != 0x58 || raw[1] != 0x20 {
		return errors.New("-kes-vkey cborHex is not a 32-byte key")
	}

	kes := raw[2:]

	keys, err := s.inventory()
	if err != nil {
		return err
	}

	nonce, err := randomNonce()
	if err != nil {
		return err
	}

	pub := keys["pool"]
	req := opCertRequest(s.profile, pub, nonce, kes, chain, period)

	var resp device.SignResponse

	if err = s.sign(req, &resp); err != nil {
		return err
	}

	cert, issue, err := checkOpCert(req, resp, pub, chain, period)
	if err != nil {
		return err
	}

	if err = os.WriteFile(outFile, marshalOpCertEnvelope(cert), 0o600); err != nil {
		return err
	}

	fmt.Fprintf(out, "issue counter %d\n", issue)

	return nil
}

func address(paymentFile, stakeFile, typ, network string, out io.Writer) error {
	netID, err := networkID(network)
	if err != nil {
		return err
	}

	data, err := os.ReadFile(stakeFile)
	if err != nil {
		return err
	}

	stake, err := readVkey(data, stakeVkeyType)
	if err != nil {
		return fmt.Errorf("-stake-vkey: %w", err)
	}

	var addr string

	switch typ {
	case "reward":
		addr, err = rewardAddress(netID, stake)
	case "base":
		if data, err = os.ReadFile(paymentFile); err != nil {
			return err
		}

		var payment ed25519.PublicKey

		if payment, err = readVkey(data, paymentVkeyType); err != nil {
			return fmt.Errorf("-payment-vkey: %w", err)
		}

		addr, err = baseAddress(netID, payment, stake)
	default:
		return fmt.Errorf("unknown -type %q (base or reward)", typ)
	}

	if err != nil {
		return err
	}

	fmt.Fprintln(out, addr)

	return nil
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("armory-pool", flag.ContinueOnError)
	base := fs.String("signer", "http://10.0.0.1", "armory-signer URL")
	source := fs.String("source", "10.0.0.2", "local source address on the USB network")
	identityHex := fs.String("identity", "", "device identity public key (hex), pinned")
	profileName := fs.String("profile", "", "device profile holding the pool keys")
	hostKeyFile := fs.String("host-key", "", "host signing key file authenticating signing requests")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() == 0 {
		return errors.New("subcommand required: keys, witness, opcert, reward-hex, address, host-key")
	}

	sub, rest := fs.Arg(0), fs.Args()[1:]
	sf := flag.NewFlagSet(sub, flag.ContinueOnError)

	connect := func() (*session, error) {
		id, err := hex.DecodeString(*identityHex)
		if err != nil || len(id) != ed25519.PublicKeySize {
			return nil, errors.New("-identity must be the 32-byte identity public key in hex")
		}

		if *profileName == "" {
			return nil, errors.New("-profile is required")
		}

		s := &session{c: newClient(*base, *source), identity: id, profile: *profileName}

		if *hostKeyFile != "" {
			if s.hostKey, err = readHostKey(*hostKeyFile); err != nil {
				return nil, err
			}
		}

		return s, nil
	}

	switch sub {
	case "keys":
		outDir := sf.String("out-dir", "", "directory for pool-cold.vkey and owner.vkey")
		network := sf.String("network", "preview", "network for the reward address")

		if err := sf.Parse(rest); err != nil {
			return err
		}

		if *outDir == "" {
			return errors.New("-out-dir is required")
		}

		s, err := connect()
		if err != nil {
			return err
		}

		return s.keys(*outDir, *network, stdout)
	case "witness":
		role := sf.String("role", "", "pool or stake")
		txFile := sf.String("tx-file", "", "unsigned transaction envelope")
		out := sf.String("out", "", "witness file to write")

		if err := sf.Parse(rest); err != nil {
			return err
		}

		if *txFile == "" || *out == "" {
			return errors.New("-tx-file and -out are required")
		}

		s, err := connect()
		if err != nil {
			return err
		}

		return s.witness(*role, *txFile, *out, stdout)
	case "opcert":
		kes := sf.String("kes-vkey", "", "KES verification key envelope")
		period := sf.Uint64("kes-period", 0, "KES period")
		chain := sf.String("chain-counter", "", "pool's on-chain opcert counter, or none")
		out := sf.String("out", "", "certificate file to write")

		if err := sf.Parse(rest); err != nil {
			return err
		}

		if *kes == "" || *chain == "" || *out == "" {
			return errors.New("-kes-vkey, -chain-counter and -out are required")
		}

		s, err := connect()
		if err != nil {
			return err
		}

		return s.opcert(*kes, *period, *chain, *out, stdout)
	case "host-key":
		out := sf.String("out", "", "host signing key file to create")

		if err := sf.Parse(rest); err != nil {
			return err
		}

		if *out == "" {
			return errors.New("-out is required")
		}

		return newHostKey(*out, stdout)
	case "reward-hex":
		if len(rest) != 1 {
			return errors.New("usage: reward-hex <stake_test1...>")
		}

		h, err := rewardHex(rest[0])
		if err != nil {
			return err
		}

		fmt.Fprintln(stdout, h)

		return nil
	case "address":
		payment := sf.String("payment-vkey", "", "payment verification key envelope")
		stake := sf.String("stake-vkey", "", "stake verification key envelope")
		typ := sf.String("type", "base", "base or reward")
		network := sf.String("network", "preview", "preview, preprod, testnet or mainnet")

		if err := sf.Parse(rest); err != nil {
			return err
		}

		return address(*payment, *stake, *typ, *network, stdout)
	}

	return fmt.Errorf("unknown subcommand %q", sub)
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "armory-pool:", err)
		os.Exit(1)
	}
}
