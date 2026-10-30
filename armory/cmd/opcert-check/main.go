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

// Command opcert-check verifies a provisioned armory-signer cold key against
// public pool material: the cold verification key, the pool id, and an
// existing operational certificate. It asks the device for opcert-next with
// the chain counter one below the certificate's issue number, so the device
// must choose that issue number and reproduce the cold signature byte for
// byte (Ed25519 is deterministic). Like any opcert-next request it raises
// the profile's floor to that chain counter; POST /provision/floor resets it.
//
// With -host-key it authenticates the request with a host signing key
// registered on the device, as armory-pool -host-key does; a device with
// registered host keys refuses an unauthenticated request.
//
// It reads only public inputs (and the host key, if given) and binds its connections to the USB network
// source address so requests cannot leave through another route.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/blinklabs-io/bursa/armory/device"
	"github.com/blinklabs-io/bursa/armory/hostkey"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2b"
)

func decodeCBORHex(s string, v any) error {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return err
	}

	return cbor.Unmarshal(b, v)
}

// opCert is [[kes_vkey, issue_number, kes_period, cold_signature], cold_vkey].
type opCert struct {
	_       struct{} `cbor:",toarray"`
	Body    opCertBody
	ColdKey []byte
}

type opCertBody struct {
	_           struct{} `cbor:",toarray"`
	KESKey      []byte
	IssueNumber uint64
	KESPeriod   uint64
	ColdSig     []byte
}

// signable matches gouroboros common.OpCertSignableBytes.
func (b opCertBody) signable() []byte {
	out := append([]byte{}, b.KESKey...)
	out = binary.BigEndian.AppendUint64(out, b.IssueNumber)
	return binary.BigEndian.AppendUint64(out, b.KESPeriod)
}

type client struct {
	http *http.Client
	base string
}

func newClient(base, source string) *client {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)},
	}

	return &client{
		base: base,
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{DialContext: dialer.DialContext},
		},
	}
}

func (c *client) do(method, path, body string) (string, error) {
	req, err := http.NewRequest(method, c.base+path, strings.NewReader(body))
	if err != nil {
		return "", err
	}

	res, err := c.http.Do(req)
	if err != nil {
		return "", err
	}

	defer res.Body.Close()

	b, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s %s: %s: %s", method, path, res.Status, bytes.TrimSpace(b))
	}

	return strings.TrimSpace(string(b)), nil
}

// sign posts sr to /v1/sign and decodes the response. With a host key it
// first fetches a challenge and authenticates the request sent; the response
// binding is still over sr, since it does not cover the host fields.
func (c *client) sign(sr device.SignRequest, hostKey ed25519.PrivateKey, resp *device.SignResponse) error {
	if hostKey != nil {
		out, err := c.do(http.MethodPost, "/v1/challenge", "{}")
		if err != nil {
			return err
		}

		var ch device.ChallengeResponse

		if err = json.Unmarshal([]byte(out), &ch); err != nil {
			return err
		}

		sr = hostkey.Authenticate(sr, hostKey, ch.Challenge)
	}

	req, err := json.Marshal(sr)
	if err != nil {
		return err
	}

	out, err := c.do(http.MethodPost, "/v1/sign", string(req))
	if err != nil {
		return err
	}

	return json.Unmarshal([]byte(out), resp)
}

func main() {
	log.SetFlags(0)

	if err := run(os.Args[1:], log.Writer()); err != nil {
		log.Fatal(err)
	}
}

// run verifies the cert and reports each passed check to out. It returns an
// error for the first failed check.
func run(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("opcert-check", flag.ContinueOnError)
	vkeyHex := fs.String("vkey", "", "cold verification key cborHex (node.vkey)")
	certHex := fs.String("cert", "", "operational certificate cborHex (node.cert)")
	poolID := fs.String("pool", "", "expected pool id (hex)")
	profileName := fs.String("profile", "", "device profile holding the cold key")
	base := fs.String("signer", "http://10.0.0.1", "armory-signer URL")
	source := fs.String("source", "10.0.0.2", "local source address on the USB network")
	hostKeyFile := fs.String("host-key", "", "host signing key file authenticating the signing request")

	if err := fs.Parse(args); err != nil {
		// a help request printed the usage and succeeds, as flag.Parse exits 0
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}

		return err
	}

	var vkey []byte

	if err := decodeCBORHex(*vkeyHex, &vkey); err != nil {
		return fmt.Errorf("invalid -vkey: %w", err)
	}

	if len(vkey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid -vkey: %d bytes, want %d", len(vkey), ed25519.PublicKeySize)
	}

	var cert opCert

	if err := decodeCBORHex(*certHex, &cert); err != nil {
		return fmt.Errorf("invalid -cert: %w", err)
	}

	var hostKey ed25519.PrivateKey

	if *hostKeyFile != "" {
		var err error

		if hostKey, err = hostkey.Read(*hostKeyFile); err != nil {
			return fmt.Errorf("invalid -host-key: %w", err)
		}
	}

	c := newClient(*base, *source)

	var failed error

	check := func(name string, ok bool) bool {
		if !ok {
			failed = fmt.Errorf("FAIL %s", name)

			return false
		}

		_, _ = fmt.Fprintf(out, "ok   %s\n", name)

		return true
	}

	h, _ := blake2b.New(28, nil)
	h.Write(vkey)

	if !check("blake2b-224(node.vkey) equals pool id", hex.EncodeToString(h.Sum(nil)) == strings.ToLower(*poolID)) ||
		!check("node.cert cold key equals node.vkey", bytes.Equal(cert.ColdKey, vkey)) ||
		!check("node.cert signature verifies under node.vkey",
			ed25519.Verify(vkey, cert.Body.signable(), cert.Body.ColdSig)) {
		return failed
	}

	if cert.Body.IssueNumber == 0 {
		return errors.New("node.cert issue number 0 has no chain counter below it")
	}

	nonce := make([]byte, 32)

	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	// the chain counter is the one before this cert, so the device's
	// choice of issue number must land on the cert's
	payload := append([]byte{}, cert.Body.KESKey...)
	payload = binary.BigEndian.AppendUint64(payload, cert.Body.IssueNumber-1)
	payload = binary.BigEndian.AppendUint64(payload, cert.Body.KESPeriod)

	sr := device.SignRequest{
		Version: device.Protocol,
		Purpose: "opcert-next",
		KeyHash: *poolID,
		Role:    "pool",
		Nonce:   nonce,
		Payload: payload,
		Profile: *profileName,
	}

	var resp device.SignResponse

	if err := c.sign(sr, hostKey, &resp); err != nil {
		return err
	}

	if resp.Error != "" {
		return fmt.Errorf("FAIL opcert-next refused: %s", resp.Error)
	}

	if !check("response echoes nonce", bytes.Equal(resp.Nonce, nonce)) ||
		!check(fmt.Sprintf("device chose issue counter %d", cert.Body.IssueNumber),
			resp.IssueCounter != nil && *resp.IssueCounter == cert.Body.IssueNumber) ||
		!check(fmt.Sprintf("device reproduces node.cert signature (issue %d, KES period %d)",
			cert.Body.IssueNumber, cert.Body.KESPeriod), bytes.Equal(resp.Signature, cert.Body.ColdSig)) ||
		!check("binding signature covers the request under node.vkey",
			ed25519.Verify(vkey, device.ResponseBinding(sr, resp.Signature), resp.BindingSignature)) {
		return failed
	}

	return nil
}
