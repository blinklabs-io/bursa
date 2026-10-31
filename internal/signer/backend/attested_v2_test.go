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

package backend

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// TestAttestedSummaryBindingVector pins the bytes the armory firmware signs
// over too (armory/device TestResponseBindingSummaryVector).
func TestAttestedSummaryBindingVector(t *testing.T) {
	t.Parallel()
	era := uint(6)
	req := AttestedRequest{
		Version: AttestedProtocolSummary, Purpose: PurposeTxBody, KeyHash: strings.Repeat("ab", 28), Role: KeyTypePool,
		Nonce: bytes.Repeat([]byte{1}, 32), Payload: bytes.Repeat([]byte{2}, 48), Profile: "otg@preview", Era: &era,
	}
	sig := bytes.Repeat([]byte{4}, 64)
	const want = "b60325204c042b454e43758b76753047c7a7cc94329a4dfe6c0bc671b34d4c45"
	if got := hex.EncodeToString(AttestedResponseBinding(req, sig, "pledge 1")); got != want {
		t.Fatalf("summary binding = %s, want %s", got, want)
	}
	const wantEmpty = "3c3c52985f23d4b5f9be422dac4cb8a6ebf96062e8bfb8e82324833b05fb8599"
	if got := hex.EncodeToString(AttestedResponseBinding(req, sig, "")); got != wantEmpty {
		t.Fatalf("empty summary binding = %s, want %s", got, wantEmpty)
	}
	req.Version = AttestedProtocol
	const wantV1 = "f32cdc04026da1b47e82bc0af6c5b39b2aa53fe265bc595e7d0ff5fbd057e70b"
	if got := hex.EncodeToString(AttestedResponseBinding(req, sig, "")); got != wantV1 {
		t.Fatalf("version 1 binding = %s, want %s", got, wantV1)
	}
}

const testDeviceSummary = "pool retirement: epoch 500"

// v2Device is a fake armory that authenticates a host key and answers sign
// requests according to behavior.
type v2Device struct {
	mu         sync.Mutex
	behavior   string
	identity   ed25519.PrivateKey
	pool       ed25519.PrivateKey
	host       ed25519.PublicKey
	issued     [][]byte
	versions   []string
	nonces     [][]byte
	inventory  int
	tamperWith string
	failSign   bool
}

// behaviors:
//
//	supported  answers v1 and v2 in the version sent (like the updated firmware)
//	v1only     answers v1 and refuses anything else the way the v1 firmware does
//	echoV1     answers v1 to a v2 request with a valid signature and no error
//	echoV2     answers v2 (with a summary) to a v1 request
//	tampered   as supported, but the summary differs from the bound one
//	otherError refuses v2 with an error that is not the unsupported-version one
//	forgedOK   refuses v2 as unsupported but also carries a signature
//	v1Summary  answers v1 with a summary covered by the binding signature
//
// failSign makes the sign endpoint answer 500 before reading the request.
func (d *v2Device) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch r.URL.Path {
	case "/v1/inventory":
		d.inventory++
		var in struct {
			Nonce []byte `json:"nonce"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		keys := []AttestedKeyInfo{{Role: KeyTypePool, PublicKey: d.pool.Public().(ed25519.PublicKey)}}
		_ = json.NewEncoder(w).Encode(AttestedInventory{
			Version: AttestedProtocol, Keys: keys,
			Attestation: ed25519.Sign(d.identity, InventoryBinding(in.Nonce, keys)),
		})
	case "/v1/challenge":
		c := bytes.Repeat([]byte{byte(len(d.issued) + 1)}, attestedChallengeSize)
		d.issued = append(d.issued, c)
		_ = json.NewEncoder(w).Encode(map[string]any{"version": AttestedProtocol, "challenge": c})
	case "/v1/sign":
		if d.failSign {
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		}
		var req AttestedRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		d.versions = append(d.versions, req.Version)
		d.nonces = append(d.nonces, req.Nonce)
		_ = json.NewEncoder(w).Encode(d.answer(req))
	}
}

func (d *v2Device) answer(req AttestedRequest) AttestedResponse {
	resp := AttestedResponse{Version: AttestedProtocol, Nonce: req.Nonce}
	// the host must hold the latest challenge, which a request consumes
	fresh := len(d.issued) > 0 && bytes.Equal(req.Challenge, d.issued[len(d.issued)-1])
	if !bytes.Equal(req.HostKey, d.host) || !fresh ||
		!ed25519.Verify(d.host, AttestedRequestBinding(req), req.HostSignature) {
		resp.Error = "host authentication failed"
		return resp
	}
	sign := func(version string) {
		hash := blake2b.Sum256(req.Payload)
		resp.Version = version
		resp.Signature = ed25519.Sign(d.pool, hash[:])
		summary := ""
		if version == AttestedProtocolSummary {
			summary = testDeviceSummary
		}
		resp.Summary = summary
		resp.BindingSignature = ed25519.Sign(d.pool, AttestedResponseBinding(req, resp.Signature, summary))
	}
	switch {
	case d.behavior == "v1Summary":
		hash := blake2b.Sum256(req.Payload)
		resp.Signature = ed25519.Sign(d.pool, hash[:])
		resp.Summary = testDeviceSummary
		resp.BindingSignature = ed25519.Sign(d.pool, AttestedResponseBinding(req, resp.Signature, resp.Summary))
	case d.behavior == "echoV2":
		sign(AttestedProtocolSummary)
	case d.behavior == "echoV1" && req.Version == AttestedProtocolSummary:
		sign(AttestedProtocol)
	case req.Version == AttestedProtocol:
		sign(AttestedProtocol)
	case req.Version == AttestedProtocolSummary && d.behavior == "supported":
		sign(AttestedProtocolSummary)
	case req.Version == AttestedProtocolSummary && d.behavior == "tampered":
		sign(AttestedProtocolSummary)
		resp.Summary = "pool retirement: epoch 501"
	case d.behavior == "otherError":
		resp.Error = "profile not provisioned"
	case d.behavior == "forgedOK":
		sign(AttestedProtocol)
		resp.Error = attestedUnsupportedVersion
	default:
		resp.Error = attestedUnsupportedVersion
	}
	return resp
}

// newV2Backend loads an attested backend over a host-key HTTP enclave served
// by a v2Device with the given behavior.
func newV2Backend(t *testing.T, behavior string, mode AttestedProtocolMode) (*v2Device, *AttestedBackend, TxBodySigner) {
	t.Helper()
	_, identity, _ := ed25519.GenerateKey(nil)
	_, pool, _ := ed25519.GenerateKey(nil)
	host, hostPriv, _ := ed25519.GenerateKey(nil)
	dev := &v2Device{behavior: behavior, identity: identity, pool: pool, host: host}
	srv := httptest.NewServer(dev)
	t.Cleanup(srv.Close)
	enclave, err := NewHostKeyHTTPEnclave(srv.URL, "otg@preview", hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewArmoryVerifier(identity.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	b := NewProfiledAttestedBackend("armory", "otg@preview", enclave, verifier).WithProtocolMode(mode)
	if err := b.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	ref, err := b.GetKey(t.Context(), HashPublicKey(pool.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	signer, ok := ref.(TxBodySigner)
	if !ok {
		t.Fatal("attested key does not implement TxBodySigner")
	}
	return dev, b, signer
}

func (d *v2Device) seen() (versions []string, nonces [][]byte, challenges int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.versions...), append([][]byte(nil), d.nonces...), len(d.issued)
}

func sameStrings(a, b []string) bool {
	return strings.Join(a, ",") == strings.Join(b, ",")
}

func TestAttestedV2ReturnsBoundSummary(t *testing.T) {
	t.Parallel()
	for name, mode := range map[string]AttestedProtocolMode{"negotiate": AttestedNegotiate, "require": AttestedRequireVersion2} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dev, _, signer := newV2Backend(t, "supported", mode)
			sig, summary, err := signer.SignTxBody(t.Context(), []byte{0xa0}, 6)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if len(sig) != ed25519.SignatureSize {
				t.Fatalf("signature is %d bytes", len(sig))
			}
			if summary != testDeviceSummary {
				t.Fatalf("summary = %q, want %q", summary, testDeviceSummary)
			}
			versions, _, challenges := dev.seen()
			if !sameStrings(versions, []string{AttestedProtocolSummary}) || challenges != 1 {
				t.Fatalf("sign requests at %v with %d challenges, want one at version 2", versions, challenges)
			}
		})
	}
}

func TestAttestedVersion1ModeSendsVersion1(t *testing.T) {
	t.Parallel()
	dev, _, signer := newV2Backend(t, "supported", AttestedVersion1)
	_, summary, err := signer.SignTxBody(t.Context(), []byte{0xa0}, 6)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if summary != "" {
		t.Fatalf("version 1 reply summary = %q", summary)
	}
	if versions, _, _ := dev.seen(); !sameStrings(versions, []string{AttestedProtocol}) {
		t.Fatalf("sign requests at %v, want version 1 only", versions)
	}
}

func TestAttestedNegotiateFallsBackToVersion1(t *testing.T) {
	t.Parallel()
	dev, b, signer := newV2Backend(t, "v1only", AttestedNegotiate)
	sig, summary, err := signer.SignTxBody(t.Context(), []byte{0xa0}, 6)
	if err != nil {
		t.Fatalf("sign against version 1 firmware: %v", err)
	}
	if len(sig) != ed25519.SignatureSize || summary != "" {
		t.Fatalf("signature %d bytes, summary %q", len(sig), summary)
	}
	versions, nonces, challenges := dev.seen()
	if !sameStrings(versions, []string{AttestedProtocolSummary, AttestedProtocol}) {
		t.Fatalf("sign requests at %v, want version 2 then version 1", versions)
	}
	if challenges != 2 {
		t.Fatalf("challenges = %d, want a fresh one for the retry", challenges)
	}
	if bytes.Equal(nonces[0], nonces[1]) {
		t.Fatal("retry reused the nonce")
	}

	// the negotiated version is cached: the next request skips the failed probe
	if _, _, err := signer.SignTxBody(t.Context(), []byte{0xa0}, 6); err != nil {
		t.Fatalf("second sign: %v", err)
	}
	if versions, _, _ := dev.seen(); !sameStrings(versions, []string{AttestedProtocolSummary, AttestedProtocol, AttestedProtocol}) {
		t.Fatalf("sign requests at %v, want the second at version 1 only", versions)
	}

	// a reload re-probes
	if err := b.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	ref, err := b.GetKey(t.Context(), HashPublicKey(dev.pool.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ref.(TxBodySigner).SignTxBody(t.Context(), []byte{0xa0}, 6); err != nil {
		t.Fatalf("sign after reload: %v", err)
	}
	versions, _, _ = dev.seen()
	if len(versions) != 5 || versions[3] != AttestedProtocolSummary || versions[4] != AttestedProtocol {
		t.Fatalf("sign requests at %v, want a version 2 probe after reload", versions)
	}
}

func TestAttestedRequireVersion2RefusesFallback(t *testing.T) {
	t.Parallel()
	dev, _, signer := newV2Backend(t, "v1only", AttestedRequireVersion2)
	_, _, err := signer.SignTxBody(t.Context(), []byte{0xa0}, 6)
	if err == nil {
		t.Fatal("signed against version 1 firmware with version 2 required")
	}
	if !errors.Is(err, ErrAttestedProtocol) {
		t.Fatalf("error = %v, want ErrAttestedProtocol", err)
	}
	if versions, _, _ := dev.seen(); !sameStrings(versions, []string{AttestedProtocolSummary}) {
		t.Fatalf("sign requests at %v, want exactly one at version 2", versions)
	}
}

func TestAttestedRefusesReplyAtAnotherVersion(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		behavior string
		mode     AttestedProtocolMode
	}{
		"version 1 reply to negotiate": {"echoV1", AttestedNegotiate},
		"version 1 reply to require":   {"echoV1", AttestedRequireVersion2},
		"version 2 reply to version 1": {"echoV2", AttestedVersion1},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dev, _, signer := newV2Backend(t, tc.behavior, tc.mode)
			_, _, err := signer.SignTxBody(t.Context(), []byte{0xa0}, 6)
			if err == nil || !errors.Is(err, ErrAttestedProtocol) {
				t.Fatalf("error = %v, want ErrAttestedProtocol", err)
			}
			if versions, _, _ := dev.seen(); len(versions) != 1 {
				t.Fatalf("sign requests at %v, want one and no retry", versions)
			}
		})
	}
}

func TestAttestedNegotiateFallsBackOnlyOnUnsupportedVersion(t *testing.T) {
	t.Parallel()
	for _, behavior := range []string{"otherError", "forgedOK"} {
		t.Run(behavior, func(t *testing.T) {
			t.Parallel()
			dev, _, signer := newV2Backend(t, behavior, AttestedNegotiate)
			if _, _, err := signer.SignTxBody(t.Context(), []byte{0xa0}, 6); err == nil {
				t.Fatal("signed")
			}
			if versions, _, _ := dev.seen(); len(versions) != 1 {
				t.Fatalf("sign requests at %v, want no retry", versions)
			}
		})
	}
}

func TestAttestedRefusesTamperedSummary(t *testing.T) {
	t.Parallel()
	_, _, signer := newV2Backend(t, "tampered", AttestedNegotiate)
	_, summary, err := signer.SignTxBody(t.Context(), []byte{0xa0}, 6)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("error = %v, want ErrInvalidSignature", err)
	}
	if summary != "" {
		t.Fatalf("returned the unverified summary %q", summary)
	}
}

// A version-1 reply carrying a summary is refused even when the binding
// signature covers it: only a version-2 request may return one.
func TestAttestedRefusesSummaryOnVersion1Reply(t *testing.T) {
	t.Parallel()
	_, _, signer := newV2Backend(t, "v1Summary", AttestedVersion1)
	_, summary, err := signer.SignTxBody(t.Context(), []byte{0xa0}, 6)
	if !errors.Is(err, ErrAttestedProtocol) {
		t.Fatalf("error = %v, want ErrAttestedProtocol", err)
	}
	if summary != "" {
		t.Fatalf("returned summary %q from a version 1 reply", summary)
	}
}

// A failed round trip clears the cached version 1, so the next request probes
// version 2 again.
func TestAttestedNegotiateReprobesAfterFailedRoundTrip(t *testing.T) {
	t.Parallel()
	dev, _, signer := newV2Backend(t, "v1only", AttestedNegotiate)
	if _, _, err := signer.SignTxBody(t.Context(), []byte{0xa0}, 6); err != nil {
		t.Fatalf("sign: %v", err)
	}
	dev.mu.Lock()
	dev.failSign = true
	dev.mu.Unlock()
	if _, _, err := signer.SignTxBody(t.Context(), []byte{0xa0}, 6); err == nil {
		t.Fatal("signed through a failing device")
	}
	dev.mu.Lock()
	dev.failSign = false
	dev.mu.Unlock()
	if _, _, err := signer.SignTxBody(t.Context(), []byte{0xa0}, 6); err != nil {
		t.Fatalf("sign after recovery: %v", err)
	}
	want := []string{AttestedProtocolSummary, AttestedProtocol, AttestedProtocolSummary, AttestedProtocol}
	if versions, _, _ := dev.seen(); !sameStrings(versions, want) {
		t.Fatalf("sign requests at %v, want %v", versions, want)
	}
}

// The cached version is shared by every request on the backend; run with
// -race.
func TestAttestedVersionCacheConcurrent(t *testing.T) {
	t.Parallel()
	_, b, _ := newV2Backend(t, "supported", AttestedNegotiate)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				switch i % 4 {
				case 0:
					b.pinVersion1()
				case 1:
					b.unpinVersion()
				case 2:
					_ = b.requestVersion()
				default:
					if err := b.Load(t.Context()); err != nil {
						t.Error(err)
						return
					}
				}
			}
		}()
	}
	wg.Wait()
}

func TestClipSummary(t *testing.T) {
	t.Parallel()
	exact := strings.Repeat("a", attestedMaxSummary)
	if got := clipSummary(exact); got != exact {
		t.Fatalf("clipped a summary of exactly %d bytes", attestedMaxSummary)
	}
	// the cut falls inside the two-byte rune, which is dropped
	long := strings.Repeat("a", attestedMaxSummary-1) + "\u00e9" + "tail"
	want := strings.Repeat("a", attestedMaxSummary-1) + "..."
	if got := clipSummary(long); got != want {
		t.Fatalf("clipped to %d bytes ending %q, want %d bytes", len(got), got[len(got)-8:], len(want))
	}
}
