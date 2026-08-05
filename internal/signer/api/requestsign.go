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

package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Authorized-keys request-signing headers.
//
// The client signs the canonical string
//
//	METHOD | PATH | HEX(SHA-256(body)) | TIMESTAMP | NONCE
//
// (fields joined by the literal byte '|') with its Ed25519 private key, where:
//
//	METHOD    the HTTP request method, e.g. "POST" (as sent, upper-case)
//	PATH      the request URL path, e.g. "/v1/sign" (no query string)
//	SHA-256   lower-case hex of the SHA-256 digest of the exact request body
//	          (hex of the digest of the empty body for GET requests)
//	TIMESTAMP X-Bursa-Timestamp verbatim: Unix seconds as a decimal string
//	NONCE     X-Bursa-Nonce verbatim: a client-unique value per request
//
// and sends the headers:
//
//	X-Bursa-Key        caller identity naming a configured authorized key
//	X-Bursa-Signature  lower-case hex of the 64-byte Ed25519 signature
//	X-Bursa-Timestamp  the TIMESTAMP above
//	X-Bursa-Nonce      the NONCE above
//
// The server rebuilds the canonical string from the received method, path and
// body, verifies the signature against the public key registered for
// X-Bursa-Key, enforces the timestamp window and rejects reused (key,nonce)
// pairs. The caller fed to the ACL is X-Bursa-Key.
const (
	HeaderSignature = "X-Bursa-Signature"
	HeaderTimestamp = "X-Bursa-Timestamp"
	HeaderNonce     = "X-Bursa-Nonce"
	HeaderKey       = "X-Bursa-Key"
)

// defaultNonceCacheMax bounds the in-memory replay cache. Entries expire after
// twice the timestamp skew, so under the accepted window at most this many
// distinct nonces can be live before boot-time capacity pressure.
const defaultNonceCacheMax = 65536

// maxSignedBody caps how many body bytes the authenticator will buffer to hash.
// It matches the handler's own 1 MiB request-body limit.
const maxSignedBody = 1 << 20

// RequestSigningAuthenticator verifies authorized-keys request signatures and
// enforces replay protection (timestamp window + nonce cache). See the header
// documentation above for the exact canonical scheme.
type RequestSigningAuthenticator struct {
	keys    map[string]ed25519.PublicKey // caller -> public key
	skew    time.Duration
	cache   *nonceCache
	now     func() time.Time
	maxBody int64
}

// NewRequestSigningAuthenticator builds the authenticator from caller -> public
// key registrations and a timestamp skew (± window). A non-positive skew uses
// the 60s default. The nonce cache TTL is twice the skew (covering both ends of
// the window).
func NewRequestSigningAuthenticator(keys map[string]ed25519.PublicKey, skew time.Duration) *RequestSigningAuthenticator {
	if skew <= 0 {
		skew = 60 * time.Second
	}
	return &RequestSigningAuthenticator{
		keys:    keys,
		skew:    skew,
		cache:   newNonceCache(2*skew, defaultNonceCacheMax),
		now:     time.Now,
		maxBody: maxSignedBody,
	}
}

func (a *RequestSigningAuthenticator) Authenticate(r *http.Request) (string, bool, error) {
	if r == nil || r.Header == nil || r.URL == nil {
		return "", true, errNilRequest
	}
	sig := r.Header.Get(HeaderSignature)
	if sig == "" {
		return "", false, nil // no request-signing credential presented
	}
	caller := r.Header.Get(HeaderKey)
	tsStr := r.Header.Get(HeaderTimestamp)
	nonce := r.Header.Get(HeaderNonce)
	if caller == "" || tsStr == "" || nonce == "" {
		return "", true, errInvalidSignature
	}
	pub, ok := a.keys[caller]
	if !ok {
		return "", true, errUnknownKey
	}
	// Timestamp window (cheap; reject before touching the body).
	tsSec, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return "", true, errInvalidSignature
	}
	if d := a.now().Sub(time.Unix(tsSec, 0)); d > a.skew || d < -a.skew {
		return "", true, errStaleTimestamp
	}
	// Buffer the body so the handler can still read it, then hash it.
	body, err := a.readBody(r)
	if err != nil {
		return "", true, err
	}
	bodyHash := sha256.Sum256(body)
	canonical := strings.Join([]string{
		r.Method,
		r.URL.Path,
		hex.EncodeToString(bodyHash[:]),
		tsStr,
		nonce,
	}, "|")
	sigBytes, err := hex.DecodeString(sig)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return "", true, errInvalidSignature
	}
	if !ed25519.Verify(pub, []byte(canonical), sigBytes) {
		return "", true, errInvalidSignature
	}
	// Replay check runs only after the signature verifies, so unauthenticated
	// requests cannot flood the nonce cache.
	if err := a.cache.checkAndStore(caller + "\x00" + nonce); err != nil {
		return "", true, err
	}
	return caller, true, nil
}

// readBody buffers up to maxBody+1 bytes, rejecting oversized bodies, and
// resets r.Body so downstream handlers read the same bytes.
func (a *RequestSigningAuthenticator) readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, a.maxBody+1))
	if err != nil {
		return nil, errInvalidSignature
	}
	if int64(len(body)) > a.maxBody {
		return nil, errBodyTooLarge
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

// nonceCache is a bounded, TTL-expiring set of seen (key,nonce) identifiers for
// replay protection. It is safe for concurrent use.
type nonceCache struct {
	mu      sync.Mutex
	entries map[string]int64 // identifier -> expiry (unix nanos)
	ttl     time.Duration
	max     int
	now     func() time.Time
}

func newNonceCache(ttl time.Duration, max int) *nonceCache {
	return &nonceCache{
		entries: make(map[string]int64),
		ttl:     ttl,
		max:     max,
		now:     time.Now,
	}
}

// checkAndStore records id and returns nil, errReplay if id is already present
// and unexpired, or errNonceCacheFull if the cache is at capacity (fail closed:
// replay protection cannot be guaranteed, so the request is refused). Expired
// entries are purged on every call, bounding memory to the accepted window.
func (c *nonceCache) checkAndStore(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().UnixNano()
	for k, exp := range c.entries {
		if exp <= now {
			delete(c.entries, k)
		}
	}
	if exp, ok := c.entries[id]; ok && exp > now {
		return errReplay
	}
	if len(c.entries) >= c.max {
		return errNonceCacheFull
	}
	c.entries[id] = c.now().Add(c.ttl).UnixNano()
	return nil
}
