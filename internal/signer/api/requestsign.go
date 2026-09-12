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
	"encoding/binary"
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

// nonceCacheKeyBytes is the fixed size of the digest retained for each replay
// identity. Keeping only this digest avoids retaining attacker-controlled nonce
// bytes while the count and byte limits bound map metadata and key storage.
const nonceCacheKeyBytes = sha256.Size

// defaultNonceCacheMaxBytes bounds retained replay-key bytes independently of
// the entry count. It is derived from the fixed-width key so valid nonces of
// any size accepted by the HTTP server remain compatible.
const defaultNonceCacheMaxBytes = int64(defaultNonceCacheMax) * nonceCacheKeyBytes

// An Ed25519 signature is fixed-width and is represented as lower-case hex in
// the request header. Check that width before touching the request body.
const maxSignatureHexLength = ed25519.SignatureSize * 2

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
//
// Keys not of ed25519.PublicKeySize are dropped rather than stored: ed25519.Verify
// panics on a malformed key, and BuildAuthorizedKeys already validates length,
// but this constructor is exported, so a future or external caller passing a
// short key must not be able to turn an unauthenticated request into a panic.
func NewRequestSigningAuthenticator(keys map[string]ed25519.PublicKey, skew time.Duration) *RequestSigningAuthenticator {
	valid := make(map[string]ed25519.PublicKey, len(keys))
	for caller, pub := range keys {
		if len(pub) == ed25519.PublicKeySize {
			valid[caller] = pub
		}
	}
	if skew <= 0 {
		skew = 60 * time.Second
	}
	return &RequestSigningAuthenticator{
		keys:    valid,
		skew:    skew,
		cache:   newNonceCacheWithByteLimit(2*skew, defaultNonceCacheMax, defaultNonceCacheMaxBytes),
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
	// Reject malformed credentials before reading a potentially slow body;
	// valid requests still hash and verify the exact body before the replay cache
	// is changed.
	if len(sig) != maxSignatureHexLength {
		return "", true, errInvalidSignature
	}
	sigBytes, err := hex.DecodeString(sig)
	if err != nil {
		return "", true, errInvalidSignature
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
	if !ed25519.Verify(pub, []byte(canonical), sigBytes) {
		return "", true, errInvalidSignature
	}
	// Replay check runs only after the signature verifies, so unauthenticated
	// requests cannot flood the nonce cache.
	if err := a.cache.checkAndStore(caller, nonce); err != nil {
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
// replay protection. It is safe for concurrent use. The map retains only a
// fixed-width digest of each identifier; the original caller and nonce are
// never retained after checkAndStore returns.
type nonceCache struct {
	mu       sync.Mutex
	entries  map[[nonceCacheKeyBytes]byte]int64 // digest -> expiry (unix nanos)
	ttl      time.Duration
	max      int
	bytes    int64
	maxBytes int64
	now      func() time.Time
}

func newNonceCache(ttl time.Duration, max int) *nonceCache {
	return newNonceCacheWithByteLimit(ttl, max, int64(max)*nonceCacheKeyBytes)
}

func newNonceCacheWithByteLimit(ttl time.Duration, max int, maxBytes int64) *nonceCache {
	return &nonceCache{
		entries:  make(map[[nonceCacheKeyBytes]byte]int64),
		ttl:      ttl,
		max:      max,
		maxBytes: maxBytes,
		now:      time.Now,
	}
}

// checkAndStore records (caller, nonce) and returns nil, errReplay if the pair
// is already present and unexpired, or errNonceCacheFull if the cache is at
// either capacity (fail closed: replay protection cannot be guaranteed, so the
// request is refused). Expired entries are purged lazily — only when the cache
// is at or over capacity — rather than scanning every live entry on every call:
// a full O(n) sweep under the single cache-wide mutex on every request would
// serialize all request-signing traffic and grow with cache occupancy. The
// count and byte bounds remain memory-safe because each retained key is exactly
// 32 bytes.
func (c *nonceCache) checkAndStore(caller, nonce string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().UnixNano()
	key := nonceCacheKey(caller, nonce)
	if exp, ok := c.entries[key]; ok {
		if exp > now {
			return errReplay
		}
		delete(c.entries, key)
		c.bytes -= nonceCacheKeyBytes
	}
	if len(c.entries) >= c.max || c.bytes+nonceCacheKeyBytes > c.maxBytes {
		for k, exp := range c.entries {
			if exp <= now {
				delete(c.entries, k)
				c.bytes -= nonceCacheKeyBytes
			}
		}
	}
	if len(c.entries) >= c.max || c.bytes+nonceCacheKeyBytes > c.maxBytes {
		return errNonceCacheFull
	}
	c.entries[key] = c.now().Add(c.ttl).UnixNano()
	c.bytes += nonceCacheKeyBytes
	return nil
}

// nonceCacheKey hashes length-delimited caller and nonce fields. Length
// prefixes preserve the pair boundary without allocating a concatenated string
// proportional to an attacker-controlled nonce.
func nonceCacheKey(caller, nonce string) [nonceCacheKeyBytes]byte {
	h := sha256.New()
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(caller)))
	_, _ = h.Write(length[:])
	_, _ = io.WriteString(h, caller)
	binary.BigEndian.PutUint64(length[:], uint64(len(nonce)))
	_, _ = h.Write(length[:])
	_, _ = io.WriteString(h, nonce)
	var key [nonceCacheKeyBytes]byte
	copy(key[:], h.Sum(nil))
	return key
}
