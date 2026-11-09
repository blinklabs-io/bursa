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

package kesagent

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/kesagent/securemem"
	"github.com/blinklabs-io/gouroboros/kes"
)

// ErrKeyAlreadyInstalled is returned by KeyStore.Install when the staged key
// was already installed, by another replica, with a different operational
// certificate. The installed record is left as it is.
var ErrKeyAlreadyInstalled = errors.New(
	"kesagent: the staged KES key was already installed with a different opcert",
)

// KeyStore is where agent replicas share each profile's KES key. A profile
// has at most one staged and one installed record, named by the pool's cold
// key hash and the network, exactly as the shared guard names its records.
// The signing key in a record is sealed with age; the store only holds it.
type KeyStore interface {
	// PutStaged replaces the profile's staged record with rec.
	PutStaged(ctx context.Context, pool, network string, rec SealedKey) error
	// Staged returns the profile's staged record and whether there is one.
	Staged(ctx context.Context, pool, network string) (SealedKey, bool, error)
	// Installed returns the profile's installed record and whether there is
	// one.
	Installed(ctx context.Context, pool, network string) (SealedKey, bool, error)
	// Install atomically moves the staged record whose KES verification key
	// is kesVKey to installed with opcert, replacing any installed record,
	// and returns the new record's generation. When that key is already
	// installed with the same opcert (a second replica installing the same
	// certificate) it returns the existing generation. It returns
	// ErrNoStagedKey when no key is staged, ErrOpCertKESVK when a different
	// key is staged, and ErrKeyAlreadyInstalled when kesVKey was installed
	// with a different opcert.
	Install(
		ctx context.Context,
		pool, network string,
		kesVKey, opcert []byte,
	) (uint64, error)
}

// SealedKey is one stored KES key: its verification key, the KES period
// (internal, 0-based) the signing key was at when it was sealed, and the
// sealed signing key. An installed record also carries its operational
// certificate and a generation that increases with every install.
type SealedKey struct {
	KESVKey      []byte
	Depth        uint64
	SealedPeriod uint64
	Sealed       []byte
	OpCert       []byte
	Generation   uint64
}

// sealedKeyMagic opens every sealed plaintext, naming its layout.
var sealedKeyMagic = []byte("bursa-kes-sealed-v1\x00")

// KeySealer seals KES signing keys with age to a set of recipients and opens
// them with a set of identities.
type KeySealer struct {
	recipients []age.Recipient
	identities []age.Identity
}

// NewKeySealer parses age recipients (age1... strings) and the identity file
// at identityFile. Both are required: the recipients seal staged keys, the
// identities open installed ones.
func NewKeySealer(recipients []string, identityFile string) (*KeySealer, error) {
	if len(recipients) == 0 {
		return nil, errors.New("kesagent: at least one age recipient is required")
	}
	if identityFile == "" {
		return nil, errors.New("kesagent: an age identity file is required")
	}
	rs, err := age.ParseRecipients(strings.NewReader(strings.Join(recipients, "\n")))
	if err != nil {
		return nil, fmt.Errorf("kesagent: parse age recipients: %w", err)
	}
	// Read as a secret key file: anyone who can read it can open the stored
	// keys, so group or other access is refused as for other key files.
	raw, err := bursa.ReadSecretKeyFile(identityFile)
	if err != nil {
		return nil, fmt.Errorf("kesagent: read age identity file: %w", err)
	}
	defer securemem.Wipe(raw)
	ids, err := age.ParseIdentities(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("kesagent: parse age identity file: %w", err)
	}
	return &KeySealer{recipients: rs, identities: ids}, nil
}

// seal encrypts a KES signing key at internal period period to the
// recipients. The plaintext names the key's depth, period and verification
// key, so unseal can refuse a sealed key presented as another.
func (s *KeySealer) seal(depth, period uint64, vkey, sk []byte) ([]byte, error) {
	plain := make([]byte, 0, len(sealedKeyMagic)+16+len(vkey)+len(sk))
	plain = append(plain, sealedKeyMagic...)
	plain = binary.BigEndian.AppendUint64(plain, depth)
	plain = binary.BigEndian.AppendUint64(plain, period)
	plain = append(plain, vkey...)
	plain = append(plain, sk...)
	defer securemem.Wipe(plain)
	var out bytes.Buffer
	w, err := age.Encrypt(&out, s.recipients...)
	if err != nil {
		return nil, fmt.Errorf("kesagent: seal KES key: %w", err)
	}
	if _, err := w.Write(plain); err != nil {
		return nil, fmt.Errorf("kesagent: seal KES key: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("kesagent: seal KES key: %w", err)
	}
	return out.Bytes(), nil
}

// unseal opens rec's sealed signing key into a locked buffer. It checks that
// the plaintext is the key rec names: same depth, period and verification
// key, and a signing key that derives that verification key. A sealed key
// none of the identities opens returns an error wrapping
// *age.NoIdentityMatchError.
//
// The returned buffer holds the only copy this function keeps; the heap
// copies it makes are wiped. age's own decryption buffers are not reachable
// from here and are left to the garbage collector.
func (s *KeySealer) unseal(rec SealedKey) (*securemem.Buffer, error) {
	skLen := kesSecretKeySize(rec.Depth)
	if skLen == 0 {
		return nil, fmt.Errorf("kesagent: sealed KES key has invalid depth %d", rec.Depth)
	}
	r, err := age.Decrypt(bytes.NewReader(rec.Sealed), s.identities...)
	if err != nil {
		return nil, fmt.Errorf("kesagent: unseal KES key: %w", err)
	}
	want := len(sealedKeyMagic) + 16 + len(rec.KESVKey) + skLen
	plain := make([]byte, want)
	defer securemem.Wipe(plain)
	if _, err := io.ReadFull(r, plain); err != nil {
		return nil, fmt.Errorf("kesagent: unseal KES key: %w", err)
	}
	var extra [1]byte
	if n, _ := r.Read(extra[:]); n != 0 {
		return nil, errors.New("kesagent: unseal KES key: sealed key is too long")
	}
	off := len(sealedKeyMagic)
	if !bytes.Equal(plain[:off], sealedKeyMagic) {
		return nil, errors.New("kesagent: unseal KES key: unknown sealed key format")
	}
	depth := binary.BigEndian.Uint64(plain[off:])
	period := binary.BigEndian.Uint64(plain[off+8:])
	off += 16
	vkey := plain[off : off+len(rec.KESVKey)]
	off += len(rec.KESVKey)
	sk := plain[off:]
	if depth != rec.Depth || period != rec.SealedPeriod ||
		!bytes.Equal(vkey, rec.KESVKey) {
		return nil, errors.New(
			"kesagent: unseal KES key: sealed key does not match its record",
		)
	}
	derived := kes.PublicKey(&kes.SecretKey{Depth: depth, Period: period, Data: sk})
	if subtle.ConstantTimeCompare(derived, rec.KESVKey) != 1 {
		return nil, errors.New(
			"kesagent: unseal KES key: signing key does not match its verification key",
		)
	}
	buf, err := securemem.New(len(sk))
	if err != nil {
		return nil, err
	}
	if err := buf.Set(sk); err != nil {
		_ = buf.Close()
		return nil, err
	}
	return buf, nil
}

// kesSecretKeySize is the length of a Sum-KES signing key of the given depth:
// the Ed25519 seed, plus a seed and two child verification keys per level. It
// is 0 for a depth the agent cannot generate.
func kesSecretKeySize(depth uint64) int {
	if depth > kes.MaxKeyGenDepth {
		return 0
	}
	return 32 + int(depth)*96 // #nosec G115 -- depth <= kes.MaxKeyGenDepth
}
