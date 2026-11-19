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

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/signer"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/confidentialspace"
	"github.com/spf13/cobra"
)

const (
	importSigningKeyType = "StakePoolSigningKey_ed25519"
	importVKeyType       = "StakePoolVerificationKey_ed25519"
	importTimeout        = 2 * time.Minute
)

// serveConfidentialSpaceImport runs the workload in import mode: it serves the
// two import routes until one import has been written, then exits.
func serveConfidentialSpaceImport(
	ctx context.Context,
	listenAddress string,
	tlsConfig *tls.Config,
	authorityFile string,
	cfg confidentialspace.ImportConfig,
) error {
	authority, err := readFixedHexFile(
		authorityFile,
		"import authority public key",
		ed25519.PublicKeySize,
	)
	if err != nil {
		return err
	}
	cfg.Authority = authority
	importer, err := confidentialspace.NewImporter(cfg)
	if err != nil {
		return err
	}
	defer importer.Close()
	slog.Info("confidential space import mode: waiting for one import")
	if err := serveConfidentialSpace(
		ctx,
		listenAddress,
		importer.Handler(),
		tlsConfig,
		importer.Done(),
	); err != nil {
		return err
	}
	select {
	case <-importer.Done():
		slog.Info("confidential space import finished")
		return nil
	default:
		return errors.New("import mode stopped before an import finished")
	}
}

func confidentialSpaceClientCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "confidential-space",
		Short: "Operate a GCP Confidential Space custody workload",
	}
	cmd.AddCommand(confidentialSpaceImportCommand())
	return cmd
}

type confidentialSpaceImportOptions struct {
	address, caFile, certFile, keyFile     string
	audience, imageDigest, jwksURL, kmsKey string
	authorityFile                          string
	signingKeyFile, vkeyFile               []string
	profiles                               []string
}

func confidentialSpaceImportCommand() *cobra.Command {
	var o confidentialSpaceImportOptions
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import an existing pool cold key into an import-mode workload",
		Long: `Import one existing pool cold key into a confidential-space-workload started
with --import against an empty --state-secret.

Run this on the machine that holds the cold key. It requests an attestation
token from the workload and verifies it locally (Google's signature, the
audience, the image digest, the production and debug claims, and that the token
vouches for the workload's one-use channel key), seals the key to that channel,
has the provisioning authority sign the binding and the ciphertext, and sends
it. The workload checks that the key derives --vkey-file before it wraps it.

--signing-key-file is the non-extended StakePoolSigningKey_ed25519 file, as
cardano-cli and 'bursa key pool-cold' write it. --vkey-file is the pool's
registered StakePoolVerificationKey_ed25519 file, an input independent of the
signing key. A plain path is the one key every --profile shares. To give each
profile its own pool key, pass NAME=FILE for every --profile, in both flags,
each under a distinct key; a value is NAME=FILE when the text before its first
"=" is a valid profile name, so write a path that contains "=" as ./PATH. --authority-key-file is a hex Ed25519 seed (or 64-byte private
key) whose public key the workload was started with in --import-authority-file;
it must not be the TLS client identity.

Each --profile is NAME=NEXT, where NEXT is the next operational-certificate
issue number the profile may sign: one above the highest issue number the key
has signed, on chain or not, and never below the pool's on-chain counter plus
one; 0 for a pool that has never issued. Stop the old signer issuing first.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runConfidentialSpaceImportCommand(cmd.Context(), o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.address, "address", "", "https address of the import-mode workload")
	f.StringVar(&o.caFile, "tls-ca-file", "", "PEM CA that issued the workload certificate")
	f.StringVar(&o.certFile, "tls-client-cert-file", "", "PEM client certificate accepted by the workload")
	f.StringVar(&o.keyFile, "tls-client-key-file", "", "PEM private key of --tls-client-cert-file")
	f.StringVar(&o.audience, "audience", "", "audience the attestation token must carry")
	f.StringVar(&o.imageDigest, "image-digest", "", "required workload container image digest, sha256:...")
	f.StringVar(&o.jwksURL, "jwks-url", "", "attestation signing keys (default: Google's published set)")
	f.StringVar(&o.kmsKey, "kms-key", "", "Cloud KMS CryptoKey the workload wraps the key with")
	f.StringArrayVar(&o.signingKeyFile, "signing-key-file", nil, "StakePoolSigningKey_ed25519 file of the pool cold key, or NAME=FILE for the key of profile NAME (repeatable, one for every --profile)")
	f.StringArrayVar(&o.vkeyFile, "vkey-file", nil, "StakePoolVerificationKey_ed25519 file of the registered pool cold key, or NAME=FILE for the key of profile NAME")
	f.StringVar(&o.authorityFile, "authority-key-file", "", "hex Ed25519 signing key of the provisioning authority")
	f.StringArrayVar(&o.profiles, "profile", nil, "profile to serve and its next issue number, NAME=NEXT, repeatable")
	for _, name := range []string{
		"address", "tls-ca-file", "tls-client-cert-file", "tls-client-key-file",
		"audience", "image-digest", "kms-key", "signing-key-file",
		"vkey-file", "authority-key-file", "profile",
	} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

func runConfidentialSpaceImportCommand(
	ctx context.Context,
	o confidentialSpaceImportOptions,
) error {
	profiles, err := parseImportProfiles(o.profiles)
	if err != nil {
		return err
	}
	keys, err := loadImportKeys(o.signingKeyFile, o.vkeyFile, profiles)
	if err != nil {
		return err
	}
	defer keys.wipe()
	authority, err := readImportAuthorityKey(o.authorityFile)
	if err != nil {
		return err
	}
	defer clear(authority)
	client, err := confidentialspace.NewImportClient(
		o.address, o.caFile, o.certFile, o.keyFile,
		authority.Public().(ed25519.PublicKey),
	)
	if err != nil {
		return err
	}
	verifier, err := signer.NewConfidentialSpaceVerifier(
		o.jwksURL, o.audience, o.imageDigest,
	)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, importTimeout)
	defer cancel()
	if err := runConfidentialSpaceImport(
		ctx, client, verifier, keys.params(o.kmsKey, profiles, authority),
	); err != nil {
		return err
	}
	if keys.byProfile == nil {
		fmt.Printf("imported pool cold key %x\n", keys.vkey)
		return nil
	}
	for _, p := range profiles {
		fmt.Printf(
			"imported pool cold key %x for profile %s\n",
			keys.byProfile[p.Profile].VKey, p.Profile,
		)
	}
	return nil
}

// importTransport is the workload's side of the import.
type importTransport interface {
	Challenge(context.Context) (confidentialspace.ImportChallenge, error)
	Import(context.Context, confidentialspace.ImportRequest) error
}

// runConfidentialSpaceImport requests a challenge, verifies it, seals and
// authorizes the key, and sends it.
func runConfidentialSpaceImport(
	ctx context.Context,
	transport importTransport,
	verifier backend.AttestationVerifier,
	params confidentialspace.ImportParams,
) error {
	ch, err := transport.Challenge(ctx)
	if err != nil {
		return fmt.Errorf("request import challenge: %w", err)
	}
	req, err := confidentialspace.BuildImportRequest(
		ctx, verifier, ch, params,
	)
	if err != nil {
		return fmt.Errorf("build import request: %w", err)
	}
	if err := transport.Import(ctx, req); err != nil {
		return fmt.Errorf("import: %w", err)
	}
	return nil
}

// parseImportProfiles reads NAME=NEXT entries.
func parseImportProfiles(
	values []string,
) ([]confidentialspace.ImportProfile, error) {
	out := make([]confidentialspace.ImportProfile, 0, len(values))
	for _, value := range values {
		name, next, ok := strings.Cut(value, "=")
		if !ok {
			return nil, fmt.Errorf("--profile %q must be NAME=NEXT", value)
		}
		if err := confidentialspace.ValidateProfile(name); err != nil {
			return nil, err
		}
		n, err := strconv.ParseUint(next, 10, 64)
		if err != nil {
			return nil, fmt.Errorf(
				"--profile %q: next issue number must be an unsigned integer",
				value,
			)
		}
		for _, seen := range out {
			if seen.Profile == name {
				return nil, fmt.Errorf("duplicate --profile %q", name)
			}
		}
		out = append(out, confidentialspace.ImportProfile{
			Profile: name, NextIssueNumber: n,
		})
	}
	return out, nil
}

// importKeys is the pool cold key material of one import: one key shared by
// every profile, or one key per profile.
type importKeys struct {
	seed, vkey []byte
	byProfile  map[string]confidentialspace.ImportKey
}

func (k importKeys) wipe() {
	clear(k.seed)
	for _, key := range k.byProfile {
		clear(key.Seed)
	}
}

func (k importKeys) params(
	kmsKey string,
	profiles []confidentialspace.ImportProfile,
	authority ed25519.PrivateKey,
) confidentialspace.ImportParams {
	return confidentialspace.ImportParams{
		KMSKey:    kmsKey,
		Seed:      k.seed,
		VKey:      k.vkey,
		Keys:      k.byProfile,
		Profiles:  profiles,
		Authority: authority,
	}
}

// splitProfileFile reads a --signing-key-file or --vkey-file value: NAME=FILE
// when the text before the first "=" is a valid profile name, which no path
// with a directory part is, and a plain path otherwise.
func splitProfileFile(value string) (profile, path string, qualified bool) {
	name, rest, ok := strings.Cut(value, "=")
	if ok && confidentialspace.ValidateProfile(name) == nil {
		return name, rest, true
	}
	return "", value, false
}

// profileFiles maps each profile to its file, for NAME=FILE values.
func profileFiles(flag string, values []string) (map[string]string, error) {
	files := make(map[string]string, len(values))
	for _, value := range values {
		name, path, _ := splitProfileFile(value)
		if path == "" {
			return nil, fmt.Errorf("%s %q names no file", flag, value)
		}
		if _, dup := files[name]; dup {
			return nil, fmt.Errorf("duplicate %s for profile %q", flag, name)
		}
		files[name] = path
	}
	return files, nil
}

// loadImportKeys reads the key material the import seals. Plain paths are the
// one key every profile shares. NAME=FILE values give each profile its own
// key, and must name exactly the --profile profiles, each under a distinct
// key; the two forms are not mixed.
func loadImportKeys(
	signingKeyFiles, vkeyFiles []string,
	profiles []confidentialspace.ImportProfile,
) (importKeys, error) {
	qualified := 0
	for _, value := range slices.Concat(signingKeyFiles, vkeyFiles) {
		if _, _, ok := splitProfileFile(value); ok {
			qualified++
		}
	}
	switch {
	case qualified == 0:
		if len(signingKeyFiles) != 1 || len(vkeyFiles) != 1 {
			return importKeys{}, errors.New(
				"give one --signing-key-file and one --vkey-file, " +
					"or one NAME=FILE of each for every --profile",
			)
		}
		seed, vkey, err := loadImportColdKey(signingKeyFiles[0], vkeyFiles[0])
		if err != nil {
			return importKeys{}, err
		}
		return importKeys{seed: seed, vkey: vkey}, nil
	case qualified != len(signingKeyFiles)+len(vkeyFiles):
		return importKeys{}, errors.New(
			"--signing-key-file and --vkey-file are either plain paths " +
				"or all NAME=FILE, not both",
		)
	}
	signing, err := profileFiles("--signing-key-file", signingKeyFiles)
	if err != nil {
		return importKeys{}, err
	}
	verification, err := profileFiles("--vkey-file", vkeyFiles)
	if err != nil {
		return importKeys{}, err
	}
	if len(signing) != len(profiles) || len(verification) != len(profiles) {
		return importKeys{}, errors.New(
			"--signing-key-file and --vkey-file must name each --profile once",
		)
	}
	keys := importKeys{byProfile: make(
		map[string]confidentialspace.ImportKey, len(profiles),
	)}
	for _, p := range profiles {
		skFile, okSK := signing[p.Profile]
		vkFile, okVK := verification[p.Profile]
		if !okSK || !okVK {
			keys.wipe()
			return importKeys{}, fmt.Errorf(
				"profile %q needs a --signing-key-file and a --vkey-file",
				p.Profile,
			)
		}
		seed, vkey, err := loadImportColdKey(skFile, vkFile)
		if err != nil {
			keys.wipe()
			return importKeys{}, fmt.Errorf("profile %q: %w", p.Profile, err)
		}
		for _, other := range keys.byProfile {
			if bytes.Equal(other.VKey, vkey) {
				clear(seed)
				keys.wipe()
				return importKeys{}, fmt.Errorf(
					"profile %q has the same key as another profile; "+
						"give a plain --signing-key-file to share one key",
					p.Profile,
				)
			}
		}
		keys.byProfile[p.Profile] = confidentialspace.ImportKey{
			Seed: seed, VKey: vkey,
		}
	}
	return keys, nil
}

// loadImportColdKey reads the pool cold key's Ed25519 seed and the pool's
// registered verification key, and requires the seed to derive it. Only the
// non-extended signing key is accepted: its 32 bytes are the seed the
// workload signs with, which an extended key's scalar is not.
func loadImportColdKey(
	signingKeyFile, vkeyFile string,
) (seed, vkey []byte, err error) {
	sk, err := bursa.LoadSecretKeyFromFile(signingKeyFile)
	if err != nil {
		return nil, nil, err
	}
	defer clear(sk.SKey)
	if sk.Type != importSigningKeyType ||
		len(sk.SKey) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf(
			"--signing-key-file must be a non-extended %s file, got %q",
			importSigningKeyType, sk.Type,
		)
	}
	vk, err := bursa.LoadKeyFromFile(vkeyFile)
	if err != nil {
		return nil, nil, err
	}
	if vk.Type != importVKeyType || len(vk.VKey) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf(
			"--vkey-file must be a %s file, got %q", importVKeyType, vk.Type,
		)
	}
	seed = bytes.Clone(sk.SKey[:ed25519.SeedSize])
	priv := ed25519.NewKeyFromSeed(seed)
	derived := priv.Public().(ed25519.PublicKey)
	clear(priv)
	if !bytes.Equal(derived, vk.VKey) {
		clear(seed)
		return nil, nil, errors.New(
			"--signing-key-file does not derive the key in --vkey-file",
		)
	}
	return seed, bytes.Clone(vk.VKey), nil
}

// readImportAuthorityKey reads the provisioning authority's Ed25519 key as hex:
// a 32-byte seed or a 64-byte private key.
func readImportAuthorityKey(path string) (ed25519.PrivateKey, error) {
	raw, err := bursa.ReadSecretKeyFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, errors.New("--authority-key-file must hold hex")
	}
	defer clear(decoded)
	switch len(decoded) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), nil
	case ed25519.PrivateKeySize:
		key := ed25519.NewKeyFromSeed(decoded[:ed25519.SeedSize])
		if !bytes.Equal(key, decoded) {
			clear(key)
			return nil, errors.New(
				"--authority-key-file private key does not match its seed",
			)
		}
		return key, nil
	default:
		return nil, fmt.Errorf(
			"--authority-key-file must hold %d or %d bytes, got %d",
			ed25519.SeedSize, ed25519.PrivateKeySize, len(decoded),
		)
	}
}
