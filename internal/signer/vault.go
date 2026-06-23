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

package signer

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	vaultapi "github.com/hashicorp/vault/api"
)

// buildVaultBackend wires a backend.VaultBackend over Vault's Transit engine.
// Transit signs Ed25519 natively over the raw input (PureEdDSA, no prehash),
// which is exactly what Cardano vkey witnesses require. Standard keys only;
// extended (BIP32-Ed25519) keys cannot live in Vault (design §2).
//
// The registered public key is the key's latest version at boot. If the
// Transit key is rotated, signatures from the new version will fail the
// coordinator's verify step until the signer is restarted.
func buildVaultBackend(ctx context.Context, c config.SignerBackendConfig) (*backend.VaultBackend, error) {
	if c.Address == "" {
		return nil, errors.New("vault backend requires address")
	}
	u, err := url.Parse(c.Address)
	if err != nil {
		return nil, fmt.Errorf("invalid vault address: %w", err)
	}
	if u.Scheme != "https" && !backend.IsLoopbackHost(u.Hostname()) {
		return nil, errors.New("vault address must use https; plain http is allowed only for loopback addresses (the token would travel in cleartext)")
	}
	if len(c.Keys) == 0 {
		return nil, errors.New("vault backend requires an explicit keys list (name + type per transit key)")
	}
	// Validate key types before any network I/O so config errors surface fast.
	for _, k := range c.Keys {
		if !backend.KeyType(k.Type).Valid() {
			return nil, fmt.Errorf("vault key %q: invalid key type %q", k.Name, k.Type)
		}
	}
	mount := c.TransitMount
	if mount == "" {
		mount = "transit"
	}
	tokenEnv := c.TokenEnv
	if tokenEnv == "" {
		tokenEnv = "VAULT_TOKEN"
	}
	token := os.Getenv(tokenEnv)
	if token == "" {
		return nil, fmt.Errorf("vault token env var %s is empty", tokenEnv)
	}
	vcfg := vaultapi.DefaultConfig()
	vcfg.Address = c.Address
	client, err := vaultapi.NewClient(vcfg)
	if err != nil {
		return nil, fmt.Errorf("vault client: %w", err)
	}
	client.SetToken(token)
	logical := client.Logical()

	sign := func(ctx context.Context, keyName string, digest []byte) (string, error) {
		resp, err := logical.WriteWithContext(ctx, mount+"/sign/"+keyName, map[string]any{
			"input": base64.StdEncoding.EncodeToString(digest),
		})
		if err != nil {
			return "", err
		}
		if resp == nil {
			return "", errors.New("empty transit sign response")
		}
		sig, ok := resp.Data["signature"].(string)
		if !ok {
			return "", errors.New("transit sign response missing signature")
		}
		return sig, nil
	}

	b := backend.NewVaultBackend(c.Name, sign)
	// Bound each boot-time key read independently so an unreachable Vault fails
	// fast, while a config with many keys is not starved by a single shared
	// deadline: each read gets the full timeout rather than racing all keys
	// against one 30s budget.
	for _, k := range c.Keys {
		pub, err := func() ([]byte, error) {
			keyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			return vaultTransitPublicKey(keyCtx, logical, mount, k.Name)
		}()
		if err != nil {
			return nil, fmt.Errorf("vault key %q: %w", k.Name, err)
		}
		if _, err := b.AddKey(k.Name, pub, backend.KeyType(k.Type)); err != nil {
			return nil, fmt.Errorf("vault key %q: %w", k.Name, err)
		}
	}
	return b, nil
}

// vaultTransitPublicKey reads a Transit key and returns the 32-byte Ed25519
// public key of its latest version.
func vaultTransitPublicKey(ctx context.Context, logical *vaultapi.Logical, mount, name string) ([]byte, error) {
	resp, err := logical.ReadWithContext(ctx, mount+"/keys/"+name)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("transit key not found")
	}
	if t, _ := resp.Data["type"].(string); t != "ed25519" {
		return nil, fmt.Errorf("transit key type %q is not ed25519", resp.Data["type"])
	}
	version, err := transitLatestVersion(resp.Data)
	if err != nil {
		return nil, err
	}
	keys, ok := resp.Data["keys"].(map[string]any)
	if !ok {
		return nil, errors.New("transit key response missing keys map")
	}
	entry, ok := keys[version].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("transit key has no version %s entry", version)
	}
	pubB64, ok := entry["public_key"].(string)
	if !ok {
		return nil, errors.New("transit key version missing public_key")
	}
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected %d-byte public key, got %d", ed25519.PublicKeySize, len(pub))
	}
	return pub, nil
}

// transitLatestVersion extracts latest_version from a Transit key read, which
// the Vault client may decode as json.Number or float64.
func transitLatestVersion(data map[string]any) (string, error) {
	switch v := data["latest_version"].(type) {
	case json.Number:
		return v.String(), nil
	case float64:
		return strconv.FormatInt(int64(v), 10), nil
	case string:
		return v, nil
	default:
		return "", fmt.Errorf("unexpected latest_version type %T", data["latest_version"])
	}
}
