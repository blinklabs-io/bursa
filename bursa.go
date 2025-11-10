// Copyright 2025 Blink Labs Software
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

package bursa

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/blinklabs-io/bursa/bip32"
	"github.com/blinklabs-io/bursa/internal/config"
	ouroboros "github.com/blinklabs-io/gouroboros"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/fxamacker/cbor/v2"
	bip39 "github.com/tyler-smith/go-bip39"
)

type KeyFile struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	CborHex     string `json:"cborHex"`
}

type LoadedKey struct {
	File        string
	Type        string
	Description string
	RawCBOR     []byte
	VKey        []byte
	SKey        []byte
}

type Wallet struct {
	Mnemonic            string  `json:"mnemonic"`
	PaymentAddress      string  `json:"payment_address"`
	StakeAddress        string  `json:"stake_address"`
	PaymentVKey         KeyFile `json:"payment_vkey"`
	PaymentSKey         KeyFile `json:"payment_skey"`
	PaymentExtendedSKey KeyFile `json:"payment_extended_skey"`
	StakeVKey           KeyFile `json:"stake_vkey"`
	StakeSKey           KeyFile `json:"stake_skey"`
	StakeExtendedSKey   KeyFile `json:"stake_extended_skey"`
}

func NewWallet(
	mnemonic, network, password string,
	accountId uint,
	paymentId, stakeId, addressId uint32,
) (*Wallet, error) {
	rootKey, err := GetRootKeyFromMnemonic(mnemonic, password)
	if err != nil {
		return nil, fmt.Errorf("failed to get root key from mnemonic: %w", err)
	}
	accountKey := GetAccountKey(rootKey, accountId)
	paymentKey := GetPaymentKey(accountKey, paymentId)
	stakeKey := GetStakeKey(accountKey, stakeId)
	addr, err := GetAddress(accountKey, network, addressId)
	if err != nil {
		return nil, fmt.Errorf("unable to get address: %w", err)
	}
	if addr == nil {
		return nil, errors.New("unable to get address")
	}
	stakeAddr := addr.StakeAddress()
	if stakeAddr == nil {
		return nil, errors.New("unable to get stake address")
	}
	w := &Wallet{
		Mnemonic:            mnemonic,
		PaymentAddress:      addr.String(),
		StakeAddress:        stakeAddr.String(),
		PaymentVKey:         GetPaymentVKey(paymentKey),
		PaymentSKey:         GetPaymentSKey(paymentKey),
		PaymentExtendedSKey: GetPaymentExtendedSKey(paymentKey),
		StakeVKey:           GetStakeVKey(stakeKey),
		StakeSKey:           GetStakeSKey(stakeKey),
		StakeExtendedSKey:   GetStakeExtendedSKey(stakeKey),
	}
	return w, nil
}

func ExtractKeyFiles(wallet *Wallet) (map[string]string, error) {
	keyMap := map[string]KeyFile{
		"payment.vkey":         wallet.PaymentVKey,
		"payment.skey":         wallet.PaymentSKey,
		"paymentExtended.skey": wallet.PaymentExtendedSKey,
		"stake.vkey":           wallet.StakeVKey,
		"stake.skey":           wallet.StakeSKey,
		"stakeExtended.skey":   wallet.StakeExtendedSKey,
	}

	result := make(map[string]string)
	for name, kf := range keyMap {
		keyStr, err := GetKeyFile(kf)
		if err != nil {
			return nil, fmt.Errorf("unable to get %s: %w", name, err)
		}
		result[name] = keyStr
	}
	return result, nil
}

func NewDefaultWallet(mnemonic string) (*Wallet, error) {
	cfg := config.GetConfig()
	w, err := NewWallet(mnemonic, cfg.Network, "", 0, 0, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create default wallet: %w", err)
	}
	return w, nil
}

func NewMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", err
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", err
	}
	return mnemonic, nil
}

func GetRootKeyFromMnemonic(mnemonic, password string) (bip32.XPrv, error) {
	entropy, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}
	pwBytes := []byte{}
	if password != "" {
		pwBytes = []byte(password)
	}
	rootKey := GetRootKey(entropy, pwBytes)
	return rootKey, nil
}

func GetRootKey(entropy []byte, password []byte) bip32.XPrv {
	return bip32.FromBip39Entropy(entropy, password)
}

func GetAccountKey(rootKey bip32.XPrv, num uint) bip32.XPrv {
	const harden = 0x80000000
	hardNum := harden + num
	if hardNum > math.MaxUint32 {
		panic("num out of bounds")
	}
	return rootKey.
		Derive(uint32(harden + 1852)).
		Derive(uint32(harden + 1815)).
		Derive(uint32(hardNum))
}

func GetPaymentKey(accountKey bip32.XPrv, num uint32) bip32.XPrv {
	return accountKey.Derive(0).Derive(num)
}

func GetPaymentVKey(paymentKey bip32.XPrv) KeyFile {
	keyCbor, err := cbor.Marshal(paymentKey.Public().PublicKey())
	if err != nil {
		panic(err)
	}
	return KeyFile{
		Type:        "PaymentVerificationKeyShelley_ed25519",
		Description: "Payment Verification Key",
		CborHex:     hex.EncodeToString(keyCbor),
	}
}

func getSigningKeyFile(key bip32.XPrv, keyType, description string) KeyFile {
	keyCbor, err := cbor.Marshal(key.PrivateKey()[:32])
	if err != nil {
		panic(err)
	}
	return KeyFile{
		Type:        keyType,
		Description: description,
		CborHex:     hex.EncodeToString(keyCbor),
	}
}

func GetPaymentSKey(paymentKey bip32.XPrv) KeyFile {
	return getSigningKeyFile(paymentKey, "PaymentSigningKeyShelley_ed25519", "Payment Signing Key")
}

func GetPaymentExtendedSKey(paymentKey bip32.XPrv) KeyFile {
	keyCbor, err := cbor.Marshal(
		GetExtendedPrivateKey(paymentKey),
	)
	if err != nil {
		panic(err)
	}
	return KeyFile{
		Type:        "PaymentExtendedSigningKeyShelley_ed25519_bip32",
		Description: "Payment Extended Signing Key (BIP32)",
		CborHex:     hex.EncodeToString(keyCbor),
	}
}

func GetStakeKey(accountKey bip32.XPrv, num uint32) bip32.XPrv {
	return accountKey.Derive(2).Derive(num)
}

func GetStakeVKey(stakeKey bip32.XPrv) KeyFile {
	keyCbor, err := cbor.Marshal(stakeKey.Public().PublicKey())
	if err != nil {
		panic(err)
	}
	return KeyFile{
		Type:        "StakeVerificationKeyShelley_ed25519",
		Description: "Stake Verification Key",
		CborHex:     hex.EncodeToString(keyCbor),
	}
}

func GetStakeSKey(stakeKey bip32.XPrv) KeyFile {
	return getSigningKeyFile(stakeKey, "StakeSigningKeyShelley_ed25519", "Stake Signing Key")
}

func GetStakeExtendedSKey(stakeKey bip32.XPrv) KeyFile {
	keyCbor, err := cbor.Marshal(
		GetExtendedPrivateKey(stakeKey),
	)
	if err != nil {
		panic(err)
	}
	return KeyFile{
		Type:        "StakeExtendedSigningKeyShelley_ed25519_bip32",
		Description: "Stake Extended Signing Key (BIP32)",
		CborHex:     hex.EncodeToString(keyCbor),
	}
}

func GetAddress(
	accountKey bip32.XPrv,
	networkName string,
	num uint32,
) (*lcommon.Address, error) {
	network, ok := ouroboros.NetworkByName(networkName)
	if !ok {
		return nil, fmt.Errorf(
			"couldn't get network for network name %q",
			networkName,
		)
	}
	paymentKeyPublicHash := GetPaymentKey(
		accountKey,
		num,
	).Public().
		PublicKey().
		Hash()
	stakeKeyPublicHash := GetStakeKey(
		accountKey,
		num,
	).Public().
		PublicKey().
		Hash()
	addr, err := lcommon.NewAddressFromParts(
		lcommon.AddressTypeKeyKey,
		network.Id,
		paymentKeyPublicHash[:],
		stakeKeyPublicHash[:],
	)
	if err != nil {
		return nil, fmt.Errorf("error creating address: %w", err)
	}
	return &addr, nil
}

func GetExtendedPrivateKey(privateKey bip32.XPrv) bip32.XPrv {
	// Create a defensive copy to prevent accidental mutation of the input key
	xprv := make([]byte, 96)
	copy(xprv[:32], privateKey[:32])
	copy(xprv[32:64], privateKey[32:64]) // preserve k_R
	copy(xprv[64:], privateKey[64:])
	return xprv
}

func GetKeyFile(keyFile KeyFile) (string, error) {
	// Use 4 spaces for indent
	ret, err := json.MarshalIndent(keyFile, "", "    ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal key file: %w", err)
	}
	// Append newline
	return fmt.Sprintf("%s\n", ret), nil
}

func decodeNonExtendedCborKey(skeyBytes []byte) ([]byte, []byte, error) {
	if len(skeyBytes) < 3 || skeyBytes[0] != 0x58 {
		return nil, nil, errors.New("invalid signing key cbor")
	}
	switch skeyBytes[1] {
	case 0x20:
		if len(skeyBytes) != 34 {
			return nil, nil, errors.New("invalid cbor skey hex length")
		}
		key := ed25519.NewKeyFromSeed(skeyBytes[2:])
		return key[:], key[32:], nil
	// Adding this because bursa emits 58 60 (CBor byte string of length 96 bytes)
	case 0x60:
		if len(skeyBytes) != 98 {
			return nil, nil, errors.New("invalid xprv skey length")
		}
		x := bip32.XPrv{}
		x = append(x, skeyBytes[2:]...)
		pub := x.Public().PublicKey()
		return skeyBytes[2:], pub, nil
	default:
		return nil, nil, errors.New("unsupported non-extended skey cbor")
	}
}

func decodeExtendedCborKey(skeyBytes []byte) ([]byte, []byte, error) {
	if len(skeyBytes) != 130 {
		return nil, nil, errors.New("invalid cbor skey hex length")
	}
	if skeyBytes[0] != 0x58 || skeyBytes[1] != 0x80 {
		return nil, nil, errors.New("invalid cbor skey hex prefix")
	}

	// Return full 128-byte extended key (64B private + 32B public + 32B chain)
	return skeyBytes[2:130], skeyBytes[66:98], nil
}

func decodeVerificationKey(vkeyBytes []byte) ([]byte, error) {
	if len(vkeyBytes) != 34 {
		return nil, errors.New("invalid cbor vkey hex length")
	}
	if vkeyBytes[0] != 0x58 || vkeyBytes[1] != 0x20 {
		return nil, errors.New("invalid cbor vkey hex prefix")
	}
	return vkeyBytes[2:], nil
}

func parseKeyEnvelope(fileBytes []byte) (*LoadedKey, error) {
	var env KeyFile
	if err := json.Unmarshal(fileBytes, &env); err != nil {
		return nil, errors.New("could not parse key file envelope")
	}
	// Convert cbor hex to raw bytes
	cbor, err := hex.DecodeString(env.CborHex)
	if err != nil {
		return nil, fmt.Errorf("could not decode key from hex: %w", err)
	}
	lk := &LoadedKey{
		Type:        env.Type,
		Description: env.Description,
		RawCBOR:     cbor,
	}
	// Decode cbor encoded key bytes
	switch env.Type {
	case "PaymentVerificationKeyShelley_ed25519", "StakeVerificationKeyShelley_ed25519":
		vk, err := decodeVerificationKey(cbor)
		if err != nil {
			return nil, err
		}
		lk.VKey = vk
		return lk, nil
	case "PaymentSigningKeyShelley_ed25519", "StakeSigningKeyShelley_ed25519":
		sk, vk, err := decodeNonExtendedCborKey(cbor)
		if err != nil {
			return nil, err
		}
		lk.SKey, lk.VKey = sk, vk
		return lk, nil
	case "PaymentExtendedSigningKeyShelley_ed25519_bip32", "StakeExtendedSigningKeyShelley_ed25519_bip32":
		sk, vk, err := decodeExtendedCborKey(cbor)
		if err != nil {
			return nil, err
		}
		lk.SKey, lk.VKey = sk, vk
		return lk, nil
	default:
		return nil, fmt.Errorf("unknown key type: %s", env.Type)
	}
}

func LoadWalletDir(dir string, showSecrets bool) ([]*LoadedKey, error) {
	out := make([]*LoadedKey, 0)

	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range files {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !(strings.HasSuffix(n, ".vkey")) && !(strings.HasSuffix(n, ".skey")) {
			continue
		}
		p := filepath.Join(dir, n)
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		loadedKeyFile, err := parseKeyEnvelope(b)
		if err != nil {
			return nil, fmt.Errorf("decode %s: %w", p, err)
		}
		loadedKeyFile.File = n
		out = append(out, loadedKeyFile)
	}
	if len(out) == 0 {
		return nil, fs.ErrNotExist
	}

	return out, nil
}

func PrintLoadedKeys(keys []*LoadedKey, showSecrets bool) {
	// Printing out all loaded key files one by one after decoding successfully
	var lines []string
	for _, k := range keys {
		switch {
		case len(k.SKey) > 0 && len(k.VKey) > 0:
			if showSecrets {
				lines = append(lines, fmt.Sprintf("\n%s | %s | Private Key (skey): %dB %s | Public Key (vkey): 32B %s",
					k.File, k.Type, len(k.SKey), hex.EncodeToString(k.SKey), hex.EncodeToString(k.VKey)))
			} else {
				lines = append(lines, fmt.Sprintf("\n%s | %s | skey=%dB | vkey=32B %s",
					k.File, k.Type, len(k.SKey), hex.EncodeToString(k.VKey)))
			}
		case len(k.VKey) == 32:
			lines = append(lines, fmt.Sprintf("\n%s | %s | Public Key (vkey): 32B %s",
				k.File, k.Type, hex.EncodeToString(k.VKey)))
		default:
			lines = append(lines, fmt.Sprintf("%s | %s | unsupported", k.File, k.Type))
		}
	}

	for _, line := range lines {
		fmt.Println(line)
	}
}
