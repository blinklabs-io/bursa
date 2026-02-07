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

package cli

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"golang.org/x/crypto/blake2b"
)

// writeCertEnvelope writes a certificate in cardano-cli
// compatible JSON text envelope format to a file.
func writeCertEnvelope(
	envType, description string,
	cborData []byte,
	outputFile string,
) error {
	envelope := struct {
		Type        string `json:"type"`
		Description string `json:"description"`
		CborHex     string `json:"cborHex"`
	}{
		Type:        envType,
		Description: description,
		CborHex:     hex.EncodeToString(cborData),
	}
	certJSON, err := json.MarshalIndent(envelope, "", "    ")
	if err != nil {
		return fmt.Errorf(
			"failed to marshal certificate JSON: %w",
			err,
		)
	}
	certJSON = append(certJSON, '\n')
	if err := os.WriteFile(
		outputFile, certJSON, 0o600,
	); err != nil {
		return fmt.Errorf(
			"failed to write certificate file: %w", err,
		)
	}
	return nil
}

// hashVerificationKey computes the Blake2b-224 hash of a
// 32-byte verification key, producing a 28-byte credential
// hash suitable for use in Cardano certificates.
func hashVerificationKey(vkey []byte) ([]byte, error) {
	if len(vkey) != 32 {
		return nil, fmt.Errorf(
			"invalid verification key length: "+
				"got %d, expected 32",
			len(vkey),
		)
	}
	hasher, err := blake2b.New(28, nil)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to create blake2b hasher: %w", err,
		)
	}
	_, err = hasher.Write(vkey)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to hash verification key: %w", err,
		)
	}
	return hasher.Sum(nil), nil
}

// buildKeyCredential builds a CBOR-encoded key credential
// from a verification key. The credential is encoded as
// [0, keyhash] where 0 indicates a key hash credential
// (as opposed to a script hash credential type 1).
func buildKeyCredential(
	vkey []byte,
) (cbor.RawMessage, error) {
	keyHash, err := hashVerificationKey(vkey)
	if err != nil {
		return nil, err
	}
	// credential = [0, addr_keyhash]
	cred := []any{uint64(0), keyHash}
	encoded, err := cbor.Encode(cred)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to encode credential: %w", err,
		)
	}
	return cbor.RawMessage(encoded), nil
}

// RunCertStakeRegistration creates a stake address
// registration certificate and writes it as a cardano-cli
// compatible JSON text envelope file.
//
// Cardano ledger CDDL:
//
//	stake_registration = (0, stake_credential)
func RunCertStakeRegistration(
	stakeVkeyFile, outputFile string,
) error {
	// Read and parse the stake verification key
	stakeVkeyData, err := os.ReadFile(stakeVkeyFile)
	if err != nil {
		return fmt.Errorf(
			"failed to read stake vkey file: %w", err,
		)
	}
	stakeVkey, err := parseVerificationKey(stakeVkeyData)
	if err != nil {
		return fmt.Errorf(
			"failed to parse stake vkey: %w", err,
		)
	}

	// Build stake credential
	cred, err := buildKeyCredential(stakeVkey)
	if err != nil {
		return fmt.Errorf(
			"failed to build stake credential: %w", err,
		)
	}

	// Encode certificate: [0, stake_credential]
	cert := []any{uint64(0), cred}
	certBytes, err := cbor.Encode(cert)
	if err != nil {
		return fmt.Errorf(
			"failed to encode certificate CBOR: %w", err,
		)
	}

	if outputFile != "" {
		if err := writeCertEnvelope(
			"CertificateShelley",
			"Stake Address Registration Certificate",
			certBytes,
			outputFile,
		); err != nil {
			return err
		}
		fmt.Printf(
			"Stake registration certificate "+
				"written to %s\n",
			outputFile,
		)
	} else {
		fmt.Printf("%s\n", hex.EncodeToString(certBytes))
	}

	return nil
}

// RunCertStakeDeregistration creates a stake address
// deregistration certificate and writes it as a cardano-cli
// compatible JSON text envelope file.
//
// Cardano ledger CDDL:
//
//	stake_deregistration = (1, stake_credential)
func RunCertStakeDeregistration(
	stakeVkeyFile, outputFile string,
) error {
	// Read and parse the stake verification key
	stakeVkeyData, err := os.ReadFile(stakeVkeyFile)
	if err != nil {
		return fmt.Errorf(
			"failed to read stake vkey file: %w", err,
		)
	}
	stakeVkey, err := parseVerificationKey(stakeVkeyData)
	if err != nil {
		return fmt.Errorf(
			"failed to parse stake vkey: %w", err,
		)
	}

	// Build stake credential
	cred, err := buildKeyCredential(stakeVkey)
	if err != nil {
		return fmt.Errorf(
			"failed to build stake credential: %w", err,
		)
	}

	// Encode certificate: [1, stake_credential]
	cert := []any{uint64(1), cred}
	certBytes, err := cbor.Encode(cert)
	if err != nil {
		return fmt.Errorf(
			"failed to encode certificate CBOR: %w", err,
		)
	}

	if outputFile != "" {
		if err := writeCertEnvelope(
			"CertificateShelley",
			"Stake Address Deregistration Certificate",
			certBytes,
			outputFile,
		); err != nil {
			return err
		}
		fmt.Printf(
			"Stake deregistration certificate "+
				"written to %s\n",
			outputFile,
		)
	} else {
		fmt.Printf("%s\n", hex.EncodeToString(certBytes))
	}

	return nil
}

// RunCertStakeDelegation creates a stake delegation
// certificate and writes it as a cardano-cli compatible JSON
// text envelope file.
//
// Cardano ledger CDDL:
//
//	stake_delegation = (2, stake_credential, pool_keyhash)
func RunCertStakeDelegation(
	stakeVkeyFile, poolID, outputFile string,
) error {
	// Read and parse the stake verification key
	stakeVkeyData, err := os.ReadFile(stakeVkeyFile)
	if err != nil {
		return fmt.Errorf(
			"failed to read stake vkey file: %w", err,
		)
	}
	stakeVkey, err := parseVerificationKey(stakeVkeyData)
	if err != nil {
		return fmt.Errorf(
			"failed to parse stake vkey: %w", err,
		)
	}

	// Parse pool ID (bech32 or hex)
	poolKeyHash, err := parsePoolID(poolID)
	if err != nil {
		return fmt.Errorf(
			"failed to parse pool ID: %w", err,
		)
	}

	// Build stake credential
	cred, err := buildKeyCredential(stakeVkey)
	if err != nil {
		return fmt.Errorf(
			"failed to build stake credential: %w", err,
		)
	}

	// Encode certificate:
	// [2, stake_credential, pool_keyhash]
	cert := []any{uint64(2), cred, poolKeyHash}
	certBytes, err := cbor.Encode(cert)
	if err != nil {
		return fmt.Errorf(
			"failed to encode certificate CBOR: %w", err,
		)
	}

	if outputFile != "" {
		if err := writeCertEnvelope(
			"CertificateShelley",
			"Stake Delegation Certificate",
			certBytes,
			outputFile,
		); err != nil {
			return err
		}
		fmt.Printf(
			"Stake delegation certificate "+
				"written to %s\n",
			outputFile,
		)
	} else {
		fmt.Printf("%s\n", hex.EncodeToString(certBytes))
	}

	return nil
}

// parsePoolID parses a pool ID from bech32 (pool1...) or hex
// format. Returns the 28-byte pool key hash.
func parsePoolID(poolID string) ([]byte, error) {
	// Try bech32 first (pool1...)
	if len(poolID) > 5 && poolID[:5] == "pool1" {
		_, decoded, err := bech32.Decode(poolID)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to decode bech32 pool ID: %w",
				err,
			)
		}
		keyHash, err := bech32.ConvertBits(
			decoded, 5, 8, false,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to convert bits: %w", err,
			)
		}
		if len(keyHash) != 28 {
			return nil, fmt.Errorf(
				"invalid pool ID length: "+
					"got %d bytes, expected 28",
				len(keyHash),
			)
		}
		return keyHash, nil
	}

	// Try hex
	keyHash, err := hex.DecodeString(poolID)
	if err != nil {
		return nil, fmt.Errorf(
			"invalid pool ID format "+
				"(expected bech32 pool1... or "+
				"28-byte hex): %w",
			err,
		)
	}
	if len(keyHash) != 28 {
		return nil, fmt.Errorf(
			"invalid pool ID hex length: "+
				"got %d bytes, expected 28",
			len(keyHash),
		)
	}
	return keyHash, nil
}

// RunCertDRepRegistration creates a DRep registration
// certificate and writes it as a cardano-cli compatible JSON
// text envelope file.
//
// Cardano ledger CDDL:
//
//	reg_drep_cert = (16, drep_credential, coin, anchor / null)
func RunCertDRepRegistration(
	drepVkeyFile, outputFile string,
	deposit uint64,
	anchorURL, anchorHash string,
) error {
	// Read and parse the DRep verification key
	drepVkeyData, err := os.ReadFile(drepVkeyFile)
	if err != nil {
		return fmt.Errorf(
			"failed to read DRep vkey file: %w", err,
		)
	}
	drepVkey, err := parseVerificationKey(drepVkeyData)
	if err != nil {
		return fmt.Errorf(
			"failed to parse DRep vkey: %w", err,
		)
	}

	// Build DRep credential (same format as key credential)
	cred, err := buildKeyCredential(drepVkey)
	if err != nil {
		return fmt.Errorf(
			"failed to build DRep credential: %w", err,
		)
	}

	// Build anchor (null if not provided)
	anchor, err := buildAnchor(anchorURL, anchorHash)
	if err != nil {
		return fmt.Errorf(
			"failed to build anchor: %w", err,
		)
	}

	// Encode certificate:
	// [16, drep_credential, coin, anchor]
	cert := []any{uint64(16), cred, deposit, anchor}
	certBytes, err := cbor.Encode(cert)
	if err != nil {
		return fmt.Errorf(
			"failed to encode certificate CBOR: %w", err,
		)
	}

	if outputFile != "" {
		if err := writeCertEnvelope(
			"CertificateConway",
			"DRep Registration Certificate",
			certBytes,
			outputFile,
		); err != nil {
			return err
		}
		fmt.Printf(
			"DRep registration certificate "+
				"written to %s\n",
			outputFile,
		)
	} else {
		fmt.Printf("%s\n", hex.EncodeToString(certBytes))
	}

	return nil
}

// buildAnchor builds a CBOR-encoded anchor value.
// Returns CBOR null if URL is empty, otherwise returns
// [url, hash] where hash is 32 bytes.
func buildAnchor(
	anchorURL, anchorHash string,
) (cbor.RawMessage, error) {
	if anchorURL == "" {
		if anchorHash != "" {
			return nil, errors.New(
				"anchor-url is required when " +
					"anchor-hash is provided",
			)
		}
		// CBOR null
		encoded, err := cbor.Encode(nil)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to encode null anchor: %w", err,
			)
		}
		return cbor.RawMessage(encoded), nil
	}

	if anchorHash == "" {
		return nil, errors.New(
			"anchor-hash is required when " +
				"anchor-url is specified",
		)
	}

	hashBytes, err := hex.DecodeString(anchorHash)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to decode anchor hash hex: %w", err,
		)
	}
	if len(hashBytes) != 32 {
		return nil, fmt.Errorf(
			"invalid anchor hash length: "+
				"got %d bytes, expected 32",
			len(hashBytes),
		)
	}

	// anchor = [url, hash]
	anchorData := []any{anchorURL, hashBytes}
	encoded, err := cbor.Encode(anchorData)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to encode anchor: %w", err,
		)
	}
	return cbor.RawMessage(encoded), nil
}

// RunCertDRepDeregistration creates a DRep deregistration
// certificate and writes it as a cardano-cli compatible JSON
// text envelope file.
//
// Cardano ledger CDDL:
//
//	unreg_drep_cert = (17, drep_credential, coin)
func RunCertDRepDeregistration(
	drepVkeyFile, outputFile string,
	depositRefund uint64,
) error {
	// Read and parse the DRep verification key
	drepVkeyData, err := os.ReadFile(drepVkeyFile)
	if err != nil {
		return fmt.Errorf(
			"failed to read DRep vkey file: %w", err,
		)
	}
	drepVkey, err := parseVerificationKey(drepVkeyData)
	if err != nil {
		return fmt.Errorf(
			"failed to parse DRep vkey: %w", err,
		)
	}

	// Build DRep credential
	cred, err := buildKeyCredential(drepVkey)
	if err != nil {
		return fmt.Errorf(
			"failed to build DRep credential: %w", err,
		)
	}

	// Encode certificate:
	// [17, drep_credential, coin]
	cert := []any{uint64(17), cred, depositRefund}
	certBytes, err := cbor.Encode(cert)
	if err != nil {
		return fmt.Errorf(
			"failed to encode certificate CBOR: %w", err,
		)
	}

	if outputFile != "" {
		if err := writeCertEnvelope(
			"CertificateConway",
			"DRep Retirement (Deregistration) Certificate",
			certBytes,
			outputFile,
		); err != nil {
			return err
		}
		fmt.Printf(
			"DRep deregistration certificate "+
				"written to %s\n",
			outputFile,
		)
	} else {
		fmt.Printf("%s\n", hex.EncodeToString(certBytes))
	}

	return nil
}

// RunCertVoteDelegation creates a vote delegation certificate
// and writes it as a cardano-cli compatible JSON text envelope
// file.
//
// Cardano ledger CDDL:
//
//	vote_deleg_cert = (9, stake_credential, drep)
//	drep = [0, keyhash]     -- specific DRep by key hash
//	     / [1, scripthash]  -- specific DRep by script hash
//	     / 2                -- always-abstain
//	     / 3                -- always-no-confidence
func RunCertVoteDelegation(
	stakeVkeyFile, drepVkeyHash, drepID, outputFile string,
	alwaysAbstain, alwaysNoConfidence bool,
) error {
	// Validate that exactly one DRep target is specified
	targetCount := 0
	if drepVkeyHash != "" {
		targetCount++
	}
	if drepID != "" {
		targetCount++
	}
	if alwaysAbstain {
		targetCount++
	}
	if alwaysNoConfidence {
		targetCount++
	}
	if targetCount != 1 {
		return errors.New(
			"exactly one of --drep-vkey-hash, " +
				"--drep-id, --always-abstain, or " +
				"--always-no-confidence " +
				"must be specified",
		)
	}

	// Read and parse the stake verification key
	stakeVkeyData, err := os.ReadFile(stakeVkeyFile)
	if err != nil {
		return fmt.Errorf(
			"failed to read stake vkey file: %w", err,
		)
	}
	stakeVkey, err := parseVerificationKey(stakeVkeyData)
	if err != nil {
		return fmt.Errorf(
			"failed to parse stake vkey: %w", err,
		)
	}

	// Build stake credential
	cred, err := buildKeyCredential(stakeVkey)
	if err != nil {
		return fmt.Errorf(
			"failed to build stake credential: %w", err,
		)
	}

	// Build DRep target
	drepTarget, err := buildDRepTarget(
		drepVkeyHash, drepID,
		alwaysAbstain, alwaysNoConfidence,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to build DRep target: %w", err,
		)
	}

	// Encode certificate:
	// [9, stake_credential, drep]
	cert := []any{uint64(9), cred, drepTarget}
	certBytes, err := cbor.Encode(cert)
	if err != nil {
		return fmt.Errorf(
			"failed to encode certificate CBOR: %w", err,
		)
	}

	if outputFile != "" {
		if err := writeCertEnvelope(
			"CertificateConway",
			"Vote Delegation Certificate",
			certBytes,
			outputFile,
		); err != nil {
			return err
		}
		fmt.Printf(
			"Vote delegation certificate "+
				"written to %s\n",
			outputFile,
		)
	} else {
		fmt.Printf("%s\n", hex.EncodeToString(certBytes))
	}

	return nil
}

// buildDRepTarget builds a CBOR-encoded DRep value for vote
// delegation. The DRep can be a specific key hash, a DRep ID,
// always-abstain (2), or always-no-confidence (3).
func buildDRepTarget(
	drepVkeyHash, drepID string,
	alwaysAbstain, alwaysNoConfidence bool,
) (cbor.RawMessage, error) {
	switch {
	case alwaysAbstain:
		// always-abstain = 2
		encoded, err := cbor.Encode(uint64(2))
		if err != nil {
			return nil, fmt.Errorf(
				"failed to encode always-abstain: %w",
				err,
			)
		}
		return cbor.RawMessage(encoded), nil

	case alwaysNoConfidence:
		// always-no-confidence = 3
		encoded, err := cbor.Encode(uint64(3))
		if err != nil {
			return nil, fmt.Errorf(
				"failed to encode "+
					"always-no-confidence: %w",
				err,
			)
		}
		return cbor.RawMessage(encoded), nil

	case drepVkeyHash != "":
		// Parse the key hash (hex)
		keyHash, err := hex.DecodeString(drepVkeyHash)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to decode DRep "+
					"vkey hash: %w",
				err,
			)
		}
		if len(keyHash) != 28 {
			return nil, fmt.Errorf(
				"invalid DRep vkey hash length: "+
					"got %d bytes, expected 28",
				len(keyHash),
			)
		}
		// drep = [0, keyhash]
		drep := []any{uint64(0), keyHash}
		encoded, err := cbor.Encode(drep)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to encode "+
					"DRep credential: %w",
				err,
			)
		}
		return cbor.RawMessage(encoded), nil

	case drepID != "":
		// Parse DRep ID (bech32 drep1... or hex)
		keyHash, err := parseDRepID(drepID)
		if err != nil {
			return nil, err
		}
		// drep = [0, keyhash]
		drep := []any{uint64(0), keyHash}
		encoded, err := cbor.Encode(drep)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to encode "+
					"DRep credential: %w",
				err,
			)
		}
		return cbor.RawMessage(encoded), nil

	default:
		return nil, errors.New("no DRep target specified")
	}
}

// parseDRepID parses a DRep ID from bech32 (drep1...) or hex
// format. Returns the 28-byte key hash.
func parseDRepID(drepID string) ([]byte, error) {
	// Try bech32 first (drep1...)
	if len(drepID) > 5 && drepID[:5] == "drep1" {
		_, decoded, err := bech32.Decode(drepID)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to decode bech32 "+
					"DRep ID: %w",
				err,
			)
		}
		keyHash, err := bech32.ConvertBits(
			decoded, 5, 8, false,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to convert bits: %w", err,
			)
		}
		if len(keyHash) != 28 {
			return nil, fmt.Errorf(
				"invalid DRep ID length: "+
					"got %d bytes, expected 28",
				len(keyHash),
			)
		}
		return keyHash, nil
	}

	// Try hex
	keyHash, err := hex.DecodeString(drepID)
	if err != nil {
		return nil, fmt.Errorf(
			"invalid DRep ID format "+
				"(expected bech32 drep1... or "+
				"28-byte hex): %w",
			err,
		)
	}
	if len(keyHash) != 28 {
		return nil, fmt.Errorf(
			"invalid DRep ID hex length: "+
				"got %d bytes, expected 28",
			len(keyHash),
		)
	}
	return keyHash, nil
}

// RunCertCommitteeHotAuth creates a committee hot key
// authorization certificate and writes it as a cardano-cli
// compatible JSON text envelope file.
//
// Cardano ledger CDDL:
//
//	auth_committee_hot_cert =
//	  (14, committee_cold_credential,
//	       committee_hot_credential)
func RunCertCommitteeHotAuth(
	coldVkeyFile, hotVkeyFile, outputFile string,
) error {
	// Read and parse the cold verification key
	coldVkeyData, err := os.ReadFile(coldVkeyFile)
	if err != nil {
		return fmt.Errorf(
			"failed to read cold vkey file: %w", err,
		)
	}
	coldVkey, err := parseVerificationKey(coldVkeyData)
	if err != nil {
		return fmt.Errorf(
			"failed to parse cold vkey: %w", err,
		)
	}

	// Read and parse the hot verification key
	hotVkeyData, err := os.ReadFile(hotVkeyFile)
	if err != nil {
		return fmt.Errorf(
			"failed to read hot vkey file: %w", err,
		)
	}
	hotVkey, err := parseVerificationKey(hotVkeyData)
	if err != nil {
		return fmt.Errorf(
			"failed to parse hot vkey: %w", err,
		)
	}

	// Build credentials
	coldCred, err := buildKeyCredential(coldVkey)
	if err != nil {
		return fmt.Errorf(
			"failed to build cold credential: %w", err,
		)
	}
	hotCred, err := buildKeyCredential(hotVkey)
	if err != nil {
		return fmt.Errorf(
			"failed to build hot credential: %w", err,
		)
	}

	// Encode certificate:
	// [14, cold_credential, hot_credential]
	cert := []any{uint64(14), coldCred, hotCred}
	certBytes, err := cbor.Encode(cert)
	if err != nil {
		return fmt.Errorf(
			"failed to encode certificate CBOR: %w", err,
		)
	}

	if outputFile != "" {
		if err := writeCertEnvelope(
			"CertificateConway",
			"Constitutional Committee Hot Key "+
				"Authorization Certificate",
			certBytes,
			outputFile,
		); err != nil {
			return err
		}
		fmt.Printf(
			"Committee hot key authorization "+
				"certificate written to %s\n",
			outputFile,
		)
	} else {
		fmt.Printf("%s\n", hex.EncodeToString(certBytes))
	}

	return nil
}

// RunCertCommitteeColdResign creates a committee cold key
// resignation certificate and writes it as a cardano-cli
// compatible JSON text envelope file.
//
// Cardano ledger CDDL:
//
//	resign_committee_cold_cert =
//	  (15, committee_cold_credential, anchor / null)
func RunCertCommitteeColdResign(
	coldVkeyFile, outputFile string,
	anchorURL, anchorHash string,
) error {
	// Read and parse the cold verification key
	coldVkeyData, err := os.ReadFile(coldVkeyFile)
	if err != nil {
		return fmt.Errorf(
			"failed to read cold vkey file: %w", err,
		)
	}
	coldVkey, err := parseVerificationKey(coldVkeyData)
	if err != nil {
		return fmt.Errorf(
			"failed to parse cold vkey: %w", err,
		)
	}

	// Build cold credential
	coldCred, err := buildKeyCredential(coldVkey)
	if err != nil {
		return fmt.Errorf(
			"failed to build cold credential: %w", err,
		)
	}

	// Build anchor
	anchor, err := buildAnchor(anchorURL, anchorHash)
	if err != nil {
		return fmt.Errorf(
			"failed to build anchor: %w", err,
		)
	}

	// Encode certificate:
	// [15, cold_credential, anchor / null]
	cert := []any{uint64(15), coldCred, anchor}
	certBytes, err := cbor.Encode(cert)
	if err != nil {
		return fmt.Errorf(
			"failed to encode certificate CBOR: %w", err,
		)
	}

	if outputFile != "" {
		if err := writeCertEnvelope(
			"CertificateConway",
			"Constitutional Committee Cold Key "+
				"Resignation Certificate",
			certBytes,
			outputFile,
		); err != nil {
			return err
		}
		fmt.Printf(
			"Committee cold key resignation "+
				"certificate written to %s\n",
			outputFile,
		)
	} else {
		fmt.Printf("%s\n", hex.EncodeToString(certBytes))
	}

	return nil
}
