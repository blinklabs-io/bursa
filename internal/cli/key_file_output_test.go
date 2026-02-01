package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyFileOutput(t *testing.T) {
	// Test mnemonic - CIP-1852 test vector (DO NOT USE FOR REAL FUNDS)
	testMnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	tests := []struct {
		name             string
		runFunc          func(signingKeyFile, verificationKeyFile string) error
		expectedVKeyType string
		expectedSKeyType string
	}{
		{
			name:             "payment key",
			runFunc:          func(skey, vkey string) error { return RunKeyPayment(testMnemonic, "", "", skey, vkey, 0, 0) },
			expectedVKeyType: "PaymentVerificationKeyShelley_ed25519",
			expectedSKeyType: "PaymentSigningKeyShelley_ed25519",
		},
		{
			name:             "stake key",
			runFunc:          func(skey, vkey string) error { return RunKeyStake(testMnemonic, "", "", skey, vkey, 0, 0) },
			expectedVKeyType: "StakeVerificationKeyShelley_ed25519",
			expectedSKeyType: "StakeSigningKeyShelley_ed25519",
		},
		{
			name:             "pool cold key",
			runFunc:          func(skey, vkey string) error { return RunKeyPoolCold(testMnemonic, "", "", skey, vkey, 0) },
			expectedVKeyType: "StakePoolVerificationKeyShelley_ed25519",
			expectedSKeyType: "StakePoolSigningKeyShelley_ed25519",
		},
		{
			name:             "policy key",
			runFunc:          func(skey, vkey string) error { return RunKeyPolicy(testMnemonic, "", "", skey, vkey, 0) },
			expectedVKeyType: "PolicyVerificationKeyShelley_ed25519",
			expectedSKeyType: "PolicySigningKeyShelley_ed25519",
		},
		{
			name:             "drep key",
			runFunc:          func(skey, vkey string) error { return RunKeyDRep(testMnemonic, "", "", skey, vkey, 0, 0) },
			expectedVKeyType: "DRepVerificationKeyShelley_ed25519",
			expectedSKeyType: "DRepSigningKeyShelley_ed25519",
		},
		{
			name:             "committee cold key",
			runFunc:          func(skey, vkey string) error { return RunKeyCommitteeCold(testMnemonic, "", "", skey, vkey, 0, 0) },
			expectedVKeyType: "CommitteeColdVerificationKeyShelley_ed25519",
			expectedSKeyType: "CommitteeColdSigningKeyShelley_ed25519",
		},
		{
			name:             "committee hot key",
			runFunc:          func(skey, vkey string) error { return RunKeyCommitteeHot(testMnemonic, "", "", skey, vkey, 0, 0) },
			expectedVKeyType: "CommitteeHotVerificationKeyShelley_ed25519",
			expectedSKeyType: "CommitteeHotSigningKeyShelley_ed25519",
		},
		{
			name:             "VRF key",
			runFunc:          func(skey, vkey string) error { return RunKeyVRF(testMnemonic, "", "", skey, vkey, 0) },
			expectedVKeyType: "VRFVerificationKey_PraosVRF",
			expectedSKeyType: "VRFSigningKey_PraosVRF",
		},
		{
			name:             "KES key",
			runFunc:          func(skey, vkey string) error { return RunKeyKES(testMnemonic, "", "", skey, vkey, 0) },
			expectedVKeyType: "KESVerificationKey_PraosV2",
			expectedSKeyType: "KESSigningKey_PraosV2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory for test files
			tempDir, err := os.MkdirTemp("", "bursa-key-test")
			require.NoError(t, err)
			defer os.RemoveAll(tempDir)

			// Define file paths
			signingKeyFile := filepath.Join(tempDir, "skey.json")
			verificationKeyFile := filepath.Join(tempDir, "vkey.json")

			// Run the key generation function
			err = tt.runFunc(signingKeyFile, verificationKeyFile)
			require.NoError(t, err)

			// Verify signing key file was created and has correct format
			skeyData, err := os.ReadFile(signingKeyFile)
			require.NoError(t, err)

			var skey bursa.KeyFile
			err = json.Unmarshal(skeyData, &skey)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedSKeyType, skey.Type)
			assert.NotEmpty(t, skey.CborHex)
			assert.Contains(t, skey.Description, "Signing Key")

			// Verify verification key file was created and has correct format
			vkeyData, err := os.ReadFile(verificationKeyFile)
			require.NoError(t, err)

			var vkey bursa.KeyFile
			err = json.Unmarshal(vkeyData, &vkey)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedVKeyType, vkey.Type)
			assert.NotEmpty(t, vkey.CborHex)
			assert.Contains(t, vkey.Description, "Verification Key")

			// Verify files have correct permissions (should be 0o600 for security)
			skeyInfo, err := os.Stat(signingKeyFile)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0o600), skeyInfo.Mode())

			vkeyInfo, err := os.Stat(verificationKeyFile)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0o600), vkeyInfo.Mode())
		})
	}
}

func TestKeyFileOutputBackwardCompatibility(t *testing.T) {
	// Test that when no file paths are provided, functions still work (backward compatibility)
	testMnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	// Test payment key generation without files (should not error)
	err := RunKeyPayment(testMnemonic, "", "", "", "", 0, 0)
	require.NoError(t, err)

	// Test stake key generation without files (should not error)
	err = RunKeyStake(testMnemonic, "", "", "", "", 0, 0)
	require.NoError(t, err)
}

func TestKeyFilePermissionsEnforced(t *testing.T) {
	// Test mnemonic - CIP-1852 test vector (DO NOT USE FOR REAL FUNDS)
	testMnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	// Create temporary directory for test files
	tempDir, err := os.MkdirTemp("", "bursa-perm-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Define file paths
	signingKeyFile := filepath.Join(tempDir, "payment.skey")

	// First, create a file with insecure permissions
	insecureData := `{"type":"test","description":"test","cborHex":"00"}`
	err = os.WriteFile(signingKeyFile, []byte(insecureData), 0o644) // world-readable
	require.NoError(t, err)

	// Verify it has insecure permissions
	info, err := os.Stat(signingKeyFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), info.Mode())

	// Now run key generation which should overwrite with secure permissions
	err = RunKeyPayment(testMnemonic, "", "", signingKeyFile, "", 0, 0)
	require.NoError(t, err)

	// Verify the file now has secure permissions
	info, err = os.Stat(signingKeyFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode(), "Key file should have secure permissions (0o600)")

	// Verify the content is correct (not the old insecure content)
	data, err := os.ReadFile(signingKeyFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), "PaymentSigningKeyShelley_ed25519")
	assert.NotContains(t, string(data), "test")
}
