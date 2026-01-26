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

package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureStdout captures stdout during the execution of a function

func captureStdout(t *testing.T, f func()) (out string) {
	t.Helper()

	old := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)

	os.Stdout = w

	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()

	defer func() {
		os.Stdout = old
		_ = w.Close()
		<-done
		_ = r.Close()
		out = strings.TrimSpace(buf.String())
		if rec := recover(); rec != nil {
			panic(rec)
		}
	}()

	f()
	return out
}

func TestRunHashMetadata(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "bursa-hash-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Test metadata JSON
	testMetadata := `{
		"name": "Test Pool",
		"description": "A test stake pool for development",
		"ticker": "TEST",
		"homepage": "https://example.com",
		"extended": {
			"z": "extended metadata"
		}
	}`

	// Create test file
	metadataFile := filepath.Join(tempDir, "metadata.json")
	err = os.WriteFile(metadataFile, []byte(testMetadata), 0644)
	require.NoError(t, err)

	// Test pool metadata hashing
	err = RunHashMetadata(metadataFile, "pool")
	require.NoError(t, err)

	// Test drep metadata hashing
	err = RunHashMetadata(metadataFile, "drep")
	require.NoError(t, err)
}

func TestRunHashMetadataCanonicalization(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "bursa-hash-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Test that different JSON formatting produces the same hash
	metadata1 := `{"name":"Test","value":123}`
	metadata2 := `{
		"name": "Test",
		"value": 123
	}`

	file1 := filepath.Join(tempDir, "metadata1.json")
	file2 := filepath.Join(tempDir, "metadata2.json")

	err = os.WriteFile(file1, []byte(metadata1), 0644)
	require.NoError(t, err)
	err = os.WriteFile(file2, []byte(metadata2), 0644)
	require.NoError(t, err)

	// Capture output from both calls
	hash1 := captureStdout(t, func() {
		err := RunHashMetadata(file1, "pool")
		require.NoError(t, err)
	})

	hash2 := captureStdout(t, func() {
		err := RunHashMetadata(file2, "pool")
		require.NoError(t, err)
	})

	// Both should produce the same hash due to canonicalization
	assert.Equal(t, hash1, hash2, "Canonicalization should produce identical hashes for semantically equivalent JSON")
}

func TestRunHashMetadataErrors(t *testing.T) {
	// Test with non-existent file
	err := RunHashMetadata("nonexistent.json", "pool")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read metadata file")

	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "bursa-hash-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Test with invalid JSON
	invalidJSONFile := filepath.Join(tempDir, "invalid.json")
	err = os.WriteFile(invalidJSONFile, []byte(`{"invalid": json}`), 0644)
	require.NoError(t, err)

	err = RunHashMetadata(invalidJSONFile, "pool")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid JSON in metadata file")
}

func TestRunHashMetadataKnownHash(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "bursa-hash-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Test with a known input and expected output
	// This is a simple test case where we know the expected Blake2b-256 hash
	testData := `{"test": "data"}`

	file := filepath.Join(tempDir, "test.json")
	err = os.WriteFile(file, []byte(testData), 0644)
	require.NoError(t, err)

	// Capture the hash output
	hash := captureStdout(t, func() {
		err := RunHashMetadata(file, "pool")
		require.NoError(t, err)
	})

	// Verify the hash matches the expected value
	expectedHash := "d7157feba618cc73df1d0cace17e12b27a5a4354c9272ca6d030496fc2556133"
	assert.Equal(t, expectedHash, hash, "Hash should match expected Blake2b-256 value")
}
