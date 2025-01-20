// Copyright 2024 Blink Labs Software
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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
)

// Mock JSON data for successful wallet restoration
var mockWalletResponseJSON = `{
  "mnemonic": "depth kitchen crystal history rabbit brief harbor palace tent frog city charge inflict tiger negative young furnace solid august educate bounce canal someone erode",
  "payment_address": "addr1qxwqkfd3qz5pdwmemtv2llmetegdyku4ffxuldjcfrs05nfjtw33ktf3j6amgxsgnj9u3fa5nrle79nv2g24npnth0esk2dy7q",
  "stake_address": "stake1uye9hgcm95cedwa5rgyfez7g576f3lulzek9y92ese4mhucu439t0",
  "payment_vkey": {
      "type": "PaymentVerificationKeyShelley_ed25519",
      "description": "Payment Verification Key",
      "cborHex": "582040c99562052dc67d0e265bf183d2e376905972346a11eec2dbb714600bb28911"
  },
  "payment_skey": {
      "type": "PaymentExtendedSigningKeyShelley_ed25519_bip32",
      "description": "Payment Signing Key",
      "cborHex": "5880d8f05d500419f363eb81d5ed832f7264b24cb529e6e2cb643a495e82c3aa6c4203089cdb6ed0f2d0db817b5a90e9f5b689a6e4da1f1c2157b463dd6690bee72840c99562052dc67d0e265bf183d2e376905972346a11eec2dbb714600bb28911c938975e7bec39ea8e57613558571b72eb4f399ab7967e985174a23c6e767840"
  },
  "stake_vkey": {
      "type": "StakeVerificationKeyShelley_ed25519",
      "description": "Stake Verification Key",
      "cborHex": "58202a786a251854a5f459a856e7ae8f9289be9a3a7a1bf421e35bfaab815868e0fd"
  },
  "stake_skey": {
      "type": "StakeExtendedSigningKeyShelley_ed25519_bip32",
      "description": "Stake Signing Key",
      "cborHex": "5880b0a9a8bcddc391c2cc79dbbac792e21f21fa8a3572e8591235bdc802c9aa6c4210eee620765fb6f569ab6b2916001cdd6d289067b022847d62ea19160463bcf72a786a251854a5f459a856e7ae8f9289be9a3a7a1bf421e35bfaab815868e0fd258df1a6eb6b51f6769afcdf4634594b13dba6433ec3670ea9ea742a09e8711e"
  }
}`

func startAPI(
	t *testing.T,
) (apiBaseURL, metricsBaseURL string, cleanup func()) {
	t.Helper()

	// Create listeners for API and metrics with ephemeral ports
	apiListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create API listener: %v", err)
	}
	metricsListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create metrics listener: %v", err)
	}

	// Retrieve the dynamically assigned ports
	apiPort := apiListener.Addr().(*net.TCPAddr).Port
	metricsPort := metricsListener.Addr().(*net.TCPAddr).Port

	// Create the configuration
	cfg := &config.Config{
		Network: "testnet",
		Api: config.ApiConfig{
			ListenAddress: "127.0.0.1",
			ListenPort:    uint(apiPort),
		},
		Metrics: config.MetricsConfig{
			ListenAddress: "127.0.0.1",
			ListenPort:    uint(metricsPort),
		},
	}

	// Start the API in a separate goroutine
	ctx, cancel := context.WithCancel(context.Background())

	// Define cleanup to be called after the test
	cleanup = func() {
		cancel()
	}

	go func() {
		if err := Start(ctx, cfg, apiListener, metricsListener); err != nil {
			// NOTE: This logs the error but does not fail the entire test
			t.Errorf("failed to start API: %v", err)
		}
	}()

	// Construct base URLs
	apiBaseURL = fmt.Sprintf("http://127.0.0.1:%d", apiPort)
	metricsBaseURL = fmt.Sprintf("http://127.0.0.1:%d", metricsPort)

	// Verify server readiness by checking the /healthcheck endpoint
	waitForServer(apiBaseURL)

	return apiBaseURL, metricsBaseURL, cleanup
}

// waitForServer actively waits for the server to be ready with retries.
func waitForServer(apiBaseURL string) {
	const maxRetries = 50
	const retryInterval = 10 * time.Millisecond

	for i := 0; i < maxRetries; i++ {
		resp, err := http.Get(fmt.Sprintf("%s/healthcheck", apiBaseURL))
		if resp == nil {
			continue
		}
		if err == nil && resp.StatusCode == http.StatusOK {
			return // Server is ready
		}
		time.Sleep(retryInterval)
	}

	panic("server did not start within the expected time")
}

func TestMetricsEndpoint(t *testing.T) {
	// Start the API
	_, metricsBaseURL, cleanup := startAPI(t)
	defer cleanup()

	// Test the /metrics endpoint
	resp, err := http.Get(fmt.Sprintf("%s/metrics", metricsBaseURL))
	if resp == nil {
		t.Fatal("failed to get response from metrics endpoint")
	}
	if err != nil {
		t.Fatalf("failed to call metrics endpoint: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %v", resp.StatusCode)
	}
}

func TestMetricsRegistered(t *testing.T) {
	// api.init() allows to not start the metrics server
	metricFamilies, err := prometheus.DefaultGatherer.Gather()
	assert.NoError(t, err, "Unable to gather metrics from default registry")

	// Flags to check if our metrics exist
	foundWalletsCreated := false
	foundWalletsFail := false
	foundWalletsRestore := false

	for _, mf := range metricFamilies {
		switch *mf.Name {
		case "bursa_wallets_created_count":
			foundWalletsCreated = true
		case "bursa_wallets_fail_count":
			foundWalletsFail = true
		case "bursa_wallets_restore_count":
			foundWalletsRestore = true
		}
	}

	// Verify that all expected metrics are present
	assert.True(t, foundWalletsCreated,
		"Expected metric `bursa_wallets_created_count` was not registered")
	assert.True(t, foundWalletsFail,
		"Expected metric `bursa_wallets_fail_count` was not registered")
	assert.True(t, foundWalletsRestore,
		"Expected metric `bursa_wallets_restore_count` was not registered")
}

func TestRestoreWallet(t *testing.T) {
	t.Run("Successful Wallet Restoration", func(t *testing.T) {
		t.Parallel()

		// Create a mock server
		server := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/wallet/restore" && r.Method == "POST" {
					var request WalletRestoreRequest
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
						http.Error(w, "Invalid request", http.StatusBadRequest)
						return
					}

					// Respond with the mock wallet JSON data
					w.WriteHeader(http.StatusOK)
					_, err := w.Write([]byte(mockWalletResponseJSON))
					if err != nil {
						t.Fatalf("Failed to write response: %v", err)
					}

				} else {
					w.WriteHeader(http.StatusNotFound)
				}
			}),
		)
		defer server.Close()

		// Prepare the request body
		requestBody, _ := json.Marshal(WalletRestoreRequest{
			Mnemonic: "depth kitchen crystal history rabbit brief harbor palace tent frog city charge inflict tiger negative young furnace solid august educate bounce canal someone erode",
		})

		resp, err := http.Post(
			server.URL+"/api/wallet/restore",
			"application/json",
			bytes.NewBuffer(requestBody),
		)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		responseBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		var expectedResponse, actualResponse map[string]interface{}

		if err := json.Unmarshal([]byte(mockWalletResponseJSON), &expectedResponse); err != nil {
			t.Fatalf("Failed to unmarshal expected response: %v", err)
		}
		if err := json.Unmarshal(responseBody, &actualResponse); err != nil {
			t.Fatalf("Failed to unmarshal actual response: %v", err)
		}

		if !reflect.DeepEqual(expectedResponse, actualResponse) {
			t.Errorf(
				"Expected response %v, got %v",
				expectedResponse,
				actualResponse,
			)
		}
	})

}

func parseMetric(metricsData []byte, metricName string) float64 {
	lines := strings.Split(string(metricsData), "\n")
	for _, line := range lines {
		// Skip empty lines or comment lines that start with "#"
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}

		// Example lines we want to match:
		//   bursa_wallets_created_count 0

		if strings.HasPrefix(line, metricName) {
			parts := strings.Fields(line)
			if len(parts) == 2 {
				// parts[0] could be "bursa_wallets_created_count"
				// parts[1] is the numeric value string
				val, err := strconv.ParseFloat(parts[1], 64)
				if err == nil {
					return val
				}
			}
		}
	}
	// If the metric wasn't found
	return -1
}

func TestWalletCreateIncrementsCounter(t *testing.T) {
	// Start the API (includes metrics)
	apiBaseURL, metricsBaseURL, cleanup := startAPI(t)
	defer cleanup()

	// Fetch the metrics once to get the current count
	resp, err := http.Get(fmt.Sprintf("%s/metrics", metricsBaseURL))
	assert.NotEqual(t, resp, nil)
	assert.NoError(t, err, "failed to call initial metrics endpoint")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	initialBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	assert.NoError(t, err, "failed to read initial metrics response")

	initialCount := parseMetric(initialBody, "bursa_wallets_created_count")
	// If parseMetric returned -1, the metric wasn't found at all.
	assert.NotEqual(t, float64(-1), initialCount,
		"Expected `bursa_wallets_created_count` to be registered initially")

	// Call /api/wallet/create to create a wallet
	createWalletResp, err := http.Get(
		fmt.Sprintf("%s/api/wallet/create", apiBaseURL),
	)
	assert.NotEqual(t, createWalletResp, nil)
	assert.NoError(t, err, "failed to call /api/wallet/create endpoint")
	assert.Equal(t, http.StatusOK, createWalletResp.StatusCode,
		"expected /api/wallet/create to return 200 on success")
	createWalletResp.Body.Close()

	// Fetch the metrics again
	resp2, err := http.Get(fmt.Sprintf("%s/metrics", metricsBaseURL))
	assert.NotEqual(t, resp2, nil)
	assert.NoError(t, err, "failed to call second metrics endpoint")
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	secondBody, err := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	assert.NoError(t, err, "failed to read second metrics response")

	newCount := parseMetric(secondBody, "bursa_wallets_created_count")

	// Verify that the counter incremented by 1
	expected := initialCount + 1
	assert.Equal(
		t,
		expected,
		newCount,
		"bursa_wallets_created_count should have incremented by 1 after creating a wallet",
	)
}

func TestCreateWalletReturnsMnemonic(t *testing.T) {
	apiBaseURL, _, cleanup := startAPI(t)
	defer cleanup()

	resp, err := http.Get(fmt.Sprintf("%s/api/wallet/create", apiBaseURL))
	if resp == nil {
		t.Fatal("Failed calling /api/wallet/create")
	}
	if err != nil {
		t.Fatalf("Failed to call /api/wallet/create: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read create wallet response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", resp.StatusCode, string(body))
	}

	var createWalletResponse map[string]interface{}
	if err := json.Unmarshal(body, &createWalletResponse); err != nil {
		t.Fatalf("Failed to unmarshal create wallet response: %v", err)
	}

	mnemonicVal, ok := createWalletResponse["mnemonic"]
	if !ok {
		t.Errorf(
			"Expected key 'mnemonic' in createWalletResponse, but it was missing",
		)
	} else {
		mnemonicStr, isString := mnemonicVal.(string)
		if !isString || mnemonicStr == "" {
			t.Errorf("Expected 'mnemonic' to be a non-empty string, got %v", mnemonicVal)
		}
	}
}
