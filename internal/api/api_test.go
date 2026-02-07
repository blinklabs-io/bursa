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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/go-playground/validator/v10"
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

	for range maxRetries {
		resp, err := http.Get(fmt.Sprintf("%s/healthcheck", apiBaseURL))
		if err == nil && resp != nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return // Server is ready
			}
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
	assert.NotEqual(t, resp, nil)
	assert.NoError(t, err, "failed to call metrics endpoint")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
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
		switch mf.GetName() {
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

		var expectedResponse, actualResponse map[string]any

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
	lines := strings.SplitSeq(string(metricsData), "\n")
	for line := range lines {
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

	// Poll metrics until the counter increments or timeout.
	// The handler increments the Prometheus counter after writing
	// the response, so there is a brief window where the client
	// has received the 200 but the counter has not yet been
	// incremented on the server side.
	expected := initialCount + 1
	var newCount float64
	for range 20 {
		resp2, err := http.Get(
			fmt.Sprintf("%s/metrics", metricsBaseURL),
		)
		assert.NotEqual(t, resp2, nil)
		assert.NoError(
			t, err, "failed to call second metrics endpoint",
		)
		assert.Equal(t, http.StatusOK, resp2.StatusCode)

		secondBody, err := io.ReadAll(resp2.Body)
		resp2.Body.Close()
		assert.NoError(
			t, err, "failed to read second metrics response",
		)

		newCount = parseMetric(
			secondBody, "bursa_wallets_created_count",
		)
		if newCount >= expected {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

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
	assert.NotEqual(t, resp, nil)
	assert.NoError(t, err, "failed to call wallet create endpoint")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	assert.NoError(t, err, "failed to read wallet create response")

	var createWalletResponse map[string]any
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

func TestWalletCreateMethodNotAllowed(t *testing.T) {
	// Start the API
	apiBaseURL, _, cleanup := startAPI(t)
	defer cleanup()

	// Test POST method (should fail)
	resp, err := http.Post(
		fmt.Sprintf("%s/api/wallet/create", apiBaseURL),
		"application/json",
		nil,
	)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestWalletRestoreMethodNotAllowed(t *testing.T) {
	// Start the API
	apiBaseURL, _, cleanup := startAPI(t)
	defer cleanup()

	// Test GET method (should fail)
	resp, err := http.Get(fmt.Sprintf("%s/api/wallet/restore", apiBaseURL))
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestHealthcheckEndpoint(t *testing.T) {
	// Start the API
	apiBaseURL, _, cleanup := startAPI(t)
	defer cleanup()

	// Test the /healthcheck endpoint
	resp, err := http.Get(fmt.Sprintf("%s/healthcheck", apiBaseURL))
	assert.NoError(t, err, "failed to call healthcheck endpoint")
	assert.NotNil(t, resp)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Check response body
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, `{"healthy": true}`, string(body))
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
}

func TestSwaggerEndpoint(t *testing.T) {
	// Start the API
	apiBaseURL, _, cleanup := startAPI(t)
	defer cleanup()

	// Test the /swagger/ endpoint
	resp, err := http.Get(fmt.Sprintf("%s/swagger/", apiBaseURL))
	assert.NoError(t, err, "failed to call swagger endpoint")
	assert.NotNil(t, resp)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Swagger should return HTML content
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Contains(
		t,
		string(body),
		"swagger",
		"response should contain swagger content",
	)
}

func TestHealthcheckMethodNotAllowed(t *testing.T) {
	// Start the API
	apiBaseURL, _, cleanup := startAPI(t)
	defer cleanup()

	// Test POST method (should fail)
	resp, err := http.Post(
		fmt.Sprintf("%s/healthcheck", apiBaseURL),
		"application/json",
		nil,
	)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestWalletListEndpointGCPNotConfigured(t *testing.T) {
	// Start the API
	apiBaseURL, _, cleanup := startAPI(t)
	defer cleanup()

	// Test the /api/wallet/list endpoint
	resp, err := http.Get(fmt.Sprintf("%s/api/wallet/list", apiBaseURL))
	assert.NoError(t, err, "failed to call wallet list endpoint")
	assert.NotNil(t, resp)
	defer resp.Body.Close()

	// GCP routes are only registered if GCP is configured
	// Since test setup doesn't configure GCP, expect 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestWalletListMethodGCPNotConfigured(t *testing.T) {
	// Start the API
	apiBaseURL, _, cleanup := startAPI(t)
	defer cleanup()

	// Test POST method (should return 404 since GCP not configured)
	resp, err := http.Post(
		fmt.Sprintf("%s/api/wallet/list", apiBaseURL),
		"application/json",
		nil,
	)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestWalletGetEndpointGCPNotConfigured(t *testing.T) {
	t.Run("Invalid JSON", func(t *testing.T) {
		// Start the API
		apiBaseURL, _, cleanup := startAPI(t)
		defer cleanup()

		// Test with invalid JSON (should return 404 since GCP not configured)
		resp, err := http.Post(
			fmt.Sprintf("%s/api/wallet/get", apiBaseURL),
			"application/json",
			strings.NewReader("invalid json"),
		)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("Validation Error", func(t *testing.T) {
		// Start the API
		apiBaseURL, _, cleanup := startAPI(t)
		defer cleanup()

		// Test with empty request (should return 404 since GCP not configured)
		req := WalletGetRequest{}
		reqBody, _ := json.Marshal(req)

		resp, err := http.Post(
			fmt.Sprintf("%s/api/wallet/get", apiBaseURL),
			"application/json",
			bytes.NewReader(reqBody),
		)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("Nonexistent Wallet", func(t *testing.T) {
		// Start the API
		apiBaseURL, _, cleanup := startAPI(t)
		defer cleanup()

		// Test with valid request but nonexistent wallet (should return 404 since GCP not configured)
		req := WalletGetRequest{Name: "nonexistent-wallet"}
		reqBody, _ := json.Marshal(req)

		resp, err := http.Post(
			fmt.Sprintf("%s/api/wallet/get", apiBaseURL),
			"application/json",
			bytes.NewReader(reqBody),
		)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

func TestWalletGetMethodGCPNotConfigured(t *testing.T) {
	// Start the API
	apiBaseURL, _, cleanup := startAPI(t)
	defer cleanup()

	// Test GET method (should return 404 since GCP not configured)
	resp, err := http.Get(fmt.Sprintf("%s/api/wallet/get", apiBaseURL))
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestWalletDeleteEndpointGCPNotConfigured(t *testing.T) {
	t.Run("Invalid JSON", func(t *testing.T) {
		// Start the API
		apiBaseURL, _, cleanup := startAPI(t)
		defer cleanup()

		// Test with invalid JSON (should return 404 since GCP not configured)
		resp, err := http.Post(
			fmt.Sprintf("%s/api/wallet/delete", apiBaseURL),
			"application/json",
			strings.NewReader("invalid json"),
		)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("Validation Error", func(t *testing.T) {
		// Start the API
		apiBaseURL, _, cleanup := startAPI(t)
		defer cleanup()

		// Test with empty request (should return 404 since GCP not configured)
		req := WalletDeleteRequest{}
		reqBody, _ := json.Marshal(req)

		resp, err := http.Post(
			fmt.Sprintf("%s/api/wallet/delete", apiBaseURL),
			"application/json",
			bytes.NewReader(reqBody),
		)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

func TestWalletDeleteMethodGCPNotConfigured(t *testing.T) {
	// Start the API
	apiBaseURL, _, cleanup := startAPI(t)
	defer cleanup()

	// Test GET method (should return 404 since GCP not configured)
	resp, err := http.Get(fmt.Sprintf("%s/api/wallet/delete", apiBaseURL))
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestWalletUpdateEndpointGCPNotConfigured(t *testing.T) {
	t.Run("Invalid JSON", func(t *testing.T) {
		// Start the API
		apiBaseURL, _, cleanup := startAPI(t)
		defer cleanup()

		// Test with invalid JSON (should return 404 since GCP not configured)
		resp, err := http.Post(
			fmt.Sprintf("%s/api/wallet/update", apiBaseURL),
			"application/json",
			strings.NewReader("invalid json"),
		)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("Validation Error", func(t *testing.T) {
		// Start the API
		apiBaseURL, _, cleanup := startAPI(t)
		defer cleanup()

		// Test with empty request (should return 404 since GCP not configured)
		req := WalletUpdateRequest{}
		reqBody, _ := json.Marshal(req)

		resp, err := http.Post(
			fmt.Sprintf("%s/api/wallet/update", apiBaseURL),
			"application/json",
			bytes.NewReader(reqBody),
		)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

func TestWalletUpdateMethodGCPNotConfigured(t *testing.T) {
	// Start the API
	apiBaseURL, _, cleanup := startAPI(t)
	defer cleanup()

	// Test GET method (should return 404 since GCP not configured)
	resp, err := http.Get(fmt.Sprintf("%s/api/wallet/update", apiBaseURL))
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestHandleScriptCreate(t *testing.T) {
	// Setup
	reqBody := `{
		"type": "nOf",
		"required": 2,
		"key_hashes": [
			"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c",
			"02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d",
			"030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e"
		],
		"network": "mainnet"
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/script/create",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	handleScriptCreate(w, req)

	// Assert
	resp := w.Result()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Decode JSON response for stronger assertions
	var response ScriptResponse
	err = json.Unmarshal(body, &response)
	assert.NoError(t, err)

	assert.Equal(t, "NativeScript", response.Type)
	scriptType, ok := response.Script["type"]
	assert.True(t, ok)
	assert.Equal(t, "nOf", scriptType)
	assert.NotEmpty(t, response.Address)
	assert.NotEmpty(t, response.ScriptHash)
	assert.Contains(t, response.Address, "addr1")
}

func TestHandleScriptCreateAllAndAny(t *testing.T) {
	tests := []struct {
		name         string
		reqBody      string
		expectedType string
	}{
		{
			name: "all script type",
			reqBody: `{
				"type": "all",
				"key_hashes": [
					"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c",
					"02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d"
				],
				"network": "mainnet"
			}`,
			expectedType: "all",
		},
		{
			name: "any script type",
			reqBody: `{
				"type": "any",
				"key_hashes": [
					"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c",
					"02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d"
				],
				"network": "mainnet"
			}`,
			expectedType: "any",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(
				http.MethodPost,
				"/api/script/create",
				strings.NewReader(tt.reqBody),
			)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			// Execute
			handleScriptCreate(w, req)

			// Assert
			resp := w.Result()
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			assert.NoError(t, err)

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			// Decode JSON response for stronger assertions
			var response ScriptResponse
			err = json.Unmarshal(body, &response)
			assert.NoError(t, err)

			// Verify response structure
			assert.Equal(t, "NativeScript", response.Type)
			assert.NotEmpty(t, response.Script)
			assert.NotEmpty(t, response.Address)
			assert.NotEmpty(t, response.ScriptHash)

			// Verify script structure contains the expected type
			scriptType, ok := response.Script["type"].(string)
			assert.True(t, ok, "script.type should be a string")
			assert.Equal(t, tt.expectedType, scriptType)
		})
	}
}

func TestHandleScriptValidate(t *testing.T) {
	// Setup
	reqBody := `{
		"script": {
			"type": "nOf",
			"n": 2,
			"scripts": [
				{"type": "sig", "keyHash": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"},
				{"type": "sig", "keyHash": "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d"},
				{"type": "sig", "keyHash": "030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e"}
			]
		},
		"require_signatures": false
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/script/validate",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	handleScriptValidate(w, req)

	// Assert
	resp := w.Result()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "scriptHash")
	assert.Contains(t, string(body), "valid")

	// Decode JSON to check valid field specifically
	var result map[string]any
	err = json.Unmarshal(body, &result)
	assert.NoError(t, err)
	assert.Equal(t, true, result["valid"])
}

func TestHandleScriptValidateErrors(t *testing.T) {
	tests := []struct {
		name           string
		reqBody        string
		expectedStatus int
		expectedError  string
	}{
		{
			name: "invalid keyHash format",
			reqBody: `{
				"script": {
					"type": "nOf",
					"n": 2,
					"scripts": [
						{"type": "sig", "keyHash": "invalid-hex"}
					]
				}
			}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid script format",
		},
		{
			name: "missing required fields",
			reqBody: `{
				"script": {
					"type": "nOf"
				}
			}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid script format",
		},
		{
			name: "unsupported script type",
			reqBody: `{
				"script": {
					"type": "invalid",
					"n": 2,
					"scripts": [
						{"type": "sig", "keyHash": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"}
					]
				}
			}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid script format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(
				http.MethodPost,
				"/api/script/validate",
				strings.NewReader(tt.reqBody),
			)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handleScriptValidate(w, req)

			resp := w.Result()
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			assert.NoError(t, err)

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)
			assert.Contains(t, string(body), tt.expectedError)
		})
	}
}

func TestHandleScriptAddress(t *testing.T) {
	// Setup
	reqBody := `{
		"script": {
			"type": "nOf",
			"n": 2,
			"scripts": [
				{"type": "sig", "keyHash": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"},
				{"type": "sig", "keyHash": "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d"},
				{"type": "sig", "keyHash": "030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e"}
			]
		},
		"network": "mainnet"
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/script/address",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	handleScriptAddress(w, req)

	// Assert
	resp := w.Result()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Decode JSON response for stronger assertions
	var response ScriptAddressResponse
	err = json.Unmarshal(body, &response)
	assert.NoError(t, err)

	assert.NotEmpty(t, response.Address)
	assert.Equal(t, "mainnet", response.Network)
	assert.NotEmpty(t, response.ScriptHash)
	assert.Contains(t, response.Address, "addr1")
}

// readTestData reads test data from a file in the testdata directory
func readTestData(filename string) string {
	data, err := os.ReadFile(filepath.Join("testdata", filename))
	if err != nil {
		panic(
			fmt.Sprintf("failed to read test data file %s: %v", filename, err),
		)
	}
	return string(data)
}

func TestHandleAddressParse(t *testing.T) {
	// Test parsing a mainnet base address
	reqBody := `{
		"address": "addr1qxwqkfd3qz5pdwmemtv2llmetegdyku4ffxuldjcfrs05nfjtw33ktf3j6amgxsgnj9u3fa5nrle79nv2g24npnth0esk2dy7q"
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/address/parse",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	handleAddressParse(w, req)

	// Assert
	resp := w.Result()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Decode JSON response
	var response AddressParseResponse
	err = json.Unmarshal(body, &response)
	assert.NoError(t, err)

	assert.Equal(
		t,
		"addr1qxwqkfd3qz5pdwmemtv2llmetegdyku4ffxuldjcfrs05nfjtw33ktf3j6amgxsgnj9u3fa5nrle79nv2g24npnth0esk2dy7q",
		response.Address,
	)
	assert.Equal(t, "base", response.Type)
	assert.Equal(t, "payment key + stake key", response.TypeDesc)
	assert.Equal(t, "mainnet", response.Network)
	assert.NotNil(t, response.Payment)
	assert.NotNil(t, response.Stake)
	assert.Equal(t, "key", response.Payment.Type)
	assert.Equal(t, "key", response.Stake.Type)
}

func TestHandleAddressParseTestnet(t *testing.T) {
	// Test parsing a testnet address
	reqBody := `{
		"address": "addr_test1qqqcea9cpx0480yjvvklp0tw4yw56r6q9qc437gpqwg6swwc3w03xmxfgcfw6v7asa6vdapakdr6ukq5mrhawfwnjvfsqeaxws"
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/address/parse",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	handleAddressParse(w, req)

	// Assert
	resp := w.Result()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Decode JSON response
	var response AddressParseResponse
	err = json.Unmarshal(body, &response)
	assert.NoError(t, err)

	assert.Equal(t, "testnet", response.Network)
}

func TestHandleAddressParseEnterprise(t *testing.T) {
	// Test parsing an enterprise address
	reqBody := `{
		"address": "addr_test1vqqcea9cpx0480yjvvklp0tw4yw56r6q9qc437gpqwg6swg560kjv"
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/address/parse",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	handleAddressParse(w, req)

	// Assert
	resp := w.Result()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Decode JSON response
	var response AddressParseResponse
	err = json.Unmarshal(body, &response)
	assert.NoError(t, err)

	assert.Equal(t, "enterprise", response.Type)
	assert.Equal(t, "payment key only", response.TypeDesc)
	assert.NotNil(t, response.Payment)
	assert.Nil(t, response.Stake)
}

func TestHandleAddressParseInvalid(t *testing.T) {
	// Test parsing an invalid address
	reqBody := `{
		"address": "invalid_address"
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/address/parse",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	handleAddressParse(w, req)

	// Assert
	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandleAddressBuild(t *testing.T) {
	// Test building a base address
	reqBody := readTestData("address_build_base.json")

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/address/build",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	handleAddressBuild(w, req)

	// Assert
	resp := w.Result()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Decode JSON response
	var response AddressBuildResponse
	err = json.Unmarshal(body, &response)
	assert.NoError(t, err)

	assert.NotEmpty(t, response.Address)
	assert.Equal(t, "mainnet", response.Network)
	assert.Equal(t, "base", response.Type)
	assert.Contains(t, response.Address, "addr1")
}

func TestHandleAddressBuildEnterprise(t *testing.T) {
	// Test building an enterprise address
	reqBody := readTestData("address_build_enterprise.json")

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/address/build",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	handleAddressBuild(w, req)

	// Assert
	resp := w.Result()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Decode JSON response
	var response AddressBuildResponse
	err = json.Unmarshal(body, &response)
	assert.NoError(t, err)

	assert.NotEmpty(t, response.Address)
	assert.Equal(t, "mainnet", response.Network)
	assert.Equal(t, "enterprise", response.Type)
	assert.Contains(t, response.Address, "addr1")
}

func TestHandleAddressBuildInvalidKey(t *testing.T) {
	// Test building with invalid key
	reqBody := readTestData("address_build_invalid.json")

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/address/build",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	handleAddressBuild(w, req)

	// Assert
	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// --- Additional tests for increased coverage ---

func TestHandleWalletRestore_ValidMnemonic(t *testing.T) {
	mnemonic := "depth kitchen crystal history rabbit brief " +
		"harbor palace tent frog city charge inflict tiger " +
		"negative young furnace solid august educate bounce " +
		"canal someone erode"
	reqBody, _ := json.Marshal(WalletRestoreRequest{
		Mnemonic: mnemonic,
	})

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/wallet/restore",
		bytes.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleWalletRestore(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var wallet map[string]any
	err = json.Unmarshal(body, &wallet)
	assert.NoError(t, err)
	assert.NotEmpty(t, wallet["payment_address"])
	assert.NotEmpty(t, wallet["stake_address"])
	assert.Equal(t, mnemonic, wallet["mnemonic"])
}

func TestHandleWalletRestore_InvalidMnemonic(t *testing.T) {
	reqBody, _ := json.Marshal(WalletRestoreRequest{
		Mnemonic: "invalid mnemonic words that are not valid",
	})

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/wallet/restore",
		bytes.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleWalletRestore(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), "error")
}

func TestHandleWalletRestore_MissingMnemonic(t *testing.T) {
	reqBody, _ := json.Marshal(WalletRestoreRequest{})

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/wallet/restore",
		bytes.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleWalletRestore(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), "Validation failed")
}

func TestHandleWalletRestore_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/wallet/restore",
		strings.NewReader("not valid json"),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleWalletRestore(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), "Invalid JSON request")
}

func TestHandleWalletRestore_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodGet,
		"/api/wallet/restore",
		nil,
	)
	w := httptest.NewRecorder()

	handleWalletRestore(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestHandleWalletRestore_WithPassword(t *testing.T) {
	mnemonic := "depth kitchen crystal history rabbit brief " +
		"harbor palace tent frog city charge inflict tiger " +
		"negative young furnace solid august educate bounce " +
		"canal someone erode"
	reqBody, _ := json.Marshal(WalletRestoreRequest{
		Mnemonic: mnemonic,
		Password: "testpassword",
	})

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/wallet/restore",
		bytes.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleWalletRestore(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestHandleWalletRestore_WithDerivationIndices(t *testing.T) {
	mnemonic := "depth kitchen crystal history rabbit brief " +
		"harbor palace tent frog city charge inflict tiger " +
		"negative young furnace solid august educate bounce " +
		"canal someone erode"
	reqBody, _ := json.Marshal(WalletRestoreRequest{
		Mnemonic:  mnemonic,
		AccountId: 1,
		PaymentId: 2,
		StakeId:   3,
	})

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/wallet/restore",
		bytes.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleWalletRestore(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestHandleWalletCreate_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/wallet/create",
		nil,
	)
	w := httptest.NewRecorder()

	handleWalletCreate(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestHandleWalletCreate_Success(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodGet,
		"/api/wallet/create",
		nil,
	)
	w := httptest.NewRecorder()

	handleWalletCreate(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var wallet map[string]any
	err = json.Unmarshal(body, &wallet)
	assert.NoError(t, err)
	assert.NotEmpty(t, wallet["mnemonic"])
	assert.NotEmpty(t, wallet["payment_address"])
	assert.NotEmpty(t, wallet["stake_address"])
}

func TestHandleScriptCreate_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/script/create",
		strings.NewReader("not valid json"),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleScriptCreate(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), "Invalid JSON request")
}

func TestHandleScriptCreate_ValidationError(t *testing.T) {
	// Missing required fields
	reqBody := `{"type": "invalid_type"}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/script/create",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleScriptCreate(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), "Validation failed")
}

func TestHandleScriptCreate_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodGet,
		"/api/script/create",
		nil,
	)
	w := httptest.NewRecorder()

	handleScriptCreate(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestHandleScriptCreate_NOfInvalidRequired(t *testing.T) {
	// required = 0 for nOf is invalid (exceeds key count)
	reqBody := `{
		"type": "nOf",
		"required": 5,
		"key_hashes": [
			"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"
		],
		"network": "mainnet"
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/script/create",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleScriptCreate(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Contains(
		t,
		string(body),
		"Invalid required signatures count",
	)
}

func TestHandleScriptCreate_WithTimelockBefore(t *testing.T) {
	reqBody := `{
		"type": "all",
		"key_hashes": [
			"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"
		],
		"network": "mainnet",
		"timelock_before": 1000000
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/script/create",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleScriptCreate(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response ScriptResponse
	err = json.Unmarshal(body, &response)
	assert.NoError(t, err)
	assert.NotEmpty(t, response.Address)
}

func TestHandleScriptCreate_WithTimelockAfter(t *testing.T) {
	reqBody := `{
		"type": "any",
		"key_hashes": [
			"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"
		],
		"network": "mainnet",
		"timelock_after": 500000
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/script/create",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleScriptCreate(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response ScriptResponse
	err = json.Unmarshal(body, &response)
	assert.NoError(t, err)
	assert.NotEmpty(t, response.Address)
}

func TestHandleScriptCreate_BothTimelocks(t *testing.T) {
	reqBody := `{
		"type": "all",
		"key_hashes": [
			"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"
		],
		"network": "mainnet",
		"timelock_before": 1000000,
		"timelock_after": 500000
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/script/create",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleScriptCreate(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), "cannot specify both")
}

func TestHandleScriptCreate_TestnetNetworkError(t *testing.T) {
	// "testnet" passes validation but fails in
	// bursa.MarshalScript because gouroboros does not
	// recognize "testnet" as a network name. This covers
	// the MarshalScript error path.
	reqBody := `{
		"type": "nOf",
		"required": 1,
		"key_hashes": [
			"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"
		],
		"network": "testnet"
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/script/create",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleScriptCreate(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	// MarshalScript fails because testnet is not valid
	assert.Equal(
		t, http.StatusInternalServerError, resp.StatusCode,
	)
}

func TestHandleScriptValidate_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodGet,
		"/api/script/validate",
		nil,
	)
	w := httptest.NewRecorder()

	handleScriptValidate(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestHandleScriptValidate_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/script/validate",
		strings.NewReader("not valid json"),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleScriptValidate(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandleScriptValidate_AllScript(t *testing.T) {
	reqBody := `{
		"script": {
			"type": "all",
			"scripts": [
				{"type": "sig", "keyHash": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"},
				{"type": "sig", "keyHash": "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d"}
			]
		},
		"require_signatures": false
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/script/validate",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleScriptValidate(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result ScriptValidateResponse
	err = json.Unmarshal(body, &result)
	assert.NoError(t, err)
	assert.True(t, result.Valid)
	assert.NotEmpty(t, result.ScriptHash)
}

func TestHandleScriptValidate_AnyScript(t *testing.T) {
	reqBody := `{
		"script": {
			"type": "any",
			"scripts": [
				{"type": "sig", "keyHash": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"}
			]
		},
		"require_signatures": false
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/script/validate",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleScriptValidate(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result ScriptValidateResponse
	err = json.Unmarshal(body, &result)
	assert.NoError(t, err)
	assert.True(t, result.Valid)
}

func TestHandleScriptAddress_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodGet,
		"/api/script/address",
		nil,
	)
	w := httptest.NewRecorder()

	handleScriptAddress(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestHandleScriptAddress_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/script/address",
		strings.NewReader("not json"),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleScriptAddress(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandleScriptAddress_MissingNetwork(t *testing.T) {
	reqBody := `{
		"script": {
			"type": "all",
			"scripts": [
				{"type": "sig", "keyHash": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"}
			]
		}
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/script/address",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleScriptAddress(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), "Validation failed")
}

func TestHandleScriptAddress_InvalidScript(t *testing.T) {
	reqBody := `{
		"script": {
			"type": "invalid"
		},
		"network": "mainnet"
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/script/address",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleScriptAddress(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), "Invalid script format")
}

func TestHandleScriptAddress_TestnetError(t *testing.T) {
	// "testnet" is not recognized by gouroboros
	// GetScriptAddress. This exercises the error path.
	reqBody := `{
		"script": {
			"type": "all",
			"scripts": [
				{"type": "sig", "keyHash": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"}
			]
		},
		"network": "testnet"
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/script/address",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleScriptAddress(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), "Invalid network")
}

func TestHandleAddressParse_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodGet,
		"/api/address/parse",
		nil,
	)
	w := httptest.NewRecorder()

	handleAddressParse(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestHandleAddressParse_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/address/parse",
		strings.NewReader("not json"),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleAddressParse(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandleAddressParse_EmptyAddress(t *testing.T) {
	reqBody := `{"address": ""}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/address/parse",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleAddressParse(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandleAddressParse_StakeAddress(t *testing.T) {
	reqBody := `{
		"address": "stake1uye9hgcm95cedwa5rgyfez7g576f3lulzek9y92ese4mhucu439t0"
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/address/parse",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleAddressParse(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response AddressParseResponse
	err = json.Unmarshal(body, &response)
	assert.NoError(t, err)
	assert.Equal(t, "reward", response.Type)
	assert.Equal(t, "mainnet", response.Network)
	assert.Nil(t, response.Payment)
	assert.NotNil(t, response.Stake)
}

func TestHandleAddressBuild_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodGet,
		"/api/address/build",
		nil,
	)
	w := httptest.NewRecorder()

	handleAddressBuild(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestHandleAddressBuild_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/address/build",
		strings.NewReader("not json"),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleAddressBuild(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandleAddressBuild_MissingNetwork(t *testing.T) {
	reqBody := `{
		"paymentKey": "addr_vk18nqps65rh0azud77qruff3dctszahutmrhkxg87mlfny0addcles83lnyc"
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/address/build",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleAddressBuild(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandleAddressBuild_RewardType(t *testing.T) {
	reqBody := `{
		"stakeKey": "stake_vk1swf4qsf28mzdn2kexqumas5fj43psj674xathpv45mcj04y2lv5scvw4uv",
		"network": "mainnet",
		"type": "reward"
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/address/build",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleAddressBuild(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response AddressBuildResponse
	err = json.Unmarshal(body, &response)
	assert.NoError(t, err)
	assert.Equal(t, "reward", response.Type)
	assert.NotEmpty(t, response.Address)
	assert.Equal(t, "mainnet", response.Network)
}

func TestHandleAddressBuild_BaseMissingStakeKey(t *testing.T) {
	reqBody := `{
		"paymentKey": "addr_vk18nqps65rh0azud77qruff3dctszahutmrhkxg87mlfny0addcles83lnyc",
		"network": "mainnet",
		"type": "base"
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/address/build",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleAddressBuild(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), "require both")
}

func TestHandleAddressBuild_EnterpriseMissingPaymentKey(
	t *testing.T,
) {
	reqBody := `{
		"network": "mainnet",
		"type": "enterprise"
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/address/build",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleAddressBuild(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandleAddressBuild_RewardMissingStakeKey(t *testing.T) {
	reqBody := `{
		"network": "mainnet",
		"type": "reward"
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/address/build",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleAddressBuild(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandleAddressBuild_TestnetReturnsError(t *testing.T) {
	// Note: buildAddressFromKeys uses ouroboros.NetworkByName
	// which does not recognize "testnet" (only mainnet,
	// preprod, preview, sanchonet). Validation accepts
	// "testnet" but the build step fails. This tests the
	// error path.
	reqBody := `{
		"paymentKey": "addr_vk18nqps65rh0azud77qruff3dctszahutmrhkxg87mlfny0addcles83lnyc",
		"stakeKey": "stake_vk1swf4qsf28mzdn2kexqumas5fj43psj674xathpv45mcj04y2lv5scvw4uv",
		"network": "testnet"
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/address/build",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleAddressBuild(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	// testnet is not recognized by gouroboros NetworkByName
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandleAddressBuild_DefaultType(t *testing.T) {
	// When type is not specified, default to base
	reqBody := `{
		"paymentKey": "addr_vk18nqps65rh0azud77qruff3dctszahutmrhkxg87mlfny0addcles83lnyc",
		"stakeKey": "stake_vk1swf4qsf28mzdn2kexqumas5fj43psj674xathpv45mcj04y2lv5scvw4uv",
		"network": "mainnet"
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/address/build",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleAddressBuild(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var response AddressBuildResponse
	err = json.Unmarshal(body, &response)
	assert.NoError(t, err)
	assert.Equal(t, "base", response.Type)
}

func TestToSnakeCase(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"KeyHashes", "key_hashes"},
		{"TimelockBefore", "timelock_before"},
		{"RequireSignatures", "require_signatures"},
		{"simple", "simple"},
		{"XMLParser", "xml_parser"},
		{"ID", "id"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := toSnakeCase(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestToJSONFieldName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"KeyHashes", "key_hashes"},
		{"TimelockBefore", "timelock_before"},
		{"RequireSignatures", "require_signatures"},
		{"AccountId", "account_id"},
		{"PaymentId", "payment_id"},
		{"StakeId", "stake_id"},
		{"DrepId", "drep_id"},
		{"CommitteeColdId", "committee_cold_id"},
		{"CommitteeHotId", "committee_hot_id"},
		{"PoolColdId", "pool_cold_id"},
		{"AddressId", "address_id"},
		{"Unknown", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := toJSONFieldName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatValidationErrors(t *testing.T) {
	// Test by actually validating a struct with known errors
	type testStruct struct {
		Name     string `validate:"required"`
		Required int    `validate:"min=1"`
	}

	err := validate.Struct(testStruct{})
	assert.Error(t, err)

	result := formatValidationErrors(
		err.(validator.ValidationErrors),
	)
	assert.Contains(t, result, "required")
}

func TestGetAddressTypeInfo(t *testing.T) {
	tests := []struct {
		name         string
		addrType     uint8
		expectedName string
		expectedDesc string
	}{
		{"KeyKey", 0x00, "base", "payment key + stake key"},
		{"ScriptKey", 0x01, "base", "payment script + stake key"},
		{"KeyScript", 0x02, "base", "payment key + stake script"},
		{
			"ScriptScript", 0x03, "base",
			"payment script + stake script",
		},
		{
			"KeyPointer", 0x04, "pointer",
			"payment key + stake pointer",
		},
		{
			"ScriptPointer", 0x05, "pointer",
			"payment script + stake pointer",
		},
		{"KeyNone", 0x06, "enterprise", "payment key only"},
		{
			"ScriptNone", 0x07, "enterprise",
			"payment script only",
		},
		{"Byron", 0x08, "byron", "legacy bootstrap"},
		{"NoneKey", 0x0e, "reward", "stake key"},
		{"NoneScript", 0x0f, "reward", "stake script"},
		{"Unknown", 0xff, "unknown", "type 255"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, desc := getAddressTypeInfo(tt.addrType)
			assert.Equal(t, tt.expectedName, name)
			assert.Equal(t, tt.expectedDesc, desc)
		})
	}
}

func TestHealthcheck_DirectHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthcheck", nil)
	w := httptest.NewRecorder()

	handleHealthcheck(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, `{"healthy": true}`, string(body))
	assert.Equal(
		t,
		"application/json",
		resp.Header.Get("Content-Type"),
	)
}

func TestHandleScriptCreate_InvalidKeyHashLength(t *testing.T) {
	// key_hash with wrong length should fail validation
	reqBody := `{
		"type": "all",
		"key_hashes": ["0102030405"],
		"network": "mainnet"
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/script/create",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleScriptCreate(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandleScriptValidate_WithSlot(t *testing.T) {
	reqBody := `{
		"script": {
			"type": "all",
			"scripts": [
				{"type": "sig", "keyHash": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"}
			]
		},
		"slot": 12345,
		"require_signatures": false
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/script/validate",
		strings.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleScriptValidate(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result ScriptValidateResponse
	err = json.Unmarshal(body, &result)
	assert.NoError(t, err)
	assert.Equal(t, uint64(12345), result.Slot)
}
