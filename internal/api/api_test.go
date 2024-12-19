package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
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
