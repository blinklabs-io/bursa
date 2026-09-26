/*
bursa

Testing DefaultAPIService
*/

package openapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	openapiclient "github.com/blinklabs-io/bursa/openapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordedRequest captures what the stub server received, so a test can assert
// on the method, path and body the generated client actually produced rather
// than only on the value it decoded back.
type recordedRequest struct {
	method string
	path   string
	body   []byte
}

// newStubServer serves one canned response and records the request. The
// generated client is exercised against this rather than a live bursa, so the
// tests need no network, no keys and no running server.
func newStubServer(
	t *testing.T,
	status int,
	responseBody string,
) (*httptest.Server, *recordedRequest) {
	t.Helper()
	recorded := &recordedRequest{}
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			recorded.method = r.Method
			recorded.path = r.URL.Path
			recorded.body = body
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(responseBody))
		}),
	)
	t.Cleanup(server.Close)
	return server, recorded
}

func newTestClient(
	t *testing.T,
	serverURL string,
) *openapiclient.APIClient {
	t.Helper()
	configuration := openapiclient.NewConfiguration()
	configuration.Servers = openapiclient.ServerConfigurations{
		{URL: serverURL},
	}
	return openapiclient.NewAPIClient(configuration)
}

func decodeBody(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded))
	return decoded
}

func TestApiWalletCreatePost(t *testing.T) {
	server, recorded := newStubServer(
		t,
		http.StatusOK,
		`{"payment_address":"addr_test1payment",`+
			`"stake_address":"stake_test1stake"}`,
	)
	client := newTestClient(t, server.URL)

	resp, httpRes, err := client.DefaultAPI.
		ApiWalletCreatePost(context.Background()).
		Execute()

	require.NoError(t, err)
	require.NotNil(t, httpRes)
	defer httpRes.Body.Close()
	assert.Equal(t, http.StatusOK, httpRes.StatusCode)
	assert.Equal(t, http.MethodPost, recorded.method)
	assert.Equal(t, "/api/wallet/create", recorded.path)
	require.NotNil(t, resp)
	assert.Equal(t, "addr_test1payment", resp.GetPaymentAddress())
	assert.Equal(t, "stake_test1stake", resp.GetStakeAddress())
}

func TestApiWalletListGet(t *testing.T) {
	server, recorded := newStubServer(
		t,
		http.StatusOK,
		`["alpha","beta"]`,
	)
	client := newTestClient(t, server.URL)

	resp, httpRes, err := client.DefaultAPI.
		ApiWalletListGet(context.Background()).
		Execute()

	require.NoError(t, err)
	require.NotNil(t, httpRes)
	defer httpRes.Body.Close()
	assert.Equal(t, http.StatusOK, httpRes.StatusCode)
	assert.Equal(t, http.MethodGet, recorded.method)
	assert.Equal(t, "/api/wallet/list", recorded.path)
	assert.Equal(t, []string{"alpha", "beta"}, resp)
}

func TestApiWalletGetPost(t *testing.T) {
	server, recorded := newStubServer(
		t,
		http.StatusOK,
		`{"payment_address":"addr_test1payment"}`,
	)
	client := newTestClient(t, server.URL)

	resp, httpRes, err := client.DefaultAPI.
		ApiWalletGetPost(context.Background()).
		Request(*openapiclient.NewApiWalletGetRequest("primary")).
		Execute()

	require.NoError(t, err)
	require.NotNil(t, httpRes)
	defer httpRes.Body.Close()
	assert.Equal(t, http.StatusOK, httpRes.StatusCode)
	assert.Equal(t, http.MethodPost, recorded.method)
	assert.Equal(t, "/api/wallet/get", recorded.path)
	assert.Equal(
		t,
		map[string]any{"name": "primary"},
		decodeBody(t, recorded.body),
	)
	require.NotNil(t, resp)
	assert.Equal(t, "addr_test1payment", resp.GetPaymentAddress())
}

// The handler writes the JSON string `"OK"`. For a string return type the
// generated decode copies the raw body instead of unmarshalling it, so the
// quotes reach the caller; assert the contract as it actually is.
func TestApiWalletDeletePost(t *testing.T) {
	server, recorded := newStubServer(t, http.StatusOK, `"OK"`)
	client := newTestClient(t, server.URL)

	resp, httpRes, err := client.DefaultAPI.
		ApiWalletDeletePost(context.Background()).
		Request(*openapiclient.NewApiWalletDeleteRequest("primary")).
		Execute()

	require.NoError(t, err)
	require.NotNil(t, httpRes)
	defer httpRes.Body.Close()
	assert.Equal(t, http.StatusOK, httpRes.StatusCode)
	assert.Equal(t, http.MethodPost, recorded.method)
	assert.Equal(t, "/api/wallet/delete", recorded.path)
	assert.Equal(
		t,
		map[string]any{"name": "primary"},
		decodeBody(t, recorded.body),
	)
	assert.Equal(t, `"OK"`, resp)
}

func TestApiWalletUpdatePost(t *testing.T) {
	server, recorded := newStubServer(t, http.StatusOK, `"OK"`)
	client := newTestClient(t, server.URL)

	request := openapiclient.NewApiWalletUpdateRequest("primary")
	request.SetDescription("spending wallet")

	resp, httpRes, err := client.DefaultAPI.
		ApiWalletUpdatePost(context.Background()).
		Request(*request).
		Execute()

	require.NoError(t, err)
	require.NotNil(t, httpRes)
	defer httpRes.Body.Close()
	assert.Equal(t, http.StatusOK, httpRes.StatusCode)
	assert.Equal(t, http.MethodPost, recorded.method)
	assert.Equal(t, "/api/wallet/update", recorded.path)
	assert.Equal(
		t,
		map[string]any{
			"name":        "primary",
			"description": "spending wallet",
		},
		decodeBody(t, recorded.body),
	)
	assert.Equal(t, `"OK"`, resp)
}

func TestApiWalletRestorePost(t *testing.T) {
	server, recorded := newStubServer(
		t,
		http.StatusOK,
		`{"payment_address":"addr_test1restored"}`,
	)
	client := newTestClient(t, server.URL)

	// Not a BIP39 phrase. The generated client does not validate the field,
	// so a placeholder keeps a real recovery phrase out of the repository.
	restore := openapiclient.NewApiWalletRestoreRequest("placeholder-value")

	resp, httpRes, err := client.DefaultAPI.
		ApiWalletRestorePost(context.Background()).
		Request(*restore).
		Execute()

	require.NoError(t, err)
	require.NotNil(t, httpRes)
	defer httpRes.Body.Close()
	assert.Equal(t, http.StatusOK, httpRes.StatusCode)
	assert.Equal(t, http.MethodPost, recorded.method)
	assert.Equal(t, "/api/wallet/restore", recorded.path)
	assert.Equal(
		t,
		"placeholder-value",
		decodeBody(t, recorded.body)["mnemonic"],
	)
	require.NotNil(t, resp)
	assert.Equal(t, "addr_test1restored", resp.GetPaymentAddress())
}

// A required body that was never set must fail before any request is sent, so
// the stub server records nothing at all.
func TestApiWalletGetPostRequiresRequestBody(t *testing.T) {
	server, recorded := newStubServer(t, http.StatusOK, `{}`)
	client := newTestClient(t, server.URL)

	_, httpRes, err := client.DefaultAPI.
		ApiWalletGetPost(context.Background()).
		Execute()

	require.Error(t, err)
	assert.Nil(t, httpRes)
	assert.Contains(t, err.Error(), "request is required")
	assert.Empty(t, recorded.method)
}

// A non-2xx status must surface as a GenericOpenAPIError carrying the decoded
// ApiErrorResponse, while still returning the response for status inspection.
func TestApiWalletGetPostErrorResponse(t *testing.T) {
	server, _ := newStubServer(
		t,
		http.StatusBadRequest,
		`{"error":"wallet not found"}`,
	)
	client := newTestClient(t, server.URL)

	_, httpRes, err := client.DefaultAPI.
		ApiWalletGetPost(context.Background()).
		Request(*openapiclient.NewApiWalletGetRequest("missing")).
		Execute()

	require.Error(t, err)
	require.NotNil(t, httpRes)
	defer httpRes.Body.Close()
	assert.Equal(t, http.StatusBadRequest, httpRes.StatusCode)

	var apiErr *openapiclient.GenericOpenAPIError
	require.ErrorAs(t, err, &apiErr)
	model, ok := apiErr.Model().(openapiclient.ApiErrorResponse)
	require.True(t, ok)
	assert.Equal(t, "wallet not found", model.GetError())
}
