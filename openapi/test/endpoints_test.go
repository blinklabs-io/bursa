package openapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"

	openapiclient "github.com/blinklabs-io/bursa/openapi"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

type endpointCall struct {
	method string
	path   string
	// body is the JSON the server answers with; the generated client must
	// decode it into the operation's declared response type.
	body string
	call func(context.Context, openapiclient.DefaultAPI) (*http.Response, error)
}

func endpointCalls() []endpointCall {
	obj := `{}`
	arr := `[]`
	return []endpointCall{
		{"POST", "/api/address/build", obj, func(ctx context.Context, api openapiclient.DefaultAPI) (*http.Response, error) {
			_, r, err := api.ApiAddressBuildPost(ctx).Request(openapiclient.ApiAddressBuildRequest{}).Execute()
			return r, err
		}},
		{"POST", "/api/address/enumerate", arr, func(ctx context.Context, api openapiclient.DefaultAPI) (*http.Response, error) {
			_, r, err := api.ApiAddressEnumeratePost(ctx).Request(openapiclient.ApiAddressEnumerateRequest{}).Execute()
			return r, err
		}},
		{"POST", "/api/address/parse", obj, func(ctx context.Context, api openapiclient.DefaultAPI) (*http.Response, error) {
			_, r, err := api.ApiAddressParsePost(ctx).Request(openapiclient.ApiAddressParseRequest{}).Execute()
			return r, err
		}},
		{"POST", "/api/script/address", obj, func(ctx context.Context, api openapiclient.DefaultAPI) (*http.Response, error) {
			_, r, err := api.ApiScriptAddressPost(ctx).Request(openapiclient.ApiScriptAddressRequest{}).Execute()
			return r, err
		}},
		{"POST", "/api/script/create", obj, func(ctx context.Context, api openapiclient.DefaultAPI) (*http.Response, error) {
			_, r, err := api.ApiScriptCreatePost(ctx).Request(openapiclient.ApiScriptCreateRequest{}).Execute()
			return r, err
		}},
		{"POST", "/api/script/validate", obj, func(ctx context.Context, api openapiclient.DefaultAPI) (*http.Response, error) {
			_, r, err := api.ApiScriptValidatePost(ctx).Request(openapiclient.ApiScriptValidateRequest{}).Execute()
			return r, err
		}},
		{"POST", "/api/sign/data", obj, func(ctx context.Context, api openapiclient.DefaultAPI) (*http.Response, error) {
			_, r, err := api.ApiSignDataPost(ctx).Request(openapiclient.ApiSignDataRequest{}).Execute()
			return r, err
		}},
		{"POST", "/api/sign/verify", obj, func(ctx context.Context, api openapiclient.DefaultAPI) (*http.Response, error) {
			_, r, err := api.ApiSignVerifyPost(ctx).Request(openapiclient.ApiVerifyDataRequest{}).Execute()
			return r, err
		}},
		{"POST", "/api/tx/assemble", obj, func(ctx context.Context, api openapiclient.DefaultAPI) (*http.Response, error) {
			_, r, err := api.ApiTxAssemblePost(ctx).Request(openapiclient.ApiTxAssembleRequest{}).Execute()
			return r, err
		}},
		{"POST", "/api/tx/decode", obj, func(ctx context.Context, api openapiclient.DefaultAPI) (*http.Response, error) {
			_, r, err := api.ApiTxDecodePost(ctx).Request(openapiclient.ApiTxDecodeRequest{}).Execute()
			return r, err
		}},
		{"POST", "/api/tx/id", obj, func(ctx context.Context, api openapiclient.DefaultAPI) (*http.Response, error) {
			_, r, err := api.ApiTxIdPost(ctx).Request(openapiclient.ApiTxIDRequest{}).Execute()
			return r, err
		}},
		{"POST", "/api/tx/sign", obj, func(ctx context.Context, api openapiclient.DefaultAPI) (*http.Response, error) {
			_, r, err := api.ApiTxSignPost(ctx).Request(openapiclient.ApiTxSignRequest{}).Execute()
			return r, err
		}},
		{"POST", "/api/tx/witness", obj, func(ctx context.Context, api openapiclient.DefaultAPI) (*http.Response, error) {
			_, r, err := api.ApiTxWitnessPost(ctx).Request(openapiclient.ApiTxWitnessRequest{}).Execute()
			return r, err
		}},
		{"POST", "/api/wallet/create", obj, func(ctx context.Context, api openapiclient.DefaultAPI) (*http.Response, error) {
			_, r, err := api.ApiWalletCreatePost(ctx).Execute()
			return r, err
		}},
		{"POST", "/api/wallet/delete", obj, func(ctx context.Context, api openapiclient.DefaultAPI) (*http.Response, error) {
			_, r, err := api.ApiWalletDeletePost(ctx).Request(openapiclient.ApiWalletDeleteRequest{}).Execute()
			return r, err
		}},
		{"POST", "/api/wallet/get", obj, func(ctx context.Context, api openapiclient.DefaultAPI) (*http.Response, error) {
			_, r, err := api.ApiWalletGetPost(ctx).Request(openapiclient.ApiWalletGetRequest{}).Execute()
			return r, err
		}},
		{"GET", "/api/wallet/list", arr, func(ctx context.Context, api openapiclient.DefaultAPI) (*http.Response, error) {
			_, r, err := api.ApiWalletListGet(ctx).Execute()
			return r, err
		}},
		{"POST", "/api/wallet/restore", obj, func(ctx context.Context, api openapiclient.DefaultAPI) (*http.Response, error) {
			_, r, err := api.ApiWalletRestorePost(ctx).Request(openapiclient.ApiWalletRestoreRequest{}).Execute()
			return r, err
		}},
		{"POST", "/api/wallet/update", obj, func(ctx context.Context, api openapiclient.DefaultAPI) (*http.Response, error) {
			_, r, err := api.ApiWalletUpdatePost(ctx).Request(openapiclient.ApiWalletUpdateRequest{}).Execute()
			return r, err
		}},
	}
}

// TestGeneratedClientCoversSwagger fails when the server's Swagger document
// declares an operation that the generated client test does not call.
func TestGeneratedClientCoversSwagger(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("../../docs/swagger.yaml")
	require.NoError(t, err)
	var doc struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &doc))

	var declared, covered []string
	for path, methods := range doc.Paths {
		for method := range methods {
			declared = append(declared, strings.ToUpper(method)+" "+path)
		}
	}
	for _, c := range endpointCalls() {
		covered = append(covered, c.method+" "+c.path)
	}
	sort.Strings(declared)
	sort.Strings(covered)
	require.Equal(t, declared, covered)
}

// TestGeneratedClientCallsEveryEndpoint sends each operation through the
// generated client and checks the method and path on the wire.
func TestGeneratedClientCallsEveryEndpoint(t *testing.T) {
	t.Parallel()

	for _, c := range endpointCalls() {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			t.Parallel()

			var gotMethod, gotPath string
			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					gotMethod, gotPath = r.Method, r.URL.Path
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(c.body))
				}),
			)
			defer server.Close()

			configuration := openapiclient.NewConfiguration()
			configuration.Servers = openapiclient.ServerConfigurations{{URL: server.URL}}
			client := openapiclient.NewAPIClient(configuration)

			response, err := c.call(context.Background(), client.DefaultAPI)
			require.NoError(t, err)
			require.NotNil(t, response)
			require.Equal(t, http.StatusOK, response.StatusCode)
			require.Equal(t, c.method, gotMethod)
			require.Equal(t, c.path, gotPath)
		})
	}
}
