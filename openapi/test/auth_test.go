package openapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	openapiclient "github.com/blinklabs-io/bursa/openapi"
	"github.com/stretchr/testify/require"
)

func TestBearerAuthenticationHeader(t *testing.T) {
	receivedAuthorization := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthorization <- r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	defer server.Close()

	configuration := openapiclient.NewConfiguration()
	configuration.Servers = openapiclient.ServerConfigurations{{URL: server.URL}}
	apiClient := openapiclient.NewAPIClient(configuration)
	ctx := context.WithValue(
		context.Background(),
		openapiclient.ContextAPIKeys,
		map[string]openapiclient.APIKey{
			"BearerAuth": {Key: "test-jwt", Prefix: "Bearer"},
		},
	)

	_, response, err := apiClient.DefaultAPI.ApiWalletListGet(ctx).Execute()
	require.NoError(t, err)
	require.NotNil(t, response)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, "Bearer test-jwt", <-receivedAuthorization)
}
