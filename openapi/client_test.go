package openapi

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestDebugLoggingUsesSafeMetadata(t *testing.T) {
	const (
		requestMnemonic  = "request-sensitive-value"
		requestPassword  = "password-sensitive-value"
		responseMnemonic = "response-sensitive-value"
		authorizationKey = "authorization-sensitive-value"
	)

	var logs bytes.Buffer
	previousWriter := log.Writer()
	previousFlags := log.Flags()
	previousPrefix := log.Prefix()
	log.SetOutput(&logs)
	log.SetFlags(0)
	log.SetPrefix("")
	defer func() {
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
		log.SetPrefix(previousPrefix)
	}()

	configuration := NewConfiguration()
	configuration.Debug = true
	configuration.Servers = ServerConfigurations{{URL: "https://wallet.test"}}
	configuration.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(request.Body)
			require.NoError(t, err)
			require.Contains(t, string(body), requestMnemonic)
			require.Contains(t, string(body), requestPassword)
			require.Equal(t, "Bearer "+authorizationKey, request.Header.Get("Authorization"))
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body: io.NopCloser(strings.NewReader(
					`{"mnemonic":"` + responseMnemonic + `"}`,
				)),
			}, nil
		}),
	}
	client := NewAPIClient(configuration)
	ctx := context.WithValue(
		context.Background(),
		ContextAPIKeys,
		map[string]APIKey{
			"BearerAuth": {Key: authorizationKey, Prefix: "Bearer"},
		},
	)
	request := NewApiWalletRestoreRequest(requestMnemonic)
	request.SetPassword(requestPassword)

	wallet, response, err := client.DefaultAPI.
		ApiWalletRestorePost(ctx).
		Request(*request).
		Execute()

	require.NoError(t, err)
	require.NotNil(t, response)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, responseMnemonic, wallet.GetMnemonic())
	require.Equal(t, "HTTP request method=POST\nHTTP response status=200\n", logs.String())
}

func TestPrepareRequestMultipartRequiresMultipartContentType(t *testing.T) {
	client := NewAPIClient(NewConfiguration())
	formFiles := []formFile{{
		fileBytes:    []byte("payload"),
		fileName:     "payload.txt",
		formFileName: "file",
	}}

	request, err := client.prepareRequest(
		context.Background(),
		"/upload",
		http.MethodPost,
		nil,
		map[string]string{},
		nil,
		nil,
		formFiles,
	)

	require.NoError(t, err)
	require.NotNil(t, request)
	require.Empty(t, request.Header.Get("Content-Type"))
	require.Nil(t, request.Body)
}
