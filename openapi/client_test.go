package openapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTxInspectionValueEffectsRoundTrip(t *testing.T) {
	raw := []byte(`{"certificate_deposit_total":"3000000","certificate_refund_total":"2000000","certificate_value_effects_complete":true,"proposal_deposit_total":"5000000","treasury_donation_lovelace":"4000000","unresolved_certificate_deposits":1,"unresolved_certificate_refunds":2}`)
	var inspection BursaTxInspection
	require.NoError(t, json.Unmarshal(raw, &inspection))
	require.Equal(t, "3000000", inspection.GetCertificateDepositTotal())
	require.Equal(t, "2000000", inspection.GetCertificateRefundTotal())
	require.True(t, inspection.GetCertificateValueEffectsComplete())
	require.Equal(t, "5000000", inspection.GetProposalDepositTotal())
	require.Equal(t, "4000000", inspection.GetTreasuryDonationLovelace())
	require.Equal(t, int32(1), inspection.GetUnresolvedCertificateDeposits())
	require.Equal(t, int32(2), inspection.GetUnresolvedCertificateRefunds())

	encoded, err := json.Marshal(inspection)
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(encoded, &got))
	require.Equal(t, "3000000", got["certificate_deposit_total"])
	require.Equal(t, "5000000", got["proposal_deposit_total"])
	require.Equal(t, "4000000", got["treasury_donation_lovelace"])
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestNewAPIClientUsesFiniteDefaultTimeout(t *testing.T) {
	configuration := NewConfiguration()
	client := NewAPIClient(configuration)
	require.Positive(t, client.cfg.HTTPClient.Timeout)

	custom := &http.Client{}
	configuration = NewConfiguration()
	configuration.HTTPClient = custom
	client = NewAPIClient(configuration)
	require.Same(t, custom, client.cfg.HTTPClient)
	require.Zero(t, client.cfg.HTTPClient.Timeout)
}

func TestCallAPIBoundsResponseBody(t *testing.T) {
	for _, tc := range []struct {
		name    string
		size    int
		wantErr bool
	}{
		{name: "at limit", size: 1 << 20},
		{name: "over limit", size: 1<<20 + 1, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configuration := NewConfiguration()
			configuration.HTTPClient = &http.Client{
				Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     make(http.Header),
						Body: io.NopCloser(
							strings.NewReader(strings.Repeat("x", tc.size)),
						),
						ContentLength: -1,
					}, nil
				}),
			}
			client := NewAPIClient(configuration)
			request, err := http.NewRequestWithContext(
				context.Background(), http.MethodGet, "http://wallet.test", nil,
			)
			require.NoError(t, err)
			response, err := client.callAPI(request)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, response.Body.Close()) })

			body, err := io.ReadAll(response.Body)
			if tc.wantErr {
				require.ErrorIs(t, err, ErrResponseBodyTooLarge)
				require.Len(t, body, 1<<20)
				return
			}
			require.NoError(t, err)
			require.Len(t, body, tc.size)
		})
	}
}

func TestGeneratedOperationRejectsOversizedErrorResponse(t *testing.T) {
	configuration := NewConfiguration()
	configuration.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusBadGateway,
				Status:     "502 Bad Gateway",
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
				Body: io.NopCloser(
					strings.NewReader(strings.Repeat("x", maxResponseBodyBytes+1)),
				),
				ContentLength: -1,
			}, nil
		}),
	}
	client := NewAPIClient(configuration)

	_, response, err := client.DefaultAPI.ApiWalletListGet(context.Background()).Execute()
	require.ErrorIs(t, err, ErrResponseBodyTooLarge)
	require.NotNil(t, response)
	t.Cleanup(func() { require.NoError(t, response.Body.Close()) })
	body, readErr := io.ReadAll(response.Body)
	require.NoError(t, readErr)
	require.Len(t, body, maxResponseBodyBytes)
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
