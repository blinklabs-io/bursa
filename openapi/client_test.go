package openapi

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

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
