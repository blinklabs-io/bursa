// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package nitro

import (
	"context"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/require"
)

type fakeKMSAPI struct {
	generateInput *kms.GenerateDataKeyInput
	decryptInput  *kms.DecryptInput
	plaintext     []byte
}

func (f *fakeKMSAPI) GenerateDataKey(_ context.Context, input *kms.GenerateDataKeyInput, _ ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	f.generateInput = input
	return &kms.GenerateDataKeyOutput{
		CiphertextBlob: []byte("wrapped"), CiphertextForRecipient: []byte("recipient"),
		Plaintext: f.plaintext,
	}, nil
}

func (f *fakeKMSAPI) Decrypt(_ context.Context, input *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	f.decryptInput = input
	return &kms.DecryptOutput{CiphertextForRecipient: []byte("recipient"), Plaintext: f.plaintext}, nil
}

func TestAWSKMSAlwaysUsesRecipientAttestation(t *testing.T) {
	api := &fakeKMSAPI{}
	provider := &awsKMS{client: api}
	document := []byte("attestation")
	_, _, err := provider.GenerateDataKey(context.Background(), testKMSKey, document)
	require.NoError(t, err)
	require.Equal(t, document, api.generateInput.Recipient.AttestationDocument)
	require.Equal(t, types.KeyEncryptionMechanismRsaesOaepSha256, api.generateInput.Recipient.KeyEncryptionAlgorithm)
	_, err = provider.Decrypt(context.Background(), testKMSKey, []byte("wrapped"), document)
	require.NoError(t, err)
	require.Equal(t, document, api.decryptInput.Recipient.AttestationDocument)
}

func TestAWSKMSRejectsPlaintextResponses(t *testing.T) {
	api := &fakeKMSAPI{plaintext: []byte("host-visible")}
	provider := &awsKMS{client: api}
	_, _, err := provider.GenerateDataKey(context.Background(), testKMSKey, []byte("attestation"))
	require.ErrorContains(t, err, "plaintext")
	require.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, api.plaintext)
}

func TestKMSEndpointIsFixed(t *testing.T) {
	endpoint, err := KMSEndpoint("us-east-1")
	require.NoError(t, err)
	require.Equal(t, "kms.us-east-1.amazonaws.com:443", endpoint)
	for _, region := range []string{"", "https://attacker.example", "us-east-1.attacker", "cn-north-1"} {
		_, err := KMSEndpoint(region)
		require.Error(t, err)
	}
}

func TestKMSProxyHTTPClientIgnoresEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
	client := NewKMSProxyHTTPClient(DefaultKMSProxyPort)
	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	if transport.Proxy == nil {
		return
	}
	request, err := http.NewRequest(http.MethodPost, "https://kms.us-east-1.amazonaws.com/", nil)
	require.NoError(t, err)
	proxy, err := transport.Proxy(request)
	require.NoError(t, err)
	require.Nil(t, proxy)
}
