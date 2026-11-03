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
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type kmsAPI interface {
	GenerateDataKey(context.Context, *kms.GenerateDataKeyInput, ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
	Decrypt(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

type awsKMS struct {
	client kmsAPI
}

// NewAWSKMSFactory builds clients inside the enclave. httpClient should route
// TCP through the parent-vsock KMS proxy while retaining end-to-end AWS TLS.
func NewAWSKMSFactory(httpClient aws.HTTPClient) KMSFactory {
	return func(region string, credentialsValue Credentials) (KMS, error) {
		if httpClient == nil {
			return nil, errors.New("KMS proxy HTTP client is required")
		}
		if err := credentialsValue.validate(); err != nil {
			return nil, err
		}
		cfg := aws.Config{
			Region: region,
			Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(
				credentialsValue.AccessKeyID,
				credentialsValue.SecretAccessKey,
				credentialsValue.SessionToken,
			)),
			HTTPClient: httpClient,
		}
		return &awsKMS{client: kms.NewFromConfig(cfg)}, nil
	}
}

func recipientInfo(document []byte) *types.RecipientInfo {
	return &types.RecipientInfo{
		AttestationDocument:    document,
		KeyEncryptionAlgorithm: types.KeyEncryptionMechanismRsaesOaepSha256,
	}
}

func (k *awsKMS) GenerateDataKey(ctx context.Context, keyID string, recipient []byte) ([]byte, []byte, error) {
	result, err := k.client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:     aws.String(keyID),
		KeySpec:   types.DataKeySpecAes256,
		Recipient: recipientInfo(recipient),
	})
	if err != nil {
		return nil, nil, err
	}
	if len(result.Plaintext) != 0 {
		clear(result.Plaintext)
		return nil, nil, errors.New("KMS returned a plaintext data key for an attested request")
	}
	if len(result.CiphertextBlob) == 0 || len(result.CiphertextForRecipient) == 0 {
		return nil, nil, errors.New("KMS attested data-key response is incomplete")
	}
	return result.CiphertextBlob, result.CiphertextForRecipient, nil
}

func (k *awsKMS) Decrypt(ctx context.Context, keyID string, ciphertext, recipient []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, ErrEnvelope
	}
	result, err := k.client.Decrypt(ctx, &kms.DecryptInput{
		KeyId:          aws.String(keyID),
		CiphertextBlob: ciphertext,
		Recipient:      recipientInfo(recipient),
	})
	if err != nil {
		return nil, err
	}
	if len(result.Plaintext) != 0 {
		clear(result.Plaintext)
		return nil, errors.New("kms returned plaintext for an attested request")
	}
	if len(result.CiphertextForRecipient) == 0 {
		return nil, errors.New("KMS attested decrypt response is incomplete")
	}
	return result.CiphertextForRecipient, nil
}
