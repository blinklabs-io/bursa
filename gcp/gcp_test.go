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

package gcp

import (
	"context"
	"errors"
	"testing"

	secretmanager "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/googleapis/gax-go/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeSecretAdmin struct {
	getErr    error
	createErr error
	created   []*secretmanager.CreateSecretRequest
	got       []*secretmanager.GetSecretRequest
}

func TestWalletSecretResourceRequiresNamespace(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		prefix string
		name   string
	}{
		{name: "unrelated-wallet"},
		{prefix: "wallets/", name: "unrelated-wallet"},
		{prefix: "wallet prefix", name: "unrelated-wallet"},
		{prefix: "bursa-wallet-", name: "../unrelated-wallet"},
	} {
		resourceName, err := walletSecretResource("project", tc.prefix, tc.name)
		require.Empty(t, resourceName)
		require.Error(t, err)
	}
}

func TestDeleteRejectsEmptyWalletNamespace(t *testing.T) {
	cfg := config.GetConfig()
	saved := *cfg
	cfg.Google.Project = "project"
	cfg.Google.Prefix = ""
	t.Cleanup(func() { *cfg = saved })

	err := NewGoogleWallet("unrelated-wallet").Delete(context.Background())
	require.ErrorContains(t, err, "gcp secret prefix is required")
}

func TestWalletSecretResourceUsesNamespace(t *testing.T) {
	t.Parallel()
	resourceName, err := walletSecretResource("project", "bursa-wallet-", "wallet_1")
	require.NoError(t, err)
	require.Equal(
		t,
		"projects/project/secrets/bursa-wallet-wallet_1",
		resourceName,
	)
}

func (f *fakeSecretAdmin) GetSecret(
	_ context.Context,
	req *secretmanager.GetSecretRequest,
	_ ...gax.CallOption,
) (*secretmanager.Secret, error) {
	f.got = append(f.got, req)
	return &secretmanager.Secret{}, f.getErr
}

func (f *fakeSecretAdmin) CreateSecret(
	_ context.Context,
	req *secretmanager.CreateSecretRequest,
	_ ...gax.CallOption,
) (*secretmanager.Secret, error) {
	f.created = append(f.created, req)
	return &secretmanager.Secret{}, f.createErr
}

func TestEnsureSecretCreatesOnNotFound(t *testing.T) {
	t.Parallel()
	f := &fakeSecretAdmin{getErr: status.Error(codes.NotFound, "missing")}
	require.NoError(t, ensureSecret(context.Background(), f, "proj", "pre-w1"))
	require.Len(t, f.created, 1)
	require.Equal(t, "projects/proj", f.created[0].GetParent())
	require.Equal(t, "pre-w1", f.created[0].GetSecretId())
	require.Equal(t, "projects/proj/secrets/pre-w1", f.got[0].GetName())
}

func TestEnsureSecretSkipsCreateWhenPresent(t *testing.T) {
	t.Parallel()
	f := &fakeSecretAdmin{}
	require.NoError(t, ensureSecret(context.Background(), f, "proj", "pre-w1"))
	require.Empty(t, f.created)
}

func TestEnsureSecretPropagatesLookupError(t *testing.T) {
	t.Parallel()
	for _, code := range []codes.Code{
		codes.PermissionDenied,
		codes.Unavailable,
		codes.Unauthenticated,
	} {
		f := &fakeSecretAdmin{getErr: status.Error(code, "boom")}
		err := ensureSecret(context.Background(), f, "proj", "pre-w1")
		require.Error(t, err, code.String())
		require.Equal(t, code, status.Code(errors.Unwrap(err)), code.String())
		require.Empty(t, f.created, code.String())
	}
}

func TestEnsureSecretReportsCreateFailure(t *testing.T) {
	t.Parallel()
	f := &fakeSecretAdmin{
		getErr:    status.Error(codes.NotFound, "missing"),
		createErr: status.Error(codes.PermissionDenied, "no"),
	}
	err := ensureSecret(context.Background(), f, "proj", "pre-w1")
	require.ErrorContains(t, err, "failed to create secret")
}
