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

package signer

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	secretmanager "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/iterator"
)

type fakeGCPSecretClient struct {
	secrets         []*secretmanager.Secret
	versions        []*secretmanager.SecretVersion
	accessPayloads  map[string][]byte
	listVersionsErr error

	listSecretsReq  *secretmanager.ListSecretsRequest
	listVersionsReq *secretmanager.ListSecretVersionsRequest
	accessNames     []string
}

func (f *fakeGCPSecretClient) ListSecrets(_ context.Context, req *secretmanager.ListSecretsRequest) gcpSecretIterator {
	f.listSecretsReq = req
	return &fakeGCPSecretIterator{secrets: f.secrets}
}

func (f *fakeGCPSecretClient) ListSecretVersions(_ context.Context, req *secretmanager.ListSecretVersionsRequest) gcpSecretVersionIterator {
	f.listVersionsReq = req
	return &fakeGCPSecretVersionIterator{
		versions: f.versions,
		err:      f.listVersionsErr,
	}
}

func (f *fakeGCPSecretClient) AccessSecretVersion(_ context.Context, req *secretmanager.AccessSecretVersionRequest) (*secretmanager.AccessSecretVersionResponse, error) {
	f.accessNames = append(f.accessNames, req.GetName())
	payload, ok := f.accessPayloads[req.GetName()]
	if !ok {
		return nil, fmt.Errorf("unexpected access to %q", req.GetName())
	}
	return &secretmanager.AccessSecretVersionResponse{
		Name:    req.GetName(),
		Payload: &secretmanager.SecretPayload{Data: payload},
	}, nil
}

type fakeGCPSecretIterator struct {
	secrets []*secretmanager.Secret
	idx     int
}

func (i *fakeGCPSecretIterator) Next() (*secretmanager.Secret, error) {
	if i.idx >= len(i.secrets) {
		return nil, iterator.Done
	}
	secret := i.secrets[i.idx]
	i.idx++
	return secret, nil
}

type fakeGCPSecretVersionIterator struct {
	versions []*secretmanager.SecretVersion
	idx      int
	err      error
}

func (i *fakeGCPSecretVersionIterator) Next() (*secretmanager.SecretVersion, error) {
	if i.err != nil {
		err := i.err
		i.err = nil
		return nil, err
	}
	if i.idx >= len(i.versions) {
		return nil, iterator.Done
	}
	version := i.versions[i.idx]
	i.idx++
	return version, nil
}

func TestGCPSecretSourceGetUsesNewestEnabledVersion(t *testing.T) {
	const (
		parent = "projects/test-project"
		secret = "signer-payment"
		v1     = parent + "/secrets/" + secret + "/versions/1"
		v2     = parent + "/secrets/" + secret + "/versions/2"
		v3     = parent + "/secrets/" + secret + "/versions/3"
	)
	client := &fakeGCPSecretClient{
		versions: []*secretmanager.SecretVersion{
			{Name: v3, State: secretmanager.SecretVersion_DISABLED},
			{Name: v2, State: secretmanager.SecretVersion_DESTROYED},
			{Name: v1, State: secretmanager.SecretVersion_ENABLED},
		},
		accessPayloads: map[string][]byte{
			v1: []byte("enabled payload"),
		},
	}
	src := &GCPSecretSource{
		client: client,
		parent: parent,
	}

	got, err := src.Get(context.Background(), secret)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "enabled payload" {
		t.Fatalf("payload = %q, want %q", string(got), "enabled payload")
	}
	if client.listVersionsReq.GetParent() != parent+"/secrets/"+secret {
		t.Fatalf("ListSecretVersions parent = %q", client.listVersionsReq.GetParent())
	}
	if !slices.Equal(client.accessNames, []string{v1}) {
		t.Fatalf("accessed versions = %v, want [%s]", client.accessNames, v1)
	}
}

func TestGCPSecretSourceGetFailsWhenNoEnabledVersion(t *testing.T) {
	const (
		parent = "projects/test-project"
		secret = "signer-payment"
	)
	client := &fakeGCPSecretClient{
		versions: []*secretmanager.SecretVersion{
			{Name: parent + "/secrets/" + secret + "/versions/2", State: secretmanager.SecretVersion_DISABLED},
			{Name: parent + "/secrets/" + secret + "/versions/1", State: secretmanager.SecretVersion_DESTROYED},
		},
		accessPayloads: map[string][]byte{},
	}
	src := &GCPSecretSource{
		client: client,
		parent: parent,
	}

	_, err := src.Get(context.Background(), secret)
	if err == nil {
		t.Fatal("Get: expected error, got nil")
	}
	if !strings.Contains(err.Error(), `no enabled versions for secret "signer-payment"`) {
		t.Fatalf("Get error = %q", err.Error())
	}
	if len(client.accessNames) != 0 {
		t.Fatalf("accessed versions = %v, want none", client.accessNames)
	}
}
