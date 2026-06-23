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
	"errors"
	"fmt"
	"strings"

	secretmanagerclient "cloud.google.com/go/secretmanager/apiv1"
	secretmanager "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"google.golang.org/api/iterator"
)

// GCPSecretSource implements backend.SecretSource over GCP Secret Manager.
// Secrets are matched by short-name prefix within the configured
// google.project; payloads are the latest enabled secret version.
// The client is used once at boot (SopsBackend.Load) and intentionally not
// closed; the daemon holds one idle connection for its lifetime.
type GCPSecretSource struct {
	client gcpSecretClient
	parent string // projects/<project>
	prefix string // secret short-name prefix
}

type gcpSecretClient interface {
	ListSecrets(context.Context, *secretmanager.ListSecretsRequest) gcpSecretIterator
	ListSecretVersions(context.Context, *secretmanager.ListSecretVersionsRequest) gcpSecretVersionIterator
	AccessSecretVersion(context.Context, *secretmanager.AccessSecretVersionRequest) (*secretmanager.AccessSecretVersionResponse, error)
}

type gcpSecretIterator interface {
	Next() (*secretmanager.Secret, error)
}

type gcpSecretVersionIterator interface {
	Next() (*secretmanager.SecretVersion, error)
}

type gcpSecretManagerClient struct {
	*secretmanagerclient.Client
}

func (c gcpSecretManagerClient) ListSecrets(ctx context.Context, req *secretmanager.ListSecretsRequest) gcpSecretIterator {
	return c.Client.ListSecrets(ctx, req)
}

func (c gcpSecretManagerClient) ListSecretVersions(ctx context.Context, req *secretmanager.ListSecretVersionsRequest) gcpSecretVersionIterator {
	return c.Client.ListSecretVersions(ctx, req)
}

func (c gcpSecretManagerClient) AccessSecretVersion(ctx context.Context, req *secretmanager.AccessSecretVersionRequest) (*secretmanager.AccessSecretVersionResponse, error) {
	return c.Client.AccessSecretVersion(ctx, req)
}

// newSopsSecretSource is a constructor seam so wiring tests can inject a fake.
var newSopsSecretSource = func(ctx context.Context, c config.SignerBackendConfig) (backend.SecretSource, error) {
	return NewGCPSecretSource(ctx, c.SecretPrefix)
}

// NewGCPSecretSource builds a SecretSource over GCP Secret Manager. The GCP
// project comes from the global config singleton (google.project — one
// project per process, as elsewhere in bursa); the secret prefix is
// per-backend configuration (signer.backends[].secret_prefix).
func NewGCPSecretSource(ctx context.Context, prefix string) (*GCPSecretSource, error) {
	cfg := config.GetConfig()
	if cfg.Google.Project == "" {
		return nil, errors.New("google.project is required for the sops backend")
	}
	client, err := secretmanagerclient.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("secret manager client: %w", err)
	}
	return &GCPSecretSource{
		client: gcpSecretManagerClient{Client: client},
		parent: "projects/" + cfg.Google.Project,
		prefix: prefix,
	}, nil
}

// List returns the short names of secrets whose name begins with the prefix.
func (s *GCPSecretSource) List(ctx context.Context) ([]string, error) {
	req := &secretmanager.ListSecretsRequest{
		Parent:   s.parent,
		PageSize: 100,
	}
	if s.prefix != "" {
		// Server-side narrowing filter to cut paging cost. The "name:" operator
		// matches by substring containment, not true prefix, so this only
		// reduces the candidate set; the authoritative prefix match is the
		// client-side HasPrefix below.
		req.Filter = "name:" + s.prefix
	}
	it := s.client.ListSecrets(ctx, req)
	var out []string
	for {
		secret, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list secrets: %w", err)
		}
		// secret.Name is the full resource name projects/<p>/secrets/<short>.
		short := secret.GetName()
		if i := strings.LastIndex(short, "/"); i >= 0 {
			short = short[i+1:]
		}
		if s.prefix == "" || strings.HasPrefix(short, s.prefix) {
			out = append(out, short)
		}
	}
	return out, nil
}

// Get fetches the newest enabled version payload of the named secret.
func (s *GCPSecretSource) Get(ctx context.Context, name string) ([]byte, error) {
	versionName, err := s.latestEnabledVersion(ctx, name)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.AccessSecretVersion(ctx, &secretmanager.AccessSecretVersionRequest{
		Name: versionName,
	})
	if err != nil {
		return nil, fmt.Errorf("access secret %q: %w", name, err)
	}
	return resp.GetPayload().GetData(), nil
}

func (s *GCPSecretSource) latestEnabledVersion(ctx context.Context, name string) (string, error) {
	it := s.client.ListSecretVersions(ctx, &secretmanager.ListSecretVersionsRequest{
		Parent:   s.parent + "/secrets/" + name,
		PageSize: 100,
	})
	for {
		version, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("list secret versions %q: %w", name, err)
		}
		if version.GetState() != secretmanager.SecretVersion_ENABLED {
			continue
		}
		if version.GetName() == "" {
			return "", fmt.Errorf("list secret versions %q: enabled version has empty name", name)
		}
		return version.GetName(), nil
	}
	return "", fmt.Errorf("no enabled versions for secret %q", name)
}
