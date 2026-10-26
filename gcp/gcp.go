// Copyright 2025 Blink Labs Software
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
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"strings"

	secretmanagerclient "cloud.google.com/go/secretmanager/apiv1"
	secretmanager "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/sops"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const maxSecretIDLength = 255

var secretIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// ValidateWalletSecretPrefix validates the namespace used for GCP wallets.
func ValidateWalletSecretPrefix(prefix string) error {
	if prefix == "" {
		return errors.New("gcp secret prefix is required for gcp wallet storage")
	}
	if len(prefix) >= maxSecretIDLength || !secretIDPattern.MatchString(prefix) {
		return errors.New("gcp secret prefix must contain only letters, numbers, hyphens, or underscores and leave room for a wallet name")
	}
	return nil
}

func walletSecretID(prefix, name string) (string, error) {
	if err := ValidateWalletSecretPrefix(prefix); err != nil {
		return "", err
	}
	if name == "" || !secretIDPattern.MatchString(name) {
		return "", errors.New("gcp wallet name must contain only letters, numbers, hyphens, or underscores")
	}
	secretID := prefix + name
	if len(secretID) > maxSecretIDLength {
		return "", errors.New("gcp wallet secret ID exceeds 255 characters")
	}
	return secretID, nil
}

func walletSecretResource(project, prefix, name string) (string, error) {
	secretID, err := walletSecretID(prefix, name)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("projects/%s/secrets/%s", project, secretID), nil
}

type GoogleWallet struct {
	items       map[string]string
	name        string
	description string
}

func NewGoogleWallet(name string) *GoogleWallet {
	g := &GoogleWallet{
		name:  name,
		items: make(map[string]string),
	}
	return g
}

func GetGoogleWallet(ctx context.Context, name string) (*GoogleWallet, error) {
	g := NewGoogleWallet(name)
	if err := g.Load(ctx); err != nil {
		return nil, err
	}
	return g, nil
}

func ListGoogleWallets(
	ctx context.Context,
	client *secretmanagerclient.Client,
) ([]string, error) {
	ret := []string{}
	cfg := config.GetConfig()
	if err := ValidateWalletSecretPrefix(cfg.Google.Prefix); err != nil {
		return ret, err
	}
	var err error
	if client == nil {
		client, err = secretmanagerclient.NewClient(ctx)
		if err != nil {
			return ret, err
		}
		defer client.Close()
	}

	// Create our gRPC request
	req := &secretmanager.ListSecretsRequest{
		Parent:   "projects/" + cfg.Google.Project,
		PageSize: 100,
		Filter:   "/" + cfg.Google.Prefix,
	}
	secrets := client.ListSecrets(ctx, req)

	// Loop through secrets
	for {
		secret, err := secrets.Next()
		if errors.Is(err, iterator.Done) {
			break // No more secrets
		}
		if err != nil {
			return nil, err
		}
		secretID := strings.TrimPrefix(secret.GetName(), req.GetParent()+"/secrets/")
		if !strings.HasPrefix(secretID, cfg.Google.Prefix) {
			continue
		}
		name := strings.TrimPrefix(secretID, cfg.Google.Prefix)
		ret = append(ret, name)
	}
	return ret, nil
}

func (g *GoogleWallet) Name() string {
	return g.name
}

func (g *GoogleWallet) Description() string {
	return g.description
}

func (g *GoogleWallet) Items() map[string]string {
	return g.items
}

func (g *GoogleWallet) SetDescription(description string) {
	g.description = description
}

func (g *GoogleWallet) ListItems() []string {
	items := make([]string, 0, len(g.items))
	for name := range g.items {
		items = append(items, name)
	}
	return items
}

func (g *GoogleWallet) GetItem(name string) (string, error) {
	if item, ok := g.items[name]; ok {
		return item, nil
	}
	return "", fmt.Errorf("item not found: %s", name)
}

func (g *GoogleWallet) PutItem(name, value string) {
	g.items[name] = value
}

func (g *GoogleWallet) DeleteItem(name string) {
	delete(g.items, name)
}

func (g *GoogleWallet) PopulateFrom(wallet *bursa.Wallet) error {
	if wallet == nil {
		return errors.New("no wallet provided")
	}
	g.items["mnemonic"] = wallet.Mnemonic
	g.items["payment.addr"] = wallet.PaymentAddress
	g.items["stake.addr"] = wallet.StakeAddress

	keyFiles, err := bursa.ExtractKeyFiles(wallet)
	if err != nil {
		return fmt.Errorf("failed to extract key files: %w", err)
	}

	maps.Copy(g.items, keyFiles)

	return nil
}

func (g *GoogleWallet) PopulateTo(wallet *bursa.Wallet) error {
	if g == nil {
		return errors.New("nil google wallet")
	}
	if wallet == nil {
		return errors.New("nil bursa wallet")
	}
	wallet.Mnemonic = g.items["mnemonic"]
	wallet.PaymentAddress = g.items["payment.addr"]
	wallet.StakeAddress = g.items["stake.addr"]
	var keyfile bursa.KeyFile
	err := json.Unmarshal([]byte(g.items["payment.vkey"]), &keyfile)
	if err != nil {
		return err
	}
	wallet.PaymentVKey = keyfile
	err = json.Unmarshal([]byte(g.items["payment.skey"]), &keyfile)
	if err != nil {
		return err
	}
	wallet.PaymentSKey = keyfile
	err = json.Unmarshal([]byte(g.items["payment.extended.skey"]), &keyfile)
	if err != nil {
		return err
	}
	wallet.PaymentExtendedSKey = keyfile
	err = json.Unmarshal([]byte(g.items["stake.vkey"]), &keyfile)
	if err != nil {
		return err
	}
	wallet.StakeVKey = keyfile
	err = json.Unmarshal([]byte(g.items["stake.skey"]), &keyfile)
	if err != nil {
		return err
	}
	wallet.StakeSKey = keyfile
	err = json.Unmarshal([]byte(g.items["stake.extended.skey"]), &keyfile)
	if err != nil {
		return err
	}
	wallet.StakeExtendedSKey = keyfile
	return nil
}

func (g *GoogleWallet) Load(ctx context.Context) error {
	cfg := config.GetConfig()
	resourceName, err := walletSecretResource(
		cfg.Google.Project,
		cfg.Google.Prefix,
		g.name,
	)
	if err != nil {
		return err
	}
	client, err := secretmanagerclient.NewClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()

	// get latest secret version
	contentRequest := &secretmanager.AccessSecretVersionRequest{
		Name: resourceName + "/versions/latest",
	}
	contentResult, err := client.AccessSecretVersion(ctx, contentRequest)
	if err != nil {
		return fmt.Errorf("failed to get secret: %w", err)
	}
	if contentResult == nil {
		return errors.New("failed to get secret")
	}

	// decrypt
	decryptData, err := sops.Decrypt(contentResult.GetPayload().GetData())
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %w", err)
	}
	data := map[string]string{}
	if err := json.Unmarshal(decryptData, &data); err != nil {
		return fmt.Errorf("failed to decode json: %w", err)
	}

	// load each item into our GoogleWallet
	for k, v := range data {
		g.PutItem(k, v)
	}
	return nil
}

// secretAdmin is the part of the Secret Manager client that ensureSecret uses.
type secretAdmin interface {
	GetSecret(
		ctx context.Context,
		req *secretmanager.GetSecretRequest,
		opts ...gax.CallOption,
	) (*secretmanager.Secret, error)
	CreateSecret(
		ctx context.Context,
		req *secretmanager.CreateSecretRequest,
		opts ...gax.CallOption,
	) (*secretmanager.Secret, error)
}

// ensureSecret creates the named secret when it does not exist. Any lookup
// error other than not-found is returned, since the secret's state is unknown.
func ensureSecret(ctx context.Context, c secretAdmin, project, secretID string) error {
	_, err := c.GetSecret(ctx, &secretmanager.GetSecretRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s", project, secretID),
	})
	if err == nil {
		return nil
	}
	if status.Code(err) != codes.NotFound {
		return fmt.Errorf("failed to look up secret: %w", err)
	}
	_, err = c.CreateSecret(ctx, &secretmanager.CreateSecretRequest{
		Parent:   "projects/" + project,
		SecretId: secretID,
		Secret: &secretmanager.Secret{
			Replication: &secretmanager.Replication{
				Replication: &secretmanager.Replication_Automatic_{
					Automatic: &secretmanager.Replication_Automatic{},
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create secret: %w", err)
	}
	return nil
}

func (g *GoogleWallet) Save(ctx context.Context) error {
	cfg := config.GetConfig()
	secretID, err := walletSecretID(cfg.Google.Prefix, g.name)
	if err != nil {
		return err
	}
	client, err := secretmanagerclient.NewClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()

	if err := ensureSecret(ctx, client, cfg.Google.Project, secretID); err != nil {
		return err
	}

	// encrypt
	data, err := json.Marshal(g.items)
	if err != nil {
		return fmt.Errorf("failed to create payload: %w", err)
	}
	encryptData, err := sops.Encrypt(data)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	// send it
	addRequest := &secretmanager.AddSecretVersionRequest{
		Parent: fmt.Sprintf("projects/%s/secrets/%s", cfg.Google.Project, secretID),
		Payload: &secretmanager.SecretPayload{
			Data: encryptData,
		},
	}
	_, err = client.AddSecretVersion(ctx, addRequest)
	if err != nil {
		return fmt.Errorf("failed to add secret: %w", err)
	}
	return nil
}

func (g *GoogleWallet) Delete(ctx context.Context) error {
	cfg := config.GetConfig()
	resourceName, err := walletSecretResource(
		cfg.Google.Project,
		cfg.Google.Prefix,
		g.name,
	)
	if err != nil {
		return err
	}
	client, err := secretmanagerclient.NewClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()

	if err := client.DeleteSecret(ctx, &secretmanager.DeleteSecretRequest{Name: resourceName}); err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}
	return nil
}
