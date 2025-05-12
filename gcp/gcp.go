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

	secretmanagerclient "cloud.google.com/go/secretmanager/apiv1"
	secretmanager "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/sops"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type GoogleWallet struct {
	name        string
	description string
	items       map[string]string
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
	var err error
	if client == nil {
		client, err = secretmanagerclient.NewClient(ctx)
		if err != nil {
			return ret, err
		}
		defer client.Close()
	}

	cfg := config.GetConfig()
	// Create our gRPC request
	req := &secretmanager.ListSecretsRequest{
		Parent:   "projects/" + cfg.Google.Project,
		PageSize: 100,
		Filter:   "/" + cfg.Google.Prefix,
	}
	secrets := client.ListSecrets(ctx, req)

	re := regexp.MustCompile("^.*/" + regexp.QuoteMeta(cfg.Google.Prefix))
	// Loop through secrets
	for {
		secret, err := secrets.Next()
		if errors.Is(err, iterator.Done) {
			break // No more secrets
		}
		if err != nil {
			return nil, err
		}
		name := re.ReplaceAllString(secret.GetName(), "")
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
	items := []string{}
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
	client, err := secretmanagerclient.NewClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()

	cfg := config.GetConfig()

	// get latest secret version
	contentRequest := &secretmanager.AccessSecretVersionRequest{
		Name: fmt.Sprintf(
			"projects/%s/secrets/%s%s/versions/latest",
			cfg.Google.Project,
			cfg.Google.Prefix,
			g.name,
		),
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

func (g *GoogleWallet) Save(ctx context.Context) error {
	client, err := secretmanagerclient.NewClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()

	cfg := config.GetConfig()

	// Check if the GoogleWallet exists in Secrets Manager, create if not
	secretRequest := &secretmanager.GetSecretRequest{
		Name: fmt.Sprintf(
			"projects/%s/secrets/%s%s",
			cfg.Google.Project,
			cfg.Google.Prefix,
			g.name,
		),
	}
	if _, err = client.GetSecret(ctx, secretRequest); err != nil {
		if status.Code(err) == codes.NotFound {
			// create it
			createRequest := &secretmanager.CreateSecretRequest{
				Parent:   "projects/" + cfg.Google.Project,
				SecretId: fmt.Sprintf("%s%s", cfg.Google.Prefix, g.name),
				Secret: &secretmanager.Secret{
					Replication: &secretmanager.Replication{
						Replication: &secretmanager.Replication_Automatic_{
							Automatic: &secretmanager.Replication_Automatic{},
						},
					},
				},
			}
			_, createErr := client.CreateSecret(ctx, createRequest)
			if createErr != nil {
				return fmt.Errorf("failed to create secret: %w", createErr)
			}
		}
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
		Parent: fmt.Sprintf(
			"projects/%s/secrets/%s%s",
			cfg.Google.Project,
			cfg.Google.Prefix,
			g.name,
		),
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
	client, err := secretmanagerclient.NewClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()

	cfg := config.GetConfig()

	// setup request
	deleteRequest := &secretmanager.DeleteSecretRequest{
		Name: fmt.Sprintf(
			"projects/%s/secrets/%s%s",
			cfg.Google.Project,
			cfg.Google.Prefix,
			g.name,
		),
	}
	err = client.DeleteSecret(ctx, deleteRequest)
	if err != nil {
		return fmt.Errorf("failed to deletesecret: %w", err)
	}
	return nil
}
