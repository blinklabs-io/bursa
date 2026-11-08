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

package main

import (
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/internal/config"
)

func TestKesAgentStoreDSN(t *testing.T) {
	t.Setenv("BURSA_TEST_KESAGENT_STORE_DSN", "postgres://u:p@localhost/db")
	t.Setenv("BURSA_TEST_KESAGENT_STORE_EMPTY", "")
	tests := []struct {
		name    string
		in      config.KESAgentStoreConfig
		want    string
		wantErr string
	}{
		{name: "unset is the file store", in: config.KESAgentStoreConfig{}},
		{
			name: "explicit file store",
			in:   config.KESAgentStoreConfig{Type: "file"},
		},
		{
			name: "postgres reads dsn_env",
			in: config.KESAgentStoreConfig{
				Type:   "postgres",
				DSNEnv: "BURSA_TEST_KESAGENT_STORE_DSN",
			},
			want: "postgres://u:p@localhost/db",
		},
		{
			name:    "postgres without dsn_env",
			in:      config.KESAgentStoreConfig{Type: "postgres"},
			wantErr: "requires kes_agent.store.dsn_env",
		},
		{
			name: "postgres with an empty variable",
			in: config.KESAgentStoreConfig{
				Type:   "postgres",
				DSNEnv: "BURSA_TEST_KESAGENT_STORE_EMPTY",
			},
			wantErr: "environment variable is empty",
		},
		{
			name: "dsn_env without postgres",
			in: config.KESAgentStoreConfig{
				DSNEnv: "BURSA_TEST_KESAGENT_STORE_DSN",
			},
			wantErr: "is not \"postgres\"",
		},
		{
			name:    "unknown type",
			in:      config.KESAgentStoreConfig{Type: "sqlite"},
			wantErr: "must be \"file\" or \"postgres\"",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := kesAgentStoreDSN(tc.in)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("kesAgentStoreDSN: %v", err)
			}
			if got != tc.want {
				t.Fatalf("dsn = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestOpenKesAgentStoreRefusesRemotePlaintext checks that a non-loopback
// PostgreSQL host without sslmode=verify-full is refused before connecting.
func TestOpenKesAgentStoreRefusesRemotePlaintext(t *testing.T) {
	t.Setenv(
		"BURSA_TEST_KESAGENT_STORE_REMOTE",
		"postgres://u:p@db.example.invalid/db?sslmode=require",
	)
	store, err := openKesAgentStore(config.KESAgentStoreConfig{
		Type:   "postgres",
		DSNEnv: "BURSA_TEST_KESAGENT_STORE_REMOTE",
	})
	if err == nil {
		store.Close()
		t.Fatal("opened a remote store without verify-full")
	}
	if !strings.Contains(err.Error(), "verify-full") {
		t.Fatalf("err = %v, want a verify-full refusal", err)
	}
}

func TestOpenKesAgentStoreFileIsNil(t *testing.T) {
	store, err := openKesAgentStore(config.KESAgentStoreConfig{})
	if err != nil || store != nil {
		t.Fatalf("file store: store = %v, err = %v; want nil, nil", store, err)
	}
}
