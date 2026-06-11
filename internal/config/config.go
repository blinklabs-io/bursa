// Copyright 2024 Blink Labs Software
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

package config

import (
	"fmt"
	"os"

	"github.com/kelseyhightower/envconfig"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Google   GoogleConfig  `yaml:"google"`
	Logging  LoggingConfig `yaml:"logging"`
	Mnemonic string        `yaml:"mnemonic"        envconfig:"MNEMONIC"`
	Network  string        `yaml:"cardano_network" envconfig:"CARDANO_NETWORK"`
	Api      ApiConfig     `yaml:"api"`
	Metrics  MetricsConfig `yaml:"metrics"`
	Debug    DebugConfig   `yaml:"debug"`
	Storage  StorageConfig `yaml:"storage"`
	Signer   SignerConfig  `yaml:"signer"`
}

// SignerConfig holds configuration for the bursa signer daemon.
type SignerConfig struct {
	ListenAddress string                `yaml:"listen_address" envconfig:"SIGNER_LISTEN_ADDRESS"`
	ListenPort    uint                  `yaml:"listen_port"    envconfig:"SIGNER_LISTEN_PORT"`
	JWTSecret     string                `yaml:"jwt_secret"     envconfig:"SIGNER_JWT_SECRET"`
	TLSCertFile   string                `yaml:"tls_cert_file"  envconfig:"SIGNER_TLS_CERT_FILE"`
	TLSKeyFile    string                `yaml:"tls_key_file"   envconfig:"SIGNER_TLS_KEY_FILE"`
	Watermark     SignerWatermarkConfig `yaml:"watermark"`
	Backends      []SignerBackendConfig `yaml:"backends"`
	Keys          []SignerKeyConfig     `yaml:"keys"`
}

// SignerWatermarkConfig configures the anti-double-sign watermark store.
type SignerWatermarkConfig struct {
	Type string `yaml:"type"` // "mem" | "file"
	Path string `yaml:"path"`
	Mode string `yaml:"mode"` // "off" | "warn" | "enforce"
}

// SignerBackendConfig configures a key-custody backend.
type SignerBackendConfig struct {
	Name          string `yaml:"name"`
	Type          string `yaml:"type"`           // "software" | "sops" | "vault"
	Path          string `yaml:"path"`           // software: key dir
	PassphraseEnv string `yaml:"passphrase_env"` // reserved for sops follow-up; not yet honored
	SecretPrefix  string `yaml:"secret_prefix"`  // sops
	Address       string `yaml:"address"`        // vault
	TransitMount  string `yaml:"transit_mount"`  // vault
}

// SignerKeyConfig mirrors policy.KeyPolicy in YAML; mapped at setup time.
type SignerKeyConfig struct {
	Hash            string   `yaml:"hash"`
	Backend         string   `yaml:"backend"`
	AllowedRequests []string `yaml:"allowed_requests"`
	// TxPolicy and CIP8Policy are decoded as raw maps and mapped to typed
	// policy structs in internal/signer/setup.go via JSON round-trip.
	TxPolicy   map[string]any `yaml:"tx_policy"`
	CIP8Policy map[string]any `yaml:"cip8_policy"`
}

type StorageConfig struct {
	Backend string `yaml:"backend" envconfig:"STORAGE_BACKEND"`
	Dir     string `yaml:"dir"     envconfig:"STORAGE_DIR"`
	DSN     string `yaml:"dsn"     envconfig:"STORAGE_DSN"`
}

type ApiConfig struct {
	ListenAddress string `yaml:"address" envconfig:"API_LISTEN_ADDRESS"`
	ListenPort    uint   `yaml:"port"    envconfig:"API_LISTEN_PORT"`
}

type DebugConfig struct {
	ListenAddress string `yaml:"address" envconfig:"DEBUG_LISTEN_ADDRESS"`
	ListenPort    uint   `yaml:"port"    envconfig:"DEBUG_LISTEN_PORT"`
}

type GoogleConfig struct {
	Project    string `yaml:"project"         envconfig:"GOOGLE_PROJECT"`
	ResourceId string `yaml:"kms_resource_id" envconfig:"GCP_KMS_RESOURCE_ID"`
	Prefix     string `yaml:"secret_prefix"   envconfig:"GCP_SECRET_PREFIX"`
}

type LoggingConfig struct {
	Level string `yaml:"level" envconfig:"LOGGING_LEVEL"`
}

type MetricsConfig struct {
	ListenAddress string `yaml:"address" envconfig:"METRICS_LISTEN_ADDRESS"`
	ListenPort    uint   `yaml:"port"    envconfig:"METRICS_LISTEN_PORT"`
}

// defaultConfig returns the default configuration. It is used to initialise
// globalConfig and to reset it between tests.
func defaultConfig() Config {
	return Config{
		Api: ApiConfig{
			ListenAddress: "",
			ListenPort:    8080,
		},
		Google: GoogleConfig{
			Prefix: "bursa-wallet-",
		},
		Logging: LoggingConfig{
			Level: "info",
		},
		Debug: DebugConfig{
			ListenAddress: "",
			ListenPort:    0,
		},
		Metrics: MetricsConfig{
			ListenAddress: "",
			ListenPort:    8081,
		},
		Mnemonic: "",
		Network:  "mainnet",
		Storage: StorageConfig{
			Backend: "",
		},
		Signer: SignerConfig{
			ListenAddress: "",
			ListenPort:    8090,
			Watermark: SignerWatermarkConfig{
				Type: "mem",
				Mode: "enforce",
			},
		},
	}
}

// We use a singleton for the config for convenience
var globalConfig = defaultConfig()

func GetConfig() *Config {
	return &globalConfig
}

func LoadConfig() (*Config, error) {
	if err := envconfig.Process("bursa", &globalConfig); err != nil {
		return nil, fmt.Errorf(
			"failed loading config from environment: %w",
			err,
		)
	}
	return &globalConfig, nil
}

// LoadConfigFile reads a YAML config file into globalConfig and then applies
// environment-variable overrides via envconfig. A missing or empty path falls
// back to env-only loading (current behaviour preserved).
func LoadConfigFile(path string) (*Config, error) {
	globalConfig = defaultConfig()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
		}
		if err := yaml.Unmarshal(data, &globalConfig); err != nil {
			return nil, fmt.Errorf("failed to parse config file %q: %w", path, err)
		}
	}
	if err := envconfig.Process("bursa", &globalConfig); err != nil {
		return nil, fmt.Errorf(
			"failed loading config from environment: %w",
			err,
		)
	}
	return &globalConfig, nil
}
