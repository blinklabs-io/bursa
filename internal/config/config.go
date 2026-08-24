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
	Google   GoogleConfig   `yaml:"google"`
	Logging  LoggingConfig  `yaml:"logging"`
	Mnemonic string         `yaml:"mnemonic"        envconfig:"MNEMONIC"`
	Network  string         `yaml:"cardano_network" envconfig:"CARDANO_NETWORK"`
	Api      ApiConfig      `yaml:"api"`
	Metrics  MetricsConfig  `yaml:"metrics"`
	Debug    DebugConfig    `yaml:"debug"`
	Storage  StorageConfig  `yaml:"storage"`
	Signer   SignerConfig   `yaml:"signer"`
	KESAgent KESAgentConfig `yaml:"kes_agent"`
}

// KESAgentConfig holds configuration for the bursa KES agent daemon.
type KESAgentConfig struct {
	// Mode is "serve-key" (push the KES signing key to the producer) or "sign"
	// (sign block headers on the producer's behalf; key never leaves the agent).
	Mode string `yaml:"mode" envconfig:"KESAGENT_MODE"`
	// ServiceSocket is the Unix socket the producer connects to.
	ServiceSocket string `yaml:"service_socket" envconfig:"KESAGENT_SERVICE_SOCKET"`
	// ControlSocket is the Unix socket for gen/install/drop/info commands.
	ControlSocket string `yaml:"control_socket" envconfig:"KESAGENT_CONTROL_SOCKET"`
	// ServiceSocketMode is the octal file mode for the service socket, which
	// the block producer connects to (default 0600). It may be widened (e.g.
	// "0660" with the producer added to the agent's group) to let a
	// different-UID producer reach it.
	ServiceSocketMode string `yaml:"service_socket_mode" envconfig:"KESAGENT_SERVICE_SOCKET_MODE"`
	// ControlSocketMode is the octal file mode for the control socket, which
	// handles gen-staged-key/install-key/drop-key/info (default 0600). It must
	// never be widened to group/other access: those commands can drop or
	// install KES keys.
	ControlSocketMode string `yaml:"control_socket_mode" envconfig:"KESAGENT_CONTROL_SOCKET_MODE"`
	// ColdVKeyFile is a path to the pool cold verification key (cardano-cli
	// text envelope or raw/hex). The agent only ever holds the cold vkey.
	ColdVKeyFile string `yaml:"cold_vkey_file" envconfig:"KESAGENT_COLD_VKEY_FILE"`
	// ColdVKeyHex is the cold verification key as hex (alternative to the file).
	ColdVKeyHex string `yaml:"cold_vkey_hex" envconfig:"KESAGENT_COLD_VKEY_HEX"`
	// SystemStart is the Shelley genesis system start (RFC3339).
	SystemStart string `yaml:"system_start" envconfig:"KESAGENT_SYSTEM_START"`
	// SlotLength is the wall-clock length of one slot in seconds (default 1).
	SlotLength float64 `yaml:"slot_length" envconfig:"KESAGENT_SLOT_LENGTH"`
	// SlotsPerKESPeriod is the number of slots per KES period (e.g. 129600).
	SlotsPerKESPeriod uint64 `yaml:"slots_per_kes_period" envconfig:"KESAGENT_SLOTS_PER_KES_PERIOD"`
	// MaxKESEvolutions is the max opcert evolutions (mainnet 62).
	MaxKESEvolutions uint64 `yaml:"max_kes_evolutions" envconfig:"KESAGENT_MAX_KES_EVOLUTIONS"`
	// EvolveInterval is the scheduler tick as a Go duration string (default 1m).
	EvolveInterval string `yaml:"evolve_interval" envconfig:"KESAGENT_EVOLVE_INTERVAL"`
	// GuardFile is the durable monotonic-period store path.
	GuardFile string `yaml:"guard_file" envconfig:"KESAGENT_GUARD_FILE"`
}

// SignerConfig holds configuration for the bursa signer daemon.
type SignerConfig struct {
	ListenAddress string `yaml:"listen_address" envconfig:"SIGNER_LISTEN_ADDRESS"`
	ListenPort    uint   `yaml:"listen_port"    envconfig:"SIGNER_LISTEN_PORT"`
	JWTSecret     string `yaml:"jwt_secret"     envconfig:"SIGNER_JWT_SECRET"`
	JWKSURL       string `yaml:"jwks_url"       envconfig:"SIGNER_JWKS_URL"`
	JWTIssuer     string `yaml:"jwt_issuer"     envconfig:"SIGNER_JWT_ISSUER"`
	JWTAudience   string `yaml:"jwt_audience"   envconfig:"SIGNER_JWT_AUDIENCE"`
	TLSCertFile   string `yaml:"tls_cert_file"  envconfig:"SIGNER_TLS_CERT_FILE"`
	TLSKeyFile    string `yaml:"tls_key_file"   envconfig:"SIGNER_TLS_KEY_FILE"`
	// ClientCACert is a PEM file of CA certificate(s) used to verify TLS client
	// certificates (mTLS). When set, TLS client-cert auth is enabled and the
	// caller identity is derived from the verified client certificate.
	ClientCACert string `yaml:"client_ca_cert" envconfig:"SIGNER_CLIENT_CA_CERT"`
	// RequireClientCert makes a verified client certificate mandatory on every
	// connection (tls.RequireAndVerifyClientCert). When false and ClientCACert
	// is set, a client cert is optional (tls.VerifyClientCertIfGiven) and other
	// auth modes remain available on connections without one.
	RequireClientCert bool `yaml:"require_client_cert" envconfig:"SIGNER_REQUIRE_CLIENT_CERT"`
	// RequestSignSkewSeconds is the ± timestamp window (seconds) accepted for
	// authorized-keys request signatures. Zero uses the 60s default.
	RequestSignSkewSeconds int `yaml:"request_sign_skew_seconds" envconfig:"SIGNER_REQUEST_SIGN_SKEW_SECONDS"`
	// AllowInsecureFileBackend opts in to running the plaintext software/file
	// key backend while bound to a non-loopback address. The software backend
	// loads private key material into process memory and is intended for
	// development only; production deployments should use a Vault or SOPS
	// backend. Defaults to false: boot fails if a software/file backend is
	// configured on a non-loopback listen address without this flag.
	AllowInsecureFileBackend bool                        `yaml:"allow_insecure_file_backend" envconfig:"SIGNER_ALLOW_INSECURE_FILE_BACKEND"`
	Watermark                SignerWatermarkConfig       `yaml:"watermark"`
	Backends                 []SignerBackendConfig       `yaml:"backends"`
	Keys                     []SignerKeyConfig           `yaml:"keys"`
	Callers                  []SignerCallerConfig        `yaml:"callers"`
	AuthorizedKeys           []SignerAuthorizedKeyConfig `yaml:"authorized_keys"`
	// CallerPolicies optionally narrows a caller's authority for specific keys.
	// Shape: caller subject -> key hash (hex) -> tx-policy overrides (mapped to
	// policy.CallerTxOverride at setup). An override can only further restrict
	// the key's base policy (intersection); it never widens authority.
	CallerPolicies map[string]map[string]map[string]any `yaml:"caller_policies"`
	// PolicyHookURL, when set, enables an external policy hook: after the static
	// policy allows, the signer POSTs the parsed operation summary and signs only
	// on an allow response (fail closed). Off by default.
	PolicyHookURL       string `yaml:"policy_hook_url"        envconfig:"SIGNER_POLICY_HOOK_URL"`
	PolicyHookTimeoutMs uint   `yaml:"policy_hook_timeout_ms" envconfig:"SIGNER_POLICY_HOOK_TIMEOUT_MS"`
}

// SignerAuthorizedKeyConfig registers an Ed25519 public key that may
// authenticate via the authorized-keys request-signing scheme. Caller is the
// identity fed to the CallerACL; Ed25519PubkeyHex is the hex-encoded 32-byte
// public key that must verify the request signature.
type SignerAuthorizedKeyConfig struct {
	Caller           string `yaml:"caller"`
	Ed25519PubkeyHex string `yaml:"ed25519_pubkey_hex"`
}

// SignerCallerConfig grants a JWT subject access to specific keys.
// When any callers are configured, unlisted subjects are denied all keys.
type SignerCallerConfig struct {
	Subject string   `yaml:"subject"`
	Keys    []string `yaml:"keys"` // key hashes (hex blake2b-224)
}

// SignerWatermarkConfig configures the anti-double-sign watermark store.
type SignerWatermarkConfig struct {
	Type string `yaml:"type"` // "mem" | "file"
	Path string `yaml:"path"`
	Mode string `yaml:"mode"` // "off" | "warn" | "enforce"
}

// SignerBackendConfig configures a key-custody backend.
type SignerBackendConfig struct {
	Name          string                   `yaml:"name"`
	Type          string                   `yaml:"type"`           // "software" | "sops" | "vault" | "pkcs11"
	Path          string                   `yaml:"path"`           // software: key dir
	PassphraseEnv string                   `yaml:"passphrase_env"` // software: env var holding the key-file passphrase
	SecretPrefix  string                   `yaml:"secret_prefix"`  // sops: secret short-name prefix within google.project
	Address       string                   `yaml:"address"`        // vault
	TransitMount  string                   `yaml:"transit_mount"`  // vault
	TokenEnv      string                   `yaml:"token_env"`      // vault: env var holding the token (default VAULT_TOKEN)
	Module        string                   `yaml:"module"`         // pkcs11: path to the PKCS#11 module (.so)
	TokenLabel    string                   `yaml:"token_label"`    // pkcs11: token label used to select the slot
	Slot          *uint                    `yaml:"slot"`           // pkcs11: explicit slot id (alternative to token_label)
	PINEnv        string                   `yaml:"pin_env"`        // pkcs11: env var holding the user PIN (never stored in config)
	Keys          []SignerBackendKeyConfig `yaml:"keys"`           // vault: explicit transit key list; pkcs11: optional CKA_LABEL filter + key type
}

// SignerBackendKeyConfig names a remote key and its Cardano key type. For vault
// Name is the transit key name; for pkcs11 Name is the object's CKA_LABEL.
type SignerBackendKeyConfig struct {
	Name string `yaml:"name"`
	Type string `yaml:"type"` // payment|stake|drep|cc-hot|cc-cold|pool|policy
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
	ListenAddress string `yaml:"address"     envconfig:"API_LISTEN_ADDRESS"`
	ListenPort    uint   `yaml:"port"        envconfig:"API_LISTEN_PORT"`
	// JWTSecret enables HS256 bearer authentication for sensitive legacy API
	// routes. Keep it in an environment variable or an external secret store;
	// do not commit it to a config file.
	JWTSecret string `yaml:"jwt_secret" envconfig:"API_JWT_SECRET"`
	// JWKSURL enables RS256, ES256, or EdDSA bearer authentication. It is
	// mutually exclusive with JWTSecret and must use HTTPS except on loopback.
	JWKSURL     string `yaml:"jwks_url" envconfig:"API_JWKS_URL"`
	JWTIssuer   string `yaml:"jwt_issuer" envconfig:"API_JWT_ISSUER"`
	JWTAudience string `yaml:"jwt_audience" envconfig:"API_JWT_AUDIENCE"`
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
			ListenAddress: "127.0.0.1",
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
		KESAgent: KESAgentConfig{
			SlotLength:        1,
			MaxKESEvolutions:  62,
			ServiceSocketMode: "0600",
			ControlSocketMode: "0600",
			EvolveInterval:    "1m",
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
