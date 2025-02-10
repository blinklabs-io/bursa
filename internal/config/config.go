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

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	Api      ApiConfig     `yaml:"api"`
	Google   GoogleConfig  `yaml:"google"`
	Logging  LoggingConfig `yaml:"logging"`
	Metrics  MetricsConfig `yaml:"metrics"`
	Mnemonic string        `yaml:"mnemonic" envconfig:"MNEMONIC"`
	Network  string        `yaml:"cardano_network"  envconfig:"CARDANO_NETWORK"`
}

type ApiConfig struct {
	ListenAddress string `yaml:"address" envconfig:"API_LISTEN_ADDRESS"`
	ListenPort    uint   `yaml:"port"    envconfig:"API_LISTEN_PORT"`
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

// We use a singleton for the config for convenience
var globalConfig = Config{
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
	Metrics: MetricsConfig{
		ListenAddress: "",
		ListenPort:    8081,
	},
	Mnemonic: "",
	Network:  "mainnet",
}

func GetConfig() *Config {
	return &globalConfig
}

func LoadConfig() (*Config, error) {
	if err := envconfig.Process("bursa", &globalConfig); err != nil {
		return nil, fmt.Errorf(
			"failed loading config from environment: %s",
			err,
		)
	}
	return &globalConfig, nil
}
