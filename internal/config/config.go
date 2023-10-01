// Copyright 2023 Blink Labs, LLC.
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
	Logging  LoggingConfig `yaml:"logging"`
	Mnemonic string        `yaml:"mnemonic" envconfig:"MNEMONIC"`
	Network  string        `yaml:"network" envconfig:"NETWORK"`
}

type ApiConfig struct {
	ListenAddress string `yaml:"address" envconfig:"API_LISTEN_ADDRESS"`
	ListenPort    uint   `yaml:"port" envconfig:"API_LISTEN_PORT"`
}

type LoggingConfig struct {
	Level string `yaml:"level" envconfig:"LOGGING_LEVEL"`
}

// We use a singleton for the config for convenience
var globalConfig = Config{
	Api: ApiConfig{
		ListenAddress: "",
		ListenPort:    8080,
	},
	Logging: LoggingConfig{
		Level: "info",
	},
	Mnemonic: "",
	Network:  "mainnet",
}

func GetConfig() *Config {
	return &globalConfig
}

func LoadConfig() (*Config, error) {
	if err := envconfig.Process("bursa", &globalConfig); err != nil {
		return nil, fmt.Errorf("failed loading config from environment: %s", err)
	}
	return &globalConfig, nil
}
