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

package storage

import (
	"errors"

	"github.com/blinklabs-io/bursa/internal/config"
)

// NewStore creates a new storage backend based on the provided
// configuration. It returns the appropriate Store implementation
// for the configured backend type.
func NewStore(cfg *config.Config) (Store, error) {
	switch cfg.Storage.Backend {
	case "file":
		if cfg.Storage.Dir == "" {
			return nil, errors.New(
				"storage dir is required for file backend",
			)
		}
		return NewFileStore(cfg.Storage.Dir), nil
	case "sqlite":
		if cfg.Storage.DSN == "" {
			return nil, errors.New(
				"storage dsn is required for sqlite backend",
			)
		}
		return NewSQLiteStore(cfg.Storage.DSN)
	case "gcp":
		return NewGCPStore(), nil
	default:
		// Fall back to GCP if Google project is configured
		if cfg.Google.Project != "" &&
			cfg.Google.ResourceId != "" {
			return NewGCPStore(), nil
		}
		return nil, errors.New(
			"no storage backend configured",
		)
	}
}
