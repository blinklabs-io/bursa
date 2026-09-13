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

package cli

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteWalletOutputsReturnsAllConcurrentErrors(t *testing.T) {
	alphaErr := errors.New("alpha failure")
	betaErr := errors.New("beta failure")
	fileMap := []map[string]string{
		{"beta.addr": "beta"},
		{"ok.addr": "ok"},
		{"alpha.addr": "alpha"},
	}

	for range 100 {
		started := make(chan struct{}, len(fileMap))
		release := make(chan struct{})
		var releaseOnce sync.Once
		go func() {
			for range fileMap {
				<-started
			}
			releaseOnce.Do(func() { close(release) })
		}()

		got := writeWalletOutputsWithWriter(
			"output",
			fileMap,
			func(path string, _ []byte) error {
				started <- struct{}{}
				<-release
				switch filepath.Base(path) {
				case "alpha.addr":
					return alphaErr
				case "beta.addr":
					return betaErr
				default:
					return nil
				}
			},
		)

		require.Error(t, got)
		require.ErrorIs(t, got, alphaErr)
		require.ErrorIs(t, got, betaErr)
		require.Equal(
			t,
			"failed to write wallet output alpha.addr: alpha failure\n"+
				"failed to write wallet output beta.addr: beta failure",
			got.Error(),
		)
	}
}
