// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !webview

package main

import (
	"context"
	"log/slog"
	"time"
)

// awaitUI (default, headless build) serves the wallet UI over loopback for the
// user's browser and blocks until a shutdown signal arrives or the control
// surface fails. This build is pure Go (CGO_ENABLED=0) — no GUI dependency.
func awaitUI(ctx context.Context, url string, _ *slog.Logger, srvErr <-chan error) error {
	if err := waitReachable(ctx, url, 15*time.Second, srvErr); err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		return nil
	case err := <-srvErr:
		return controlSurfaceError(err)
	}
}
