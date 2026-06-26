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

package main

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

func controlSurfaceError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("control surface: %w", err)
}

// waitReachable polls url until it answers, startup fails, ctx is canceled, or
// timeout elapses.
func waitReachable(ctx context.Context, url string, timeout time.Duration, srvErr <-chan error) error {
	if timeout <= 0 {
		return nil
	}

	client := &http.Client{Timeout: time.Second}
	timeoutTimer := time.NewTimer(timeout)
	defer timeoutTimer.Stop()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-srvErr:
			return controlSurfaceError(err)
		default:
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("readiness probe: %w", err)
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			select {
			case err := <-srvErr:
				return controlSurfaceError(err)
			default:
				return nil
			}
		}

		select {
		case <-ctx.Done():
			return nil
		case err := <-srvErr:
			return controlSurfaceError(err)
		case <-timeoutTimer.C:
			return nil
		case <-ticker.C:
		}
	}
}
