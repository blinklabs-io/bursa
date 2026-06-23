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

// Package webui serves the embedded Vite/React single-page app. It is a static
// file server with SPA fallback (unknown paths serve index.html) and a strict
// same-origin Content-Security-Policy.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed dist
var distFS embed.FS

// Handler serves the embedded SPA.
func Handler() http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic("webui: embedded dist missing: " + err.Error())
	}
	index, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		panic("webui: embedded dist/index.html missing: " + err.Error())
	}
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		// The SPA is read-only: serve only safe methods. A non-GET/HEAD request
		// that fell through the API routes is a misuse — return 405 rather than
		// masking it with a 200 HTML body.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// path.Clean collapses extra slashes and resolves dot-segments before we
		// key into the embedded FS, so e.g. "//assets/x" and "/../x" route
		// correctly (and traversal can't escape dist/).
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		// Serve real asset FILES (skip directories so http.FileServer can't emit
		// a directory listing of the embedded FS).
		if p != "" && p != "index.html" {
			if info, err := fs.Stat(sub, p); err == nil && !info.IsDir() {
				files.ServeHTTP(w, r) // a real asset
				return
			}
		}
		// Root, /index.html, or unknown client-route → SPA entry point. no-cache
		// so a redeploy's new asset hashes aren't masked by a stale cached index.
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(index)
	})
}
