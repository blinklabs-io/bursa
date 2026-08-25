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

//go:build !pkcs11

package backend

import "errors"

// ErrPKCS11NotCompiled is returned by the pure-Go build, where the PKCS#11
// backend (which requires CGO) is not compiled in. Build with -tags pkcs11 and
// CGO_ENABLED=1 to enable it.
var ErrPKCS11NotCompiled = errors.New("pkcs11 backend not compiled in (build with -tags pkcs11)")

// NewPKCS11Backend is the pure-Go stub. It matches the tagged constructor's
// signature so setup wiring compiles under CGO_ENABLED=0, and always fails.
func NewPKCS11Backend(_ PKCS11Config) (Backend, error) {
	return nil, ErrPKCS11NotCompiled
}
