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

package backend

import (
	"context"
	"errors"
	"fmt"
)

// Resolver fans a key-hash lookup across multiple backends.
type Resolver struct {
	backends []Backend
}

// NewResolver builds a resolver over the given backends, queried in order.
func NewResolver(backends ...Backend) *Resolver {
	return &Resolver{backends: backends}
}

// profileOf reports the profile a backend is bound to, or "".
func profileOf(b Backend) string {
	if p, ok := b.(Profiled); ok {
		return p.Profile()
	}
	return ""
}

// Resolve returns the KeyRef for hash from the backend selected by profile.
//
// With no profile, the single backend holding hash serves it; if several hold
// it, Resolve returns ErrProfileRequired. With a profile, a profiled holder
// serves it only under exactly that profile; a holder with another profile
// does not match, and the result is ErrKeyNotFound. A hash held by an
// unprofiled backend is not network scoped (CheckAmbiguous keeps it out of
// every profiled backend), so that backend serves it whatever the profile, and
// a tx naming a profile for one signer still reaches its unprofiled signers.
// The profile selects a route and never authorizes.
func (r *Resolver) Resolve(ctx context.Context, hash KeyHash, profile string) (KeyRef, error) {
	var found KeyRef
	matches := 0
	for _, b := range r.backends {
		if bp := profileOf(b); profile != "" && bp != "" && bp != profile {
			continue
		}
		ref, err := b.GetKey(ctx, hash)
		if errors.Is(err, ErrKeyNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if profile != "" {
			return ref, nil
		}
		if found == nil {
			found = ref
		}
		matches++
	}
	switch {
	case matches > 1:
		return nil, ErrProfileRequired
	case found != nil:
		return found, nil
	}
	return nil, ErrKeyNotFound
}

// ListKeys returns every key across all backends.
func (r *Resolver) ListKeys(ctx context.Context) ([]KeyRef, error) {
	var out []KeyRef
	for _, b := range r.backends {
		keys, err := b.ListKeys(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, keys...)
	}
	return out, nil
}

// CheckAmbiguous returns an error if a KeyHash is routed ambiguously. The same
// hash may appear in several backends only when every backend holding it has a
// non-empty profile and the profiles are distinct; requests then select a
// backend by profile. A hash in an unprofiled backend and any other backend, or
// in two backends with the same profile, is a configuration error. This should
// be called once at startup before serving.
func (r *Resolver) CheckAmbiguous(ctx context.Context) error {
	type holder struct{ backend, profile string }
	seen := make(map[KeyHash][]holder)
	for _, b := range r.backends {
		keys, err := b.ListKeys(ctx)
		if err != nil {
			return fmt.Errorf("list keys from backend %q: %w", b.Name(), err)
		}
		profile := profileOf(b)
		for _, k := range keys {
			h := k.Hash()
			for _, prev := range seen[h] {
				if prev.profile == "" || profile == "" {
					return fmt.Errorf(
						"key hash %s appears in both backend %q and %q; a key may be held by several backends only when each has a distinct profile",
						h.String(), prev.backend, b.Name(),
					)
				}
				if prev.profile == profile {
					return fmt.Errorf(
						"key hash %s appears in both backend %q and %q under the same profile %q",
						h.String(), prev.backend, b.Name(), profile,
					)
				}
			}
			seen[h] = append(seen[h], holder{b.Name(), profile})
		}
	}
	return nil
}
