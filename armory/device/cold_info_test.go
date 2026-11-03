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

package device

import (
	"bytes"
	"crypto/ed25519"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// cold/info describes only a key in the cold key range that exists, and
// writes nothing: a key object outside the range is not reported as a cold
// key, and a missing key gets no origin record.
func TestColdInfoRefusals(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		id   uint32
		want string
	}{
		"below range": {coldKeyFirst - 1, "outside the cold key range"},
		"above range": {coldKeyLast + 1, "outside the cold key range"},
		"missing key": {coldKeyFirst + 5, "cold key not provisioned"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s, chip := newTestService(t)

			// a key outside the range is present, so only the range check
			// refuses it
			if tc.id < coldKeyFirst || tc.id > coldKeyLast {
				chip.keys[tc.id] = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
			}

			before := len(chip.bins)

			code, _, body := postCold(t, s, "/provision/cold/info", map[string]any{"cold_key_id": tc.id})
			if code != http.StatusBadRequest || !strings.Contains(body, tc.want) {
				t.Fatalf("got %d %s, want 400 %s", code, body, tc.want)
			}

			if _, ok := chip.bins[coldOriginID(tc.id)]; ok || len(chip.bins) != before {
				t.Fatal("cold/info wrote to the chip")
			}
		})
	}
}

// The origin record is written only where a cold key is created: writeOrigin
// is called only by generateCold and importCold, and it is the only code that
// writes an origin object. Any other writer could relabel an imported key as
// generated.
func TestColdOriginWriters(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}

	originNames := []string{"coldOriginID", "coldOriginFirst", "coldOriginLast", "coldOriginOffset"}

	var callers, writers []string

	fset := token.NewFileSet()

	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}

		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}

		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}

			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.SelectorExpr:
					// any use, called or passed as a value
					if n.Sel.Name == "writeOrigin" {
						callers = append(callers, fn.Name.Name)
					}
				case *ast.CallExpr:
					sel, ok := n.Fun.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "WriteBinary" || len(n.Args) == 0 {
						return true
					}

					ast.Inspect(n.Args[0], func(a ast.Node) bool {
						if id, ok := a.(*ast.Ident); ok && slices.Contains(originNames, id.Name) {
							writers = append(writers, fn.Name.Name)
						}

						return true
					})
				}

				return true
			})
		}
	}

	slices.Sort(callers)

	if want := []string{"generateCold", "importCold"}; !slices.Equal(callers, want) {
		t.Errorf("writeOrigin used by %v, want only %v", callers, want)
	}

	if want := []string{"writeOrigin"}; !slices.Equal(writers, want) {
		t.Errorf("origin objects written by %v, want only %v", writers, want)
	}
}

// Once a host key is registered, /provision/cold/info refuses an unsigned
// request like every other provisioning route.
func TestColdInfoRefusesUnsignedWithHostKey(t *testing.T) {
	t.Parallel()

	s, _ := newHostAuthService(t)

	code, body := rawPost(s.ProvisioningHandler(), "/provision/cold/info", jsonOf(t, ColdInfoRequest{ColdKeyID: testColdID}))
	if code == http.StatusOK {
		t.Fatalf("unsigned cold info request accepted: %s", body)
	}

	if !strings.Contains(string(body), errHostKeyUnknown.Error()) {
		t.Fatalf("refused for another reason: %s", body)
	}
}

// A cold info request signed by the registered host key is answered.
func TestColdInfoAcceptsSignedWithHostKey(t *testing.T) {
	t.Parallel()

	s, _ := newHostAuthService(t)

	code, body := postAs(t, s.ProvisioningHandler(), "/provision/cold/info", ColdInfoRequest{ColdKeyID: testColdID}, testHostKey)
	if code != http.StatusOK {
		t.Fatalf("signed cold info request refused: %d %s", code, body)
	}
}
