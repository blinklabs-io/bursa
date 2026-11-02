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

package api

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	bip39 "github.com/blinklabs-io/go-bip39"
)

var (
	sourceWords    = regexp.MustCompile(`[a-z]+`)
	privateKeyCBOR = regexp.MustCompile(
		`(?i)\b(?:5840[0-9a-f]{128}|5860[0-9a-f]{192}|5880[0-9a-f]{256})\b`,
	)
)

func TestTrackedAPIFixturesExcludeRecoveryMaterial(t *testing.T) {
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatalf("list API tests: %v", err)
	}

	for _, name := range files {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, source, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}

		ast.Inspect(file, func(node ast.Node) bool {
			expr, ok := node.(ast.Expr)
			if !ok {
				return true
			}
			value, ok := constantString(expr)
			if !ok {
				return true
			}
			containsRecovery := containsMnemonic(value)
			containsSigningKey := containsSerializedSigningKey(value)
			if containsRecovery {
				t.Errorf("%s contains a complete BIP-39 recovery phrase in tracked test source", name)
			}
			if containsSigningKey {
				t.Errorf("%s contains a serialized signing key in tracked test source", name)
			}
			return !containsRecovery && !containsSigningKey
		})
	}
}

func constantString(expr ast.Expr) (string, bool) {
	switch value := expr.(type) {
	case *ast.BasicLit:
		if value.Kind != token.STRING {
			return "", false
		}
		decoded, err := strconv.Unquote(value.Value)
		return decoded, err == nil
	case *ast.BinaryExpr:
		if value.Op != token.ADD {
			return "", false
		}
		left, leftOK := constantString(value.X)
		right, rightOK := constantString(value.Y)
		return left + right, leftOK && rightOK
	default:
		return "", false
	}
}

func containsMnemonic(value string) bool {
	words := sourceWords.FindAllString(strings.ToLower(value), -1)
	for _, count := range []int{12, 15, 18, 21, 24} {
		for start := 0; start+count <= len(words); start++ {
			if bip39.IsMnemonicValid(strings.Join(words[start:start+count], " ")) {
				return true
			}
		}
	}
	return false
}

func containsSerializedSigningKey(value string) bool {
	if privateKeyCBOR.MatchString(value) {
		return true
	}
	var decoded any
	if json.Unmarshal([]byte(value), &decoded) != nil {
		return false
	}
	return hasSigningKeyEnvelope(decoded)
}

func hasSigningKeyEnvelope(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		keyType, _ := typed["type"].(string)
		cborHex, _ := typed["cborHex"].(string)
		if strings.Contains(keyType, "SigningKey") && cborHex != "" {
			return true
		}
		for _, child := range typed {
			if hasSigningKeyEnvelope(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if hasSigningKeyEnvelope(child) {
				return true
			}
		}
	}
	return false
}
