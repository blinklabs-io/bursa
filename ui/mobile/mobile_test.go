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
package mobile

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/ui/internal/boot"
)

// TestNewHandleLifecycleBeforeStart verifies the pre-Start contract the
// Android/iOS shells rely on: a fresh handle reports port 0, and Stop is a
// harmless no-op before a successful Start (so a shell that tears down after a
// failed Start does not panic). This exercises the binding without spinning up a
// real node.
func TestNewHandleLifecycleBeforeStart(t *testing.T) {
	a := New()
	if a == nil {
		t.Fatal("New returned nil")
	}
	if got := a.Port(); got != 0 {
		t.Fatalf("Port before Start = %d, want 0", got)
	}
	if err := a.Stop(); err != nil {
		t.Fatalf("Stop before Start = %v, want nil", err)
	}
}

// gomobileSupported is true only for the value types gomobile can marshal
// across the language boundary, plus exported struct pointers (treated as
// opaque handles).
func gomobileSupported(kind string) bool {
	switch kind {
	case "bool", "int", "int64", "float32", "float64", "string", "[]byte", "error",
		"*mobile.App": // exported struct pointer — crosses as an opaque handle
		return true
	}
	return false
}

func gomobileTypeName(typ reflect.Type) string {
	if typ.Kind() == reflect.Slice && typ.Elem().Kind() == reflect.Uint8 {
		return "[]byte"
	}
	return typ.String()
}

func assertGomobileInputs(t *testing.T, name string, typ reflect.Type, offset int, params []string) {
	t.Helper()
	if typ.NumIn()-offset != len(params) {
		t.Fatalf("%s param count = %d, want %d", name, typ.NumIn()-offset, len(params))
	}
	for i, want := range params {
		got := gomobileTypeName(typ.In(i + offset))
		if got != want {
			t.Fatalf("%s param %d = %q, want %q", name, i, got, want)
		}
		if !gomobileSupported(got) {
			t.Fatalf("%s param %d type %q is not gomobile-compatible", name, i, got)
		}
	}
}

func assertGomobileResults(t *testing.T, name string, typ reflect.Type, results []string) {
	t.Helper()
	if typ.NumOut() != len(results) {
		t.Fatalf("%s result count = %d, want %d", name, typ.NumOut(), len(results))
	}
	for i, want := range results {
		got := gomobileTypeName(typ.Out(i))
		if got != want {
			t.Fatalf("%s result %d = %q, want %q", name, i, got, want)
		}
		if !gomobileSupported(got) {
			t.Fatalf("%s result %d type %q is not gomobile-compatible", name, i, got)
		}
	}
}

func assertGomobileFunc(t *testing.T, name string, typ reflect.Type, params, results []string) {
	t.Helper()
	assertGomobileInputs(t, name, typ, 0, params)
	assertGomobileResults(t, name, typ, results)
}

func assertGomobileMethod(t *testing.T, appType reflect.Type, name string, params, results []string) {
	t.Helper()
	method, ok := appType.MethodByName(name)
	if !ok {
		t.Fatalf("missing exported method %s", name)
	}
	typ := method.Type
	if typ.NumIn() == 0 || typ.In(0) != appType {
		t.Fatalf("%s has unexpected receiver signature %s", name, typ)
	}
	assertGomobileInputs(t, name, typ, 1, params)
	assertGomobileResults(t, name, typ, results)
}

// TestBindingSignaturesAreGomobileCompatible is a guard against accidentally
// adding an exported binding method (or a New return) whose parameter/return
// types gomobile cannot marshal. It reflects on the actual exported functions
// and methods so signature drift fails in plain `go test`, before CI reaches
// `gomobile bind`.
func TestBindingSignaturesAreGomobileCompatible(t *testing.T) {
	assertGomobileFunc(t, "New", reflect.TypeOf(New), nil, []string{"*mobile.App"})

	type sig struct {
		method string
		params []string
		result []string
	}
	sigs := []sig{
		{"Start", []string{"string", "string", "bool"}, []string{"error"}},
		{"StartWithTimeout", []string{"string", "string", "bool", "int64"}, []string{"error"}},
		{"Port", nil, []string{"int"}},
		{"Stop", nil, []string{"error"}},
		{"OnNetworkChanged", nil, []string{"error"}},
		{"OnResume", nil, []string{"error"}},
	}
	appType := reflect.TypeOf((*App)(nil))
	expected := make(map[string]struct{}, len(sigs))
	for _, s := range sigs {
		expected[s.method] = struct{}{}
	}
	for i := 0; i < appType.NumMethod(); i++ {
		method := appType.Method(i)
		if _, ok := expected[method.Name]; !ok {
			t.Fatalf("unexpected exported App method %s; add it to the gomobile signature guard or unexport it", method.Name)
		}
	}
	for _, s := range sigs {
		assertGomobileMethod(t, appType, s.method, s.params, s.result)
	}
}

func TestStartWithTimeoutReturnsOnStalledBoot(t *testing.T) {
	orig := bootWallet
	defer func() { bootWallet = orig }()

	started := make(chan struct{})
	release := make(chan struct{})
	bootWallet = func(context.Context, boot.Config) (*boot.App, error) {
		close(started)
		<-release
		return nil, context.Canceled
	}
	defer close(release)

	a := New()
	errCh := make(chan error, 1)
	go func() {
		errCh <- a.StartWithTimeout(t.TempDir(), "preview", true, 25)
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("boot did not start")
	}
	select {
	case err := <-errCh:
		if !errors.Is(err, errStartTimeout) {
			t.Fatalf("StartWithTimeout = %v, want errStartTimeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("StartWithTimeout did not return after timeout")
	}
}

func TestStopCancelsStartInProgress(t *testing.T) {
	orig := bootWallet
	defer func() { bootWallet = orig }()

	started := make(chan struct{})
	bootWallet = func(ctx context.Context, _ boot.Config) (*boot.App, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}

	a := New()
	errCh := make(chan error, 1)
	go func() {
		errCh <- a.StartWithTimeout(t.TempDir(), "preview", true, 60_000)
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("boot did not start")
	}
	if err := a.Stop(); err != nil {
		t.Fatalf("Stop during Start = %v, want nil", err)
	}
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Start after Stop = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Stop did not cancel Start")
	}
	if got := a.Port(); got != 0 {
		t.Fatalf("Port after canceled Start = %d, want 0", got)
	}
}
