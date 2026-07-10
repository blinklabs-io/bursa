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
	"runtime"
	"sync"
	"sync/atomic"
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

// TestStartWithTimeoutWaitsForPriorCleanup proves the fix for a race flagged
// in PR #561 review: Stop() clears starting and returns as soon as it calls
// cancel(), without waiting for the canceled boot to actually unwind. Since
// boot.Boot binds fixed node ports (5555/5556) deep inside node startup —
// past the point where it notices cancellation — an immediate retry could
// previously race the old boot's teardown for those ports. StartWithTimeout
// must now block a retry on the prior cleanup (the draining field) before
// spawning a new boot attempt.
func TestStartWithTimeoutWaitsForPriorCleanup(t *testing.T) {
	orig := bootWallet
	defer func() { bootWallet = orig }()

	firstStarted := make(chan struct{})
	release := make(chan struct{})
	secondStarted := make(chan struct{})
	var calls atomic.Int32

	bootWallet = func(ctx context.Context, _ boot.Config) (*boot.App, error) {
		if calls.Add(1) == 1 {
			close(firstStarted)
			<-ctx.Done()
			// Simulate the real teardown window (dingo's node.Run only checks
			// ctx after it has already bound its listeners): the canceled
			// boot does not release anything until this call returns.
			<-release
			return nil, ctx.Err()
		}
		close(secondStarted)
		return nil, nil
	}

	a := New()
	errCh := make(chan error, 1)
	go func() {
		errCh <- a.StartWithTimeout(t.TempDir(), "preview", true, 60_000)
	}()

	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first boot did not start")
	}
	if err := a.Stop(); err != nil {
		t.Fatalf("Stop during Start = %v, want nil", err)
	}
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("first Start = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Stop did not cancel first Start")
	}

	// Fire the retry right away, while the first boot is still stuck
	// "unwinding" behind release. It must not touch bootWallet yet.
	retryErrCh := make(chan error, 1)
	go func() {
		retryErrCh <- a.StartWithTimeout(t.TempDir(), "preview", true, 60_000)
	}()

	select {
	case <-secondStarted:
		t.Fatal("retry started a new boot before the prior canceled boot's cleanup finished")
	case <-time.After(200 * time.Millisecond):
	}

	close(release)

	select {
	case <-secondStarted:
	case <-time.After(time.Second):
		t.Fatal("retry did not start once the prior cleanup finished")
	}
	select {
	case err := <-retryErrCh:
		if err != nil {
			t.Fatalf("retry StartWithTimeout = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("retry did not complete")
	}
}

func TestStopPublishesDrainBeforeCanceledStartObservesCancellation(t *testing.T) {
	orig := bootWallet
	defer func() { bootWallet = orig }()
	oldProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(oldProcs)

	firstStarted := make(chan struct{})
	release := make(chan struct{})
	releaseClosed := make(chan struct{})
	var releaseOnce sync.Once
	closeRelease := func() {
		releaseOnce.Do(func() {
			close(release)
			close(releaseClosed)
		})
	}
	defer closeRelease()

	var calls atomic.Int32
	bootWallet = func(ctx context.Context, _ boot.Config) (*boot.App, error) {
		if calls.Add(1) == 1 {
			close(firstStarted)
			<-ctx.Done()
			<-release
			return nil, ctx.Err()
		}
		return nil, nil
	}

	a := New()
	errCh := make(chan error, 1)
	go func() {
		errCh <- a.StartWithTimeout(t.TempDir(), "preview", true, 60_000)
	}()

	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first boot did not start")
	}
	if err := a.Stop(); err != nil {
		t.Fatalf("Stop during Start = %v, want nil", err)
	}

	go func() {
		time.Sleep(200 * time.Millisecond)
		closeRelease()
	}()

	// Invoke the retry synchronously before the canceled StartWithTimeout
	// goroutine gets scheduled. Stop must already have published the first
	// start's drain channel, so this call cannot complete before release closes.
	retryErr := a.StartWithTimeout(t.TempDir(), "preview", true, 60_000)
	releasedBeforeRetryReturned := false
	select {
	case <-releaseClosed:
		releasedBeforeRetryReturned = true
	default:
	}
	closeRelease()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("first Start = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first Start did not finish after release")
	}
	if !releasedBeforeRetryReturned {
		t.Fatal("retry completed before Stop-published cleanup finished")
	}
	if retryErr != nil {
		t.Fatalf("retry StartWithTimeout = %v, want nil", retryErr)
	}
}

type fakeRuntimeApp struct {
	stopEntered chan struct{}
	stopRelease chan struct{}
}

func (f *fakeRuntimeApp) Stop() error {
	close(f.stopEntered)
	<-f.stopRelease
	return nil
}

func (f *fakeRuntimeApp) Port() int { return 0 }

func (f *fakeRuntimeApp) OnNetworkChanged() error { return nil }

func (f *fakeRuntimeApp) OnResume() error { return nil }

// TestCleanupLateStartStopsLiveAppAndTerminates proves the node-lifecycle leak
// guard in cleanupLateStart: when a superseded start's slow bootWallet call
// eventually delivers a live runtime anyway, cleanupLateStart must call Stop()
// and must not close its done channel until Stop returns.
func TestCleanupLateStartStopsLiveAppAndTerminates(t *testing.T) {
	app := &fakeRuntimeApp{
		stopEntered: make(chan struct{}),
		stopRelease: make(chan struct{}),
	}
	result := make(chan startResult, 1)
	result <- startResult{app: app, err: nil}

	done := cleanupLateStart(result)
	select {
	case <-app.stopEntered:
	case <-time.After(time.Second):
		t.Fatal("cleanupLateStart did not call Stop")
	}
	select {
	case <-done:
		t.Fatal("cleanupLateStart closed done before Stop returned")
	default:
	}
	close(app.stopRelease)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("cleanupLateStart did not terminate; goroutine leaked")
	}
}
