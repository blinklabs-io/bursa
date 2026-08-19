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

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/activity"
	"github.com/blinklabs-io/bursa/ui/internal/supervisor"
)

// fakeActivity is an in-memory api.Activity for handler tests.
type fakeActivity struct {
	events      []activity.Event
	err         error
	pollCalls   int
	activeCalls []string
}

func (f *fakeActivity) SetActive(walletID string) {
	f.activeCalls = append(f.activeCalls, walletID)
}

func (f *fakeActivity) Poll(context.Context) ([]activity.Event, error) {
	f.pollCalls++
	return f.events, f.err
}

func activityHandler(st Statuser, act Activity) http.Handler {
	return NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{},
		&fakeContacts{}, nil, &fakePoolOps{}, nil, &fakeMultiSig{}, "preview",
		http.NotFoundHandler(), WithActivity(act))
}

func TestActivityEndpointReturnsEvents(t *testing.T) {
	act := &fakeActivity{events: []activity.Event{
		{ID: "tx:abc", Kind: activity.KindReceived, Lovelace: "2500000", TxHash: "abc"},
		{ID: "reward:101", Kind: activity.KindReward, Lovelace: "7000000", Epoch: 101},
	}}
	h := activityHandler(readyStatuser(), act)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, localReq(http.MethodGet, "/wallet/activity", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /wallet/activity = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Events []activity.Event `json:"events"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Events) != 2 || got.Events[0].TxHash != "abc" || got.Events[1].Epoch != 101 {
		t.Fatalf("unexpected events: %+v", got.Events)
	}
	if act.pollCalls != 1 {
		t.Fatalf("Poll calls = %d, want 1", act.pollCalls)
	}
}

func TestActivityEndpointEmptyIsArrayNotNull(t *testing.T) {
	h := activityHandler(readyStatuser(), &fakeActivity{events: nil})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, localReq(http.MethodGet, "/wallet/activity", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /wallet/activity = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); body != `{"events":[]}` {
		t.Fatalf("empty activity body = %q, want {\"events\":[]}", body)
	}
}

func TestActivityEndpointGatedOnNodeState(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateStopped}}
	h := activityHandler(st, &fakeActivity{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, localReq(http.MethodGet, "/wallet/activity", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /wallet/activity on stopped node = %d, want 503", rec.Code)
	}
}

func TestActivityEndpointNotRegisteredWithoutOption(t *testing.T) {
	h := NewHandler(readyStatuser(), &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{},
		&fakeContacts{}, nil, &fakePoolOps{}, nil, &fakeMultiSig{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, localReq(http.MethodGet, "/wallet/activity", nil))
	// Falls through to the SPA catch-all (http.NotFoundHandler here) → 404.
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /wallet/activity without WithActivity = %d, want 404", rec.Code)
	}
}

func decodeNotifications(t *testing.T, body *bytes.Buffer) bool {
	t.Helper()
	var got struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Enabled == nil {
		t.Fatal("response missing enabled")
	}
	return *got.Enabled
}

func TestGetNotificationsReturnsPersistedValue(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateStopped}}
	set := &fakeSettings{notifications: true}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, set, &fakeContacts{}, nil, &fakePoolOps{}, nil, &fakeMultiSig{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, localReq(http.MethodGet, "/wallet/settings/notifications", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET notifications = %d, want 200", rec.Code)
	}
	if got := decodeNotifications(t, rec.Body); got != true {
		t.Fatalf("GET notifications enabled = %v, want true", got)
	}
}

func TestGetNotificationsDefaultsOff(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateStopped}}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, &fakeMultiSig{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, localReq(http.MethodGet, "/wallet/settings/notifications", nil))
	if got := decodeNotifications(t, rec.Body); got != false {
		t.Fatalf("GET notifications default = %v, want false", got)
	}
}

func TestPutNotificationsPersists(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	set := &fakeSettings{}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, set, &fakeContacts{}, nil, &fakePoolOps{}, nil, &fakeMultiSig{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"enabled":true}`)
	h.ServeHTTP(rec, localReq(http.MethodPut, "/wallet/settings/notifications", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT notifications = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !set.setNotificationsCalled || set.setNotificationsWith != true {
		t.Fatalf("SetNotifications not called with true: called=%v with=%v", set.setNotificationsCalled, set.setNotificationsWith)
	}
	if got := decodeNotifications(t, rec.Body); got != true {
		t.Fatalf("PUT notifications response = %v, want true", got)
	}
}

func TestPutNotificationsMissingEnabled(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, &fakeMultiSig{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{}`)
	h.ServeHTTP(rec, localReq(http.MethodPut, "/wallet/settings/notifications", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT notifications without enabled = %d, want 400", rec.Code)
	}
}
