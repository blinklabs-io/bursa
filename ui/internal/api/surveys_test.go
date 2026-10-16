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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/spend"
	"github.com/blinklabs-io/bursa/ui/internal/supervisor"
	"github.com/blinklabs-io/bursa/ui/internal/survey"
)

type fakeSurveys struct {
	list    []survey.Summary
	detail  survey.Detail
	err     error
	respond survey.RespondRequest
	create  survey.CreateRequest
	cancel  survey.CancelRequest
	reveal  survey.RevealRequest
}

func (f *fakeSurveys) List(context.Context) ([]survey.Summary, error) { return f.list, f.err }
func (f *fakeSurveys) Get(_ context.Context, id string) (survey.Detail, error) {
	if f.err != nil {
		return survey.Detail{}, f.err
	}
	d := f.detail
	d.ID = id
	return d, nil
}

func (f *fakeSurveys) Respond(_ context.Context, r survey.RespondRequest) (spend.Preview, error) {
	f.respond = r
	return spend.Preview{PendingID: "p-respond"}, f.err
}

func (f *fakeSurveys) Create(_ context.Context, r survey.CreateRequest) (spend.Preview, error) {
	f.create = r
	return spend.Preview{PendingID: "p-create"}, f.err
}

func (f *fakeSurveys) Cancel(_ context.Context, r survey.CancelRequest) (spend.Preview, error) {
	f.cancel = r
	return spend.Preview{PendingID: "p-cancel"}, f.err
}

func (f *fakeSurveys) Reveal(_ context.Context, r survey.RevealRequest) (survey.Detail, error) {
	f.reveal = r
	return survey.Detail{Summary: survey.Summary{ID: r.Survey}}, f.err
}

func surveyHandler(st Statuser, sv Surveys) http.Handler {
	opts := []HandlerOption{}
	if sv != nil {
		opts = append(opts, WithSurveys(sv))
	}
	return NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil,
		&fakePoolOps{}, nil, &fakeMultiSig{}, "preview", http.NotFoundHandler(), opts...)
}

func serveSurveyReq(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := localReq(method, path, rdr)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func sampleSurveys(n int) []survey.Summary {
	out := make([]survey.Summary, n)
	for i := range out {
		status := "open"
		if i%2 == 1 {
			status = "closed"
		}
		out[i] = survey.Summary{
			ID: fmt.Sprintf("%064x:0", i), Title: fmt.Sprintf("Survey %d", i), Description: "about cats",
			Status: status, LinkedActions: []string{},
		}
	}
	return out
}

func TestSurveyListPagesFiltersAndSearches(t *testing.T) {
	t.Parallel()
	fs := &fakeSurveys{list: sampleSurveys(7)}
	h := surveyHandler(readyStatuser(), fs)

	get := func(query string) surveyListResponse {
		t.Helper()
		rec := serveSurveyReq(h, http.MethodGet, "/wallet/surveys"+query, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d %s", query, rec.Code, rec.Body.String())
		}
		var resp surveyListResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return resp
	}

	all := get("")
	if all.Total != 7 || len(all.Surveys) != 7 {
		t.Fatalf("unfiltered = %+v", all)
	}
	page := get("?count=3&page=3")
	if page.Total != 7 || len(page.Surveys) != 1 || page.Page != 3 || page.Count != 3 {
		t.Fatalf("page 3 of 3 = %+v", page)
	}
	if open := get("?status=open"); open.Total != 4 {
		t.Fatalf("status=open total = %d, want 4", open.Total)
	}
	if byTitle := get("?q=survey%205"); byTitle.Total != 1 || byTitle.Surveys[0].Title != "Survey 5" {
		t.Fatalf("q=survey 5 = %+v", byTitle)
	}
	if byBody := get("?q=CATS&status=closed"); byBody.Total != 3 {
		t.Fatalf("q=CATS&status=closed total = %d, want 3", byBody.Total)
	}
	if none := get("?q=zzz"); none.Total != 0 || none.Surveys == nil {
		t.Fatalf("no match must be an empty list: %+v", none)
	}
}

func TestSurveyListLinkedFilter(t *testing.T) {
	t.Parallel()
	list := sampleSurveys(5)
	list[1].LinkedActions = []string{"gov_action_one"}
	list[4].LinkedActions = []string{"gov_action_two", "gov_action_three"}
	h := surveyHandler(readyStatuser(), &fakeSurveys{list: list})

	rec := serveSurveyReq(h, http.MethodGet, "/wallet/surveys?linked=true", "")
	var resp surveyListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("GET linked = %d %s", rec.Code, rec.Body.String())
	}
	if resp.Total != 2 || resp.Surveys[0].ID != list[1].ID || resp.Surveys[1].ID != list[4].ID {
		t.Fatalf("linked = %+v", resp)
	}
}

func TestSurveyListWhileStillIndexing(t *testing.T) {
	t.Parallel()
	list := sampleSurveys(1)
	h := surveyHandler(readyStatuser(), &fakeSurveys{
		list: list,
		err:  fmt.Errorf("%w: 5000 transactions scanned", survey.ErrIndexing),
	})
	rec := serveSurveyReq(h, http.MethodGet, "/wallet/surveys", "")
	var resp surveyListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("status = %d %s", rec.Code, rec.Body.String())
	}
	if !resp.Partial || resp.Total != 1 || len(resp.Surveys) != 1 {
		t.Fatalf("partial list = %+v", resp)
	}
}

func TestSurveyGet(t *testing.T) {
	t.Parallel()
	fs := &fakeSurveys{detail: survey.Detail{Definition: survey.Definition{Title: "T"}}}
	h := surveyHandler(readyStatuser(), fs)
	// The web client escapes the colon in "<tx hash>:<index>"; the handler sees
	// the unescaped id.
	rec := serveSurveyReq(h, http.MethodGet, "/wallet/surveys/abc%3A1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %s", rec.Code, rec.Body.String())
	}
	var got survey.Detail
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got.ID != "abc:1" || got.Definition.Title != "T" {
		t.Fatalf("detail = %+v, err %v", got, err)
	}

	fs.err = survey.ErrNotFound
	if rec := serveSurveyReq(h, http.MethodGet, "/wallet/surveys/abc:1", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown survey: status = %d", rec.Code)
	}
}

func TestSurveyBuildRoutes(t *testing.T) {
	t.Parallel()
	fs := &fakeSurveys{}
	h := surveyHandler(readyStatuser(), fs)

	rec := serveSurveyReq(h, http.MethodPost, "/wallet/surveys/respond",
		`{"survey":"abc:0","role":0,"answers":[{"kind":1,"question":0,"choice":1},{"kind":4,"question":1,"number":"9223372036854775807"}]}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"pending_id":"p-respond"`) {
		t.Fatalf("respond = %d %s", rec.Code, rec.Body.String())
	}
	if fs.respond.Survey != "abc:0" || fs.respond.Role != survey.RoleDRep ||
		len(fs.respond.Answers) != 2 || fs.respond.Answers[0].Choice != 1 || fs.respond.Answers[0].Kind != survey.KindSingleChoice ||
		fs.respond.Answers[1].Number != 9223372036854775807 || fs.respond.Answers[1].Kind != survey.KindNumericRange {
		t.Fatalf("respond request = %+v", fs.respond)
	}

	rec = serveSurveyReq(h, http.MethodPost, "/wallet/surveys/create",
		`{"title":"T","description":"D","roles":[0,3],"end_epoch":9,"questions":[{"kind":1,"prompt":"p","options":["a","b"]},{"kind":4,"prompt":"n","range":{"min":"-9223372036854775808","max":"9223372036854775807","step":"18446744073709551615"}}]}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"pending_id":"p-create"`) {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	if fs.create.Title != "T" || fs.create.EndEpoch != 9 || len(fs.create.Questions) != 2 || fs.create.Questions[0].Options[1] != "b" ||
		fs.create.Questions[1].Range == nil || fs.create.Questions[1].Range.Min != -9223372036854775808 ||
		fs.create.Questions[1].Range.Max != 9223372036854775807 || fs.create.Questions[1].Range.Step != 18446744073709551615 {
		t.Fatalf("create request = %+v", fs.create)
	}

	rec = serveSurveyReq(h, http.MethodPost, "/wallet/surveys/cancel", `{"survey":"abc:0"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"pending_id":"p-cancel"`) {
		t.Fatalf("cancel = %d %s", rec.Code, rec.Body.String())
	}
	if fs.cancel.Survey != "abc:0" {
		t.Fatalf("cancel request = %+v", fs.cancel)
	}
}

func TestSurveyRevealRoute(t *testing.T) {
	t.Parallel()
	fs := &fakeSurveys{}
	h := surveyHandler(readyStatuser(), fs)

	rec := serveSurveyReq(h, http.MethodPost, "/wallet/surveys/abc:0/reveal", `{"consent":true,"beacon":"ab"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"id":"abc:0"`) {
		t.Fatalf("reveal = %d %s", rec.Code, rec.Body.String())
	}
	// The survey comes from the path, not the body.
	if fs.reveal.Survey != "abc:0" || !fs.reveal.Consent || fs.reveal.Beacon != "ab" {
		t.Fatalf("reveal request = %+v", fs.reveal)
	}

	for name, tc := range map[string]struct {
		err  error
		want int
	}{
		"consent withheld": {survey.ErrConsentRequired, http.StatusForbidden},
		"not sealed":       {survey.ErrInvalid, http.StatusBadRequest},
		"unknown":          {survey.ErrNotFound, http.StatusNotFound},
	} {
		fs.err = tc.err
		if rec := serveSurveyReq(h, http.MethodPost, "/wallet/surveys/abc:0/reveal", `{}`); rec.Code != tc.want {
			t.Errorf("%s: status = %d, want %d", name, rec.Code, tc.want)
		}
	}

	// Revealing reads the node and, with consent, a relay; it is not a spend, so
	// a syncing node is enough.
	syncing := fakeStatuser{s: supervisor.Status{State: supervisor.StateSyncing}}
	h = surveyHandler(syncing, &fakeSurveys{})
	if rec := serveSurveyReq(h, http.MethodPost, "/wallet/surveys/abc:0/reveal", `{}`); rec.Code != http.StatusOK {
		t.Fatalf("reveal while syncing = %d", rec.Code)
	}
}

func TestSurveyBuildRouteErrors(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		err  error
		body string
		want int
	}{
		"invalid survey input":  {survey.ErrInvalid, `{"survey":"x"}`, http.StatusBadRequest},
		"unknown survey":        {survey.ErrNotFound, `{"survey":"x"}`, http.StatusNotFound},
		"no wallet":             {spend.ErrNoWallet, `{"survey":"x"}`, http.StatusConflict},
		"insufficient funds":    {spend.ErrInsufficientFunds, `{"survey":"x"}`, http.StatusUnprocessableEntity},
		"wrapped survey error":  {fmt.Errorf("question 0: %w", survey.ErrInvalid), `{"survey":"x"}`, http.StatusBadRequest},
		"malformed body":        {nil, `{`, http.StatusBadRequest},
		"trailing body content": {nil, `{"survey":"x"} {}`, http.StatusBadRequest},
	} {
		for _, route := range []string{"respond", "create", "cancel"} {
			t.Run(name+"/"+route, func(t *testing.T) {
				t.Parallel()
				h := surveyHandler(readyStatuser(), &fakeSurveys{err: tc.err})
				rec := serveSurveyReq(h, http.MethodPost, "/wallet/surveys/"+route, tc.body)
				if rec.Code != tc.want {
					t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.want, rec.Body.String())
				}
			})
		}
	}
}

func TestSurveyRoutesFollowNodeReadiness(t *testing.T) {
	t.Parallel()
	syncing := fakeStatuser{s: supervisor.Status{State: supervisor.StateSyncing}}
	h := surveyHandler(syncing, &fakeSurveys{list: sampleSurveys(1)})

	// Reads are served while syncing; spends need a fully synced node.
	if rec := serveSurveyReq(h, http.MethodGet, "/wallet/surveys", ""); rec.Code != http.StatusOK {
		t.Fatalf("list while syncing = %d", rec.Code)
	}
	for _, route := range []string{"respond", "create", "cancel"} {
		if rec := serveSurveyReq(h, http.MethodPost, "/wallet/surveys/"+route, `{}`); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s while syncing = %d, want 503", route, rec.Code)
		}
	}

	stopped := fakeStatuser{s: supervisor.Status{State: supervisor.StateStopped}}
	h = surveyHandler(stopped, &fakeSurveys{})
	if rec := serveSurveyReq(h, http.MethodGet, "/wallet/surveys", ""); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("list while stopped = %d, want 503", rec.Code)
	}
}

func TestSurveyRoutesAbsentWithoutService(t *testing.T) {
	t.Parallel()
	h := surveyHandler(readyStatuser(), nil)
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/wallet/surveys"},
		{http.MethodGet, "/wallet/surveys/x:0"},
		{http.MethodPost, "/wallet/surveys/respond"},
	} {
		if rec := serveSurveyReq(h, route.method, route.path, `{}`); rec.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404", route.method, route.path, rec.Code)
		}
	}
}

// The survey routes sit behind the same-origin guard like the rest of the API:
// a page on another origin, or a DNS-rebound host, cannot read surveys, build a
// transaction or trigger a beacon fetch.
func TestSurveyRoutesRejectForeignOrigins(t *testing.T) {
	t.Parallel()
	fs := &fakeSurveys{list: sampleSurveys(1)}
	h := surveyHandler(readyStatuser(), fs)

	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/wallet/surveys"},
		{http.MethodGet, "/wallet/surveys/abc%3A0"},
		{http.MethodPost, "/wallet/surveys/respond"},
		{http.MethodPost, "/wallet/surveys/create"},
		{http.MethodPost, "/wallet/surveys/cancel"},
		{http.MethodPost, "/wallet/surveys/abc%3A0/reveal"},
	} {
		for name, setup := range map[string]func(*http.Request){
			"cross-origin":   func(r *http.Request) { r.Header.Set("Origin", "http://evil.example") },
			"rebound host":   func(r *http.Request) { r.Host = "evil.example"; r.Header.Del("Origin") },
			"missing origin": func(r *http.Request) { r.Header.Del("Origin") },
		} {
			if route.method == http.MethodGet && name == "missing origin" {
				continue // a same-host GET needs no Origin
			}
			req := localReq(route.method, route.path, strings.NewReader(`{"consent":true}`))
			setup(req)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s %s (%s) = %d, want 403", route.method, route.path, name, rec.Code)
			}
		}
	}
	if fs.respond.Survey != "" || fs.create.Title != "" || fs.cancel.Survey != "" || fs.reveal.Survey != "" {
		t.Fatal("a rejected request reached the survey service")
	}
}
