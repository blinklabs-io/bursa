package api

import (
	"errors"
	"net/http"

	"github.com/blinklabs-io/bursa/ui/internal/remotesubmit"
)

func registerRemoteSubmission(mux *http.ServeMux, svc *remotesubmit.Service) {
	mux.HandleFunc("GET /remote-submission", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, svc.Status())
	})
	mutate := func(action func() (remotesubmit.Status, error)) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			status, err := action()
			if err != nil {
				code := http.StatusInternalServerError
				if errors.Is(err, remotesubmit.ErrDisabled) {
					code = http.StatusConflict
				}
				writeJSON(w, code, map[string]string{"error": err.Error()})
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, http.StatusOK, status)
		}
	}
	mux.HandleFunc("POST /remote-submission/enable", mutate(svc.Enable))
	mux.HandleFunc("POST /remote-submission/disable", mutate(svc.Disable))
	mux.HandleFunc("POST /remote-submission/rotate", mutate(svc.Rotate))
}
