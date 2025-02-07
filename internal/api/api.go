// Copyright 2024 Blink Labs Software
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
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	httpSwagger "github.com/swaggo/http-swagger"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/logging"

	_ "github.com/blinklabs-io/bursa/docs" // docs is generated by Swag CLI
)

// WalletCreateRequest defines the request payload for wallet creation
type WalletCreateRequest struct {
	Password string `json:"password"`
}

// WalletRestoreRequest defines the request payload for wallet restoration
type WalletRestoreRequest struct {
	Mnemonic  string `json:"mnemonic"   binding:"required"`
	Password  string `json:"password"`
	AccountId uint   `json:"account_id"`
	PaymentId uint32 `json:"payment_id"`
	StakeId   uint32 `json:"stake_id"`
	AddressId uint32 `json:"address_id"`
}

//	@title			bursa
//	@version		v0
//	@description	Programmable Cardano Wallet API
//	@Schemes		http
//	@BasePath		/

//	@contact.name	Blink Labs
//	@contact.url	https://blinklabs.io
//	@contact.email	support@blinklabs.io

//	@license.name	Apache 2.0
//	@license.url	http://www.apache.org/licenses/LICENSE-2.0.html

// Define Prometheus metrics
var (
	walletsCreatedCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "bursa_wallets_created_count",
		Help: "Total number of wallets created",
	})
	walletsFailCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "bursa_wallets_fail_count",
		Help: "Total number of wallet creation or restoration failures",
	})
	walletsRestoreCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "bursa_wallets_restore_count",
		Help: "Total number of wallets restored",
	})
)

// Register Prometheus metrics
func init() {
	prometheus.MustRegister(walletsCreatedCounter)
	prometheus.MustRegister(walletsFailCounter)
	prometheus.MustRegister(walletsRestoreCounter)
}

// Start initializes and starts the HTTP servers for the API and metrics
// Listeners can be passed in for testing purposes to provide ephermeral ports
func Start(
	ctx context.Context,
	cfg *config.Config,
	apiListener, metricsListener net.Listener,
) error {
	logger := logging.GetLogger()
	accessLogger := logging.GetAccessLogger()

	logger.Info("initializing API server")

	//
	// Main HTTP server for API endpoints
	//
	mainMux := http.NewServeMux()

	// Healthcheck
	mainMux.HandleFunc("/healthcheck", handleHealthcheck)

	// Prometheus endpoint
	mainMux.Handle("/metrics", promhttp.Handler())

	// Swagger endpoint
	mainMux.HandleFunc("/swagger/", httpSwagger.WrapHandler)

	// API routes
	mainMux.HandleFunc("/api/wallet/create", handleWalletCreate)
	mainMux.HandleFunc("/api/wallet/restore", handleWalletRestore)

	// Wrap the mainMux with an access-logging middleware
	mainHandler := logMiddleware(mainMux, accessLogger)

	//
	// Metrics HTTP server
	//
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())

	// Start metrics server
	go func() {
		logger.Info("starting metrics listener",
			"address", cfg.Metrics.ListenAddress,
			"port", cfg.Metrics.ListenPort,
		)
		var err error
		if metricsListener == nil {
			err = http.ListenAndServe(
				fmt.Sprintf(
					"%s:%d",
					cfg.Metrics.ListenAddress,
					cfg.Metrics.ListenPort,
				),
				metricsMux,
			)
		} else {
			server := &http.Server{
				Handler: metricsMux,
			}
			err = server.Serve(metricsListener)
		}
		if err != nil && err != http.ErrServerClosed {
			logger.Error("metrics listener failed to start", "error", err)
		}
	}()

	// Start API server
	logger.Info("starting API listener",
		"address", cfg.Api.ListenAddress,
		"port", cfg.Api.ListenPort,
	)
	var err error
	if apiListener == nil {
		err = http.ListenAndServe(
			fmt.Sprintf("%s:%d", cfg.Api.ListenAddress, cfg.Api.ListenPort),
			mainHandler,
		)
	} else {
		server := &http.Server{
			Handler: mainHandler,
		}
		err = server.Serve(apiListener)
	}
	return err
}

func logMiddleware(next http.Handler, accessLogger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessLogger.Info("request received",
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
		)

		// Wrap the ResponseWriter to capture status code
		rec := &statusRecorder{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}
		next.ServeHTTP(rec, r)

		accessLogger.Info("response sent",
			"status", rec.statusCode,
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
		)
	})
}

// statusRecorder helps to record the response status code
type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

// handleHealthcheck responds to GET /healthcheck
func handleHealthcheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"healthy": true}`))
}

// handleWalletCreate godoc
//
//	@Summary		Create a wallet
//	@Description	Create a wallet and return details
//	@Produce		json
//	@Success		200	{object}	bursa.Wallet	"Ok"
//	@Router			/api/wallet/create [get]
func handleWalletCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	logger := logging.GetLogger()

	mnemonic, err := bursa.NewMnemonic()
	if err != nil {
		logger.Error("failed to load mnemonic", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(fmt.Sprintf("failed to load mnemonic: %s", err)))
		walletsFailCounter.Inc()
		return
	}

	wallet, err := bursa.NewDefaultWallet(mnemonic)
	if err != nil {
		logger.Error("failed to initialize wallet", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(
			[]byte(fmt.Sprintf("failed to initialize wallet: %s", err)),
		)
		// Increment fail counter
		walletsFailCounter.Inc()
		return
	}

	w.Header().Set("Content-Type", "application/json")
	resp, _ := json.Marshal(wallet)
	_, _ = w.Write(resp)
	// Increment creation counter
	walletsCreatedCounter.Inc()
}

// handleWalletRestore handles the wallet restoration request.
//
//	@Summary		Restore a wallet using a mnemonic seed phrase
//	@Description	Restores a wallet using the provided mnemonic seed phrase and optional password and returns wallet details.
//	@Accept			json
//	@Produce		json
//	@Param			request	body		WalletRestoreRequest	true	"Wallet Restore Request"
//	@Success		200		{object}	bursa.Wallet			"Wallet successfully restored"
//	@Failure		400		{string}	string					"Invalid request"
//	@Failure		500		{string}	string					"Internal server error"
//	@Router			/api/wallet/restore [post]
func handleWalletRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req WalletRestoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"Invalid request"}`))
		// Increment fail counter
		walletsFailCounter.Inc()
		return
	}

	cfg := config.GetConfig()
	wallet, err := bursa.NewWallet(
		req.Mnemonic,
		req.Password,
		cfg.Network,
		req.AccountId,
		req.PaymentId,
		req.StakeId,
		req.AddressId,
	)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"Internal server error"}`))
		walletsFailCounter.Inc()
		return
	}

	w.Header().Set("Content-Type", "application/json")
	resp, _ := json.Marshal(wallet)
	_, _ = w.Write(resp)
	// Increment restore counter
	walletsRestoreCounter.Inc()
}
