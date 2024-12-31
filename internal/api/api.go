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
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/penglongli/gin-metrics/ginmetrics"
	swaggerFiles "github.com/swaggo/files"     // swagger embed files
	ginSwagger "github.com/swaggo/gin-swagger" // gin-swagger middleware

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/logging"

	_ "github.com/blinklabs-io/bursa/docs" // docs is generated by Swag CLI
)

// WalletRestoreRequest defines the request payload for wallet restoration
type WalletRestoreRequest struct {
	Mnemonic string `json:"mnemonic" binding:"required"`
}

//	@title			bursa
//	@version		v0
//	@description	Programmable Cardano Wallet API
//	@Schemes		http
//	@BasePath		/

//	@contact.name	Blink Labs
//	@contact.url	https://blinklabs.io
//	@contact.email	support@blinklabs.io

// @license.name	Apache 2.0
// @license.url	http://www.apache.org/licenses/LICENSE-2.0.html
func Start(cfg *config.Config) error {
	// Disable gin debug and color output
	gin.SetMode(gin.ReleaseMode)
	gin.DisableConsoleColor()
	// Configure API router
	router := gin.New()
	// Catch panics and return a 500
	router.Use(gin.Recovery())
	// Standard logging
	logger := logging.GetLogger()
	// Access logging
	accessLogger := logging.GetAccessLogger()
	accessMiddleware := func(c *gin.Context) {
		accessLogger.Info("request received", "method", c.Request.Method, "path", c.Request.URL.Path, "remote_addr", c.ClientIP())
		c.Next()
		statusCode := c.Writer.Status()
		accessLogger.Info("response sent", "status", statusCode, "method", c.Request.Method, "path", c.Request.URL.Path, "remote_addr", c.ClientIP())
	}
	router.Use(accessMiddleware)

	// Create a healthcheck
	router.GET("/healthcheck", handleHealthcheck)
	// Create a swagger endpoint
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Metrics
	metricsRouter := gin.New()
	metrics := ginmetrics.GetMonitor()
	// Set metrics path
	metrics.SetMetricPath("/")
	// Set metrics router
	metrics.Expose(metricsRouter)
	// Use metrics middleware without exposing path in main app router
	metrics.UseWithoutExposingEndpoint(router)

	// Custom metrics
	createdMetric := &ginmetrics.Metric{
		Type:        ginmetrics.Counter,
		Name:        "bursa_wallets_created_count",
		Description: "total number of wallets created",
		Labels:      nil,
	}
	failureMetric := &ginmetrics.Metric{
		Type:        ginmetrics.Counter,
		Name:        "bursa_wallets_fail_count",
		Description: "total number of wallet failures",
		Labels:      nil,
	}
	restoreMetric := &ginmetrics.Metric{
		Type:        ginmetrics.Counter,
		Name:        "bursa_wallets_restore_count",
		Description: "total number of wallets restored",
		Labels:      nil,
	}
	// Add to global monitor object
	_ = ginmetrics.GetMonitor().AddMetric(createdMetric)
	_ = ginmetrics.GetMonitor().AddMetric(failureMetric)
	_ = ginmetrics.GetMonitor().AddMetric(restoreMetric)

	// Start metrics listener
	go func() {
		// TODO: return error if we cannot initialize metrics
		logger.Info("starting metrics listener", "address", cfg.Metrics.ListenAddress, ":", cfg.Metrics.ListenPort)
		_ = metricsRouter.Run(fmt.Sprintf("%s:%d",
			cfg.Metrics.ListenAddress,
			cfg.Metrics.ListenPort,
		))
	}()

	// Configure API routes
	router.GET("/api/wallet/create", handleWalletCreate)
	router.POST("/api/wallet/restore", handleWalletRestore)

	// Start API listener
	err := router.Run(fmt.Sprintf("%s:%d",
		cfg.Api.ListenAddress,
		cfg.Api.ListenPort,
	))
	return err
}

func handleHealthcheck(c *gin.Context) {
	c.JSON(200, gin.H{"healthy": true})
}

// handleCreateWallet godoc
//
//	@Summary		CreateWallet
//	@Description	Create a wallet and return details
//	@Produce		json
//	@Success		200	{object}	bursa.Wallet	"Ok"
//	@Router			/api/wallet/create [get]
func handleWalletCreate(c *gin.Context) {
	logger := logging.GetLogger()

	mnemonic, err := bursa.NewMnemonic()
	if err != nil {
		logger.Error("failed to load mnemonic", "error", err)
		c.JSON(500, fmt.Sprintf("failed to load mnemonic: %s", err))
		_ = ginmetrics.GetMonitor().
			GetMetric("bursa_wallets_fail_count").
			Inc(nil)
		return
	}

	w, err := bursa.NewDefaultWallet(mnemonic)
	if err != nil {
		logger.Error("failed to initialize wallet", "error", err)
		c.JSON(500, fmt.Sprintf("failed to initialize wallet: %s", err))
		_ = ginmetrics.GetMonitor().
			GetMetric("bursa_wallets_fail_count").
			Inc(nil)
		return
	}
	c.JSON(200, w)
	_ = ginmetrics.GetMonitor().GetMetric("bursa_wallets_create_count").Inc(nil)
}

// handleWalletRestore handles the wallet restoration request.
//
//	@Summary		Restore a wallet using a mnemonic seed phrase
//	@Description	Restores a wallet using the provided mnemonic seed phrase and returns wallet details.
//	@Accept			json
//	@Produce		json
//	@Param			request	body		WalletRestoreRequest	true	"Wallet Restore Request"
//	@Success		200		{object}	bursa.Wallet			"Wallet successfully restored"
//	@Failure		400		{string}	string					"Invalid request"
//	@Failure		500		{string}	string					"Internal server error"
//	@Router			/api/wallet/restore [post]
func handleWalletRestore(c *gin.Context) {
	var request WalletRestoreRequest
	if err := c.BindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		_ = ginmetrics.GetMonitor().
			GetMetric("bursa_wallets_fail_count").
			Inc(nil)
		return
	}

	// Restore the wallet using the mnemonic
	wallet, err := bursa.NewDefaultWallet(request.Mnemonic)
	if err != nil {
		c.JSON(
			http.StatusInternalServerError,
			gin.H{"error": "Internal server error"},
		)
		_ = ginmetrics.GetMonitor().
			GetMetric("bursa_wallets_fail_count").
			Inc(nil)
		return
	}

	// Return the wallet details
	c.JSON(http.StatusOK, wallet)
	_ = ginmetrics.GetMonitor().
		GetMetric("bursa_wallets_restore_count").
		Inc(nil)
}
