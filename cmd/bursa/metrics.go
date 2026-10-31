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

package main

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/signer"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func newMetricsHTTPServer(cfg config.MetricsConfig) (*http.Server, error) {
	if cfg.ListenPort == 0 {
		return nil, nil
	}
	if !signer.IsLoopbackListenAddress(cfg.ListenAddress) {
		return nil, fmt.Errorf(
			"refusing metrics listener on non-loopback address %q",
			cfg.ListenAddress,
		)
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	host := strings.TrimSpace(cfg.ListenAddress)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	return &http.Server{
		Addr: net.JoinHostPort(
			host,
			strconv.FormatUint(uint64(cfg.ListenPort), 10),
		),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}, nil
}
