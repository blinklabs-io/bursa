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

// Package diagnostics assembles a node-local diagnostics report for the
// full-node wallet: node/library versions, network, sync progress, live peer
// counts, configured peers, listen ports, uptime, and the log-file location.
// Everything it reports comes from the embedded node, the supervisor, and the
// process itself — it makes NO external calls, so there is deliberately no
// external-consent gate. It also packages the wallet's log file(s) into a zip
// for a browser download.
package diagnostics

import (
	"archive/zip"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/blinklabs-io/bursa/ui/internal/supervisor"
)

const (
	dingoModulePath      = "github.com/blinklabs-io/dingo"
	gouroborosModulePath = "github.com/blinklabs-io/gouroboros"
	// chainQueryTimeout bounds the optional epoch/height lookup so a slow or
	// stuck node never stalls the diagnostics handler.
	chainQueryTimeout = 2 * time.Second
)

// NodeStatus is the node surface Diagnostics reads: the supervisor's status
// snapshot plus its live connection counts and configured peers.
type NodeStatus interface {
	Status() supervisor.Status
	Peers() supervisor.PeerCounts
	ConfiguredPeers() []supervisor.ConfiguredPeer
}

// ChainQuery optionally supplies node-queried chain facts the supervisor's tip
// poller does not track (the current epoch and the tip block height). It is
// optional: when nil, or when a lookup fails (e.g. the node is not serving
// queries yet), those fields are simply omitted from the report rather than
// invented.
type ChainQuery interface {
	LatestEpoch(ctx context.Context) (uint64, error)
	LatestBlockHeight(ctx context.Context) (uint64, error)
}

// Config wires the Service to its data sources. Everything here is known at
// boot; ControlAddr is a func because the control-surface port may be assigned
// by the OS (127.0.0.1:0) and is only known once the listener is bound.
type Config struct {
	Network        string
	ControlAddr    func() string
	BlockfrostPort uint
	UtxorpcPort    uint
	NodeSocket     string
	// LogPath is the file the wallet's logger writes to, or "" when logs are not
	// written to a file (e.g. mobile / stderr-only) — in which case log export
	// reports unavailable.
	LogPath   string
	StartedAt time.Time
	Now       func() time.Time // injectable clock; defaults to time.Now
	Chain     ChainQuery       // optional
}

// Service produces diagnostics reports and log-export archives.
type Service struct {
	node NodeStatus
	cfg  Config
}

// New builds a Service. now defaults to time.Now when cfg.Now is nil.
func New(node NodeStatus, cfg Config) *Service {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Service{node: node, cfg: cfg}
}

// --- Report shape (also the JSON response of GET /diagnostics) ---------------

// Report is the full diagnostics snapshot.
type Report struct {
	Node   NodeInfo   `json:"node"`
	Sync   SyncInfo   `json:"sync"`
	Peers  PeersInfo  `json:"peers"`
	Listen ListenInfo `json:"listen"`
	Uptime UptimeInfo `json:"uptime"`
	Log    LogInfo    `json:"log"`
}

// NodeInfo is the network and the embedded node/library versions. A version is
// omitted when it cannot be read from the build info (e.g. an unversioned
// `go run` / `go build` of a dev tree).
type NodeInfo struct {
	Network           string `json:"network"`
	DingoVersion      string `json:"dingoVersion,omitempty"`
	GouroborosVersion string `json:"gouroborosVersion,omitempty"`
	GoVersion         string `json:"goVersion,omitempty"`
}

// SyncInfo mirrors the supervisor's tip snapshot, plus a node-queried epoch and
// block height when obtainable. Epoch/BlockHeight are pointers so an
// unavailable lookup is JSON null rather than a fabricated zero.
type SyncInfo struct {
	State            string     `json:"state"`
	Tip              uint64     `json:"tip"` // latest block slot
	Epoch            *uint64    `json:"epoch,omitempty"`
	BlockHeight      *uint64    `json:"blockHeight,omitempty"`
	LatestBlockTime  *time.Time `json:"latestBlockTime,omitempty"`
	CaughtUp         bool       `json:"caughtUp"`
	SecondsBehind    *int64     `json:"secondsBehind,omitempty"`
	BootstrapPercent *float64   `json:"bootstrapPercent,omitempty"`
	BootstrapPhase   string     `json:"bootstrapPhase,omitempty"`
	Error            string     `json:"error,omitempty"`
}

// PeersInfo carries the node's live connection-manager counts and its
// configured outbound peers. Available is false when no node has been launched
// yet (no metrics). Per-connection detail (a live per-peer address/direction/
// state list) is NOT exposed by the embedded node's public API, so Configured
// is the peer address list (labelled as configured, not live-connected).
type PeersInfo struct {
	Available      bool             `json:"available"`
	Total          int              `json:"total"`
	Inbound        int              `json:"inbound"`
	Outbound       int              `json:"outbound"`
	Duplex         int              `json:"duplex"`
	FullDuplex     int              `json:"fullDuplex"`
	Unidirectional int              `json:"unidirectional"`
	Configured     []ConfiguredPeer `json:"configured"`
}

// ConfiguredPeer is one outbound access point from the node's topology.
type ConfiguredPeer struct {
	Address string `json:"address"`
	Port    uint   `json:"port"`
	Source  string `json:"source"` // "bootstrap" | "localRoot" | "publicRoot"
}

// ListenInfo is where the wallet and its embedded node listen. Every endpoint
// binds to loopback (127.0.0.1); the node socket is a unix domain socket path.
type ListenInfo struct {
	ControlSurface string `json:"controlSurface"`
	BlockfrostPort uint   `json:"blockfrostPort"`
	UtxorpcPort    uint   `json:"utxorpcPort"`
	NodeSocket     string `json:"nodeSocket"`
}

// UptimeInfo is how long this wallet process has been running.
type UptimeInfo struct {
	StartedAt time.Time `json:"startedAt"`
	Seconds   int64     `json:"seconds"`
}

// LogInfo locates the wallet's log file for export / "open folder". Available
// is false when the wallet is not writing logs to a file.
type LogInfo struct {
	Available bool   `json:"available"`
	Path      string `json:"path,omitempty"`
	Dir       string `json:"dir,omitempty"`
}

// Report assembles the current diagnostics snapshot. It makes at most one
// (bounded, loopback) node query — for the epoch and block height — and only
// when a ChainQuery is configured; that failing just omits those two fields.
func (s *Service) Report(ctx context.Context) Report {
	st := s.node.Status()
	now := s.cfg.Now()

	sync := SyncInfo{
		State:           string(st.State),
		Tip:             st.Tip,
		LatestBlockTime: st.LatestBlockTime,
		CaughtUp:        st.CaughtUp,
		Error:           st.Err,
	}
	if st.LatestBlockTime != nil {
		behind := int64(now.Sub(*st.LatestBlockTime).Seconds())
		if behind < 0 {
			behind = 0
		}
		sync.SecondsBehind = &behind
	}
	if st.Bootstrap != nil {
		p := st.Bootstrap.Percent
		sync.BootstrapPercent = &p
		sync.BootstrapPhase = st.Bootstrap.Phase
	}
	if s.cfg.Chain != nil {
		qctx, cancel := context.WithTimeout(ctx, chainQueryTimeout)
		if epoch, err := s.cfg.Chain.LatestEpoch(qctx); err == nil {
			sync.Epoch = &epoch
		}
		if height, err := s.cfg.Chain.LatestBlockHeight(qctx); err == nil {
			sync.BlockHeight = &height
		}
		cancel()
	}

	pc := s.node.Peers()
	peers := PeersInfo{
		Available:      pc.Available,
		Total:          pc.Total(),
		Inbound:        pc.Inbound,
		Outbound:       pc.Outbound,
		Duplex:         pc.Duplex,
		FullDuplex:     pc.FullDuplex,
		Unidirectional: pc.Unidirectional,
		Configured:     []ConfiguredPeer{},
	}
	for _, cp := range s.node.ConfiguredPeers() {
		peers.Configured = append(peers.Configured, ConfiguredPeer{
			Address: cp.Address, Port: cp.Port, Source: cp.Source,
		})
	}

	controlAddr := ""
	if s.cfg.ControlAddr != nil {
		controlAddr = s.cfg.ControlAddr()
	}

	// Clamp to 0: the clock moving backwards or a StartedAt in the future
	// would otherwise report a negative uptime (as secondsBehind is clamped).
	uptimeSeconds := int64(now.Sub(s.cfg.StartedAt).Seconds())
	if uptimeSeconds < 0 {
		uptimeSeconds = 0
	}

	log := LogInfo{}
	if s.cfg.LogPath != "" {
		log.Available = true
		log.Path = s.cfg.LogPath
		log.Dir = filepath.Dir(s.cfg.LogPath)
	}

	return Report{
		Node: NodeInfo{
			Network:           s.cfg.Network,
			DingoVersion:      depVersion(dingoModulePath),
			GouroborosVersion: depVersion(gouroborosModulePath),
			GoVersion:         runtime.Version(),
		},
		Sync:  sync,
		Peers: peers,
		Listen: ListenInfo{
			ControlSurface: controlAddr,
			BlockfrostPort: s.cfg.BlockfrostPort,
			UtxorpcPort:    s.cfg.UtxorpcPort,
			NodeSocket:     s.cfg.NodeSocket,
		},
		Uptime: UptimeInfo{
			StartedAt: s.cfg.StartedAt,
			Seconds:   uptimeSeconds,
		},
		Log: log,
	}
}

// LogAvailable reports whether the wallet has a log file that exists on disk
// and can be exported. It is the gate the API uses to decide 404 vs. stream,
// so it checks existence (not merely that a path was configured).
func (s *Service) LogAvailable() bool { return len(s.LogFiles()) > 0 }

// LogFiles returns the log file(s) to include in an export, skipping any that
// do not currently exist on disk.
func (s *Service) LogFiles() []string {
	if s.cfg.LogPath == "" {
		return nil
	}
	if _, err := os.Stat(s.cfg.LogPath); err != nil {
		return nil
	}
	return []string{s.cfg.LogPath}
}

// WriteLogsZip streams the log file(s) as a zip archive to w. It returns
// os.ErrNotExist when there is nothing to export (no configured/existing log).
func (s *Service) WriteLogsZip(w io.Writer) error {
	files := s.LogFiles()
	if len(files) == 0 {
		return os.ErrNotExist
	}
	zw := zip.NewWriter(w)
	for _, path := range files {
		if err := addFileToZip(zw, path); err != nil {
			_ = zw.Close()
			return err
		}
	}
	return zw.Close()
}

func addFileToZip(zw *zip.Writer, path string) error {
	f, err := os.Open(path) //nolint:gosec // path is the wallet's own configured log file
	if err != nil {
		return err
	}
	defer f.Close()
	hdr := &zip.FileHeader{Name: filepath.Base(path), Method: zip.Deflate}
	if info, err := f.Stat(); err == nil {
		hdr.Modified = info.ModTime()
	}
	dst, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}
	_, err = io.Copy(dst, f)
	return err
}

// depVersion returns the module version of the given import path from the
// binary's build info, or "" when it cannot be determined.
func depVersion(path string) string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, d := range bi.Deps {
		if d.Path != path {
			continue
		}
		if d.Replace != nil && d.Replace.Version != "" {
			return d.Replace.Version
		}
		return d.Version
	}
	return ""
}
