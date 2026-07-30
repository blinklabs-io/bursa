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
package diagnostics

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/ui/internal/supervisor"
)

type fakeNode struct {
	status     supervisor.Status
	peers      supervisor.PeerCounts
	configured []supervisor.ConfiguredPeer
}

func (f fakeNode) Status() supervisor.Status                    { return f.status }
func (f fakeNode) Peers() supervisor.PeerCounts                 { return f.peers }
func (f fakeNode) ConfiguredPeers() []supervisor.ConfiguredPeer { return f.configured }

type fakeChain struct {
	epoch     uint64
	height    uint64
	epochErr  error
	heightErr error
}

func (f fakeChain) LatestEpoch(context.Context) (uint64, error) {
	return f.epoch, f.epochErr
}
func (f fakeChain) LatestBlockHeight(context.Context) (uint64, error) {
	return f.height, f.heightErr
}

func TestReportAssemblesRealFields(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	blkTime := now.Add(-30 * time.Second)
	started := now.Add(-10 * time.Minute)

	node := fakeNode{
		status: supervisor.Status{
			State:           supervisor.StateSyncing,
			Tip:             123456,
			LatestBlockTime: &blkTime,
			CaughtUp:        false,
		},
		peers: supervisor.PeerCounts{
			Available: true, Inbound: 2, Outbound: 5, Duplex: 1, FullDuplex: 1, Unidirectional: 4,
		},
		configured: []supervisor.ConfiguredPeer{
			{Address: "relay.example", Port: 3001, Source: "bootstrap"},
		},
	}
	svc := New(node, Config{
		Network:        "preview",
		ControlAddr:    func() string { return "127.0.0.1:8090" },
		BlockfrostPort: 5556,
		UtxorpcPort:    5555,
		NodeSocket:     "/data/node.socket",
		StartedAt:      started,
		Now:            func() time.Time { return now },
		Chain:          fakeChain{epoch: 812, height: 99000},
	})

	rep := svc.Report(context.Background())

	if rep.Node.Network != "preview" {
		t.Errorf("network = %q, want preview", rep.Node.Network)
	}
	if rep.Node.GoVersion == "" {
		t.Error("GoVersion should be populated from runtime")
	}
	if rep.Sync.State != "syncing" || rep.Sync.Tip != 123456 {
		t.Errorf("unexpected sync: %+v", rep.Sync)
	}
	if rep.Sync.Epoch == nil || *rep.Sync.Epoch != 812 {
		t.Errorf("epoch = %v, want 812", rep.Sync.Epoch)
	}
	if rep.Sync.BlockHeight == nil || *rep.Sync.BlockHeight != 99000 {
		t.Errorf("blockHeight = %v, want 99000", rep.Sync.BlockHeight)
	}
	if rep.Sync.SecondsBehind == nil || *rep.Sync.SecondsBehind != 30 {
		t.Errorf("secondsBehind = %v, want 30", rep.Sync.SecondsBehind)
	}
	if !rep.Peers.Available || rep.Peers.Total != 7 || rep.Peers.Outbound != 5 {
		t.Errorf("unexpected peers: %+v", rep.Peers)
	}
	if len(rep.Peers.Configured) != 1 || rep.Peers.Configured[0].Source != "bootstrap" {
		t.Errorf("unexpected configured peers: %+v", rep.Peers.Configured)
	}
	if rep.Listen.ControlSurface != "127.0.0.1:8090" || rep.Listen.BlockfrostPort != 5556 {
		t.Errorf("unexpected listen: %+v", rep.Listen)
	}
	if rep.Listen.NodeSocket != "/data/node.socket" {
		t.Errorf("nodeSocket = %q, want /data/node.socket", rep.Listen.NodeSocket)
	}
	if rep.Uptime.Seconds != 600 {
		t.Errorf("uptime = %d, want 600", rep.Uptime.Seconds)
	}
	if rep.Log.Available {
		t.Error("log should be unavailable when no LogPath is set")
	}
}

func TestReportOmitsChainFieldsOnError(t *testing.T) {
	svc := New(fakeNode{status: supervisor.Status{State: supervisor.StateError, Err: "boom"}}, Config{
		Network: "preview",
		Now:     time.Now,
		Chain:   fakeChain{epochErr: errors.New("node down"), heightErr: errors.New("node down")},
	})
	rep := svc.Report(context.Background())
	if rep.Sync.Epoch != nil || rep.Sync.BlockHeight != nil {
		t.Errorf("chain fields must be nil when lookups fail: %+v", rep.Sync)
	}
	if rep.Sync.Error != "boom" {
		t.Errorf("error passthrough = %q", rep.Sync.Error)
	}
	// Configured is always a (possibly empty) slice, never nil, so the JSON is [].
	if rep.Peers.Configured == nil {
		t.Error("configured peers should be an empty slice, not nil")
	}
}

func TestReportBootstrapPercent(t *testing.T) {
	svc := New(fakeNode{status: supervisor.Status{
		State:     supervisor.StateBootstrapping,
		Bootstrap: &supervisor.BootstrapProgress{Phase: "bootstrap", Percent: 42.5},
	}}, Config{Now: time.Now})
	rep := svc.Report(context.Background())
	if rep.Sync.BootstrapPercent == nil || *rep.Sync.BootstrapPercent != 42.5 {
		t.Errorf("bootstrapPercent = %v, want 42.5", rep.Sync.BootstrapPercent)
	}
	if rep.Sync.BootstrapPhase != "bootstrap" {
		t.Errorf("bootstrapPhase = %q", rep.Sync.BootstrapPhase)
	}
}

func TestUptimeClampedToZero(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	// StartedAt in the future (e.g. a clock that moved backwards) must not
	// produce a negative uptime.
	svc := New(fakeNode{}, Config{
		StartedAt: now.Add(5 * time.Minute),
		Now:       func() time.Time { return now },
	})
	rep := svc.Report(context.Background())
	if rep.Uptime.Seconds != 0 {
		t.Errorf("uptime = %d, want 0 (clamped)", rep.Uptime.Seconds)
	}
}

func TestLogExport(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "bursa-wallet.log")
	if err := os.WriteFile(logPath, []byte("hello log\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := New(fakeNode{}, Config{LogPath: logPath, Now: time.Now})

	if !svc.LogAvailable() {
		t.Fatal("LogAvailable should be true for an existing log file")
	}
	rep := svc.Report(context.Background())
	if !rep.Log.Available || rep.Log.Path != logPath || rep.Log.Dir != dir {
		t.Errorf("unexpected log info: %+v", rep.Log)
	}

	var buf bytes.Buffer
	if err := svc.WriteLogsZip(&buf); err != nil {
		t.Fatalf("WriteLogsZip: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}
	if len(zr.File) != 1 || zr.File[0].Name != "bursa-wallet.log" {
		t.Fatalf("unexpected zip contents: %+v", zr.File)
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, _ := os.ReadFile(logPath)
	var zipped bytes.Buffer
	_, _ = zipped.ReadFrom(rc)
	if zipped.String() != string(got) {
		t.Errorf("zipped content mismatch: %q vs %q", zipped.String(), string(got))
	}
}

func TestLogUnavailable(t *testing.T) {
	// No LogPath configured.
	if New(fakeNode{}, Config{}).LogAvailable() {
		t.Error("LogAvailable should be false with no LogPath")
	}
	// LogPath set but file does not exist.
	svc := New(fakeNode{}, Config{LogPath: filepath.Join(t.TempDir(), "missing.log")})
	if svc.LogAvailable() {
		t.Error("LogAvailable should be false when the file is missing")
	}
	if err := svc.WriteLogsZip(&bytes.Buffer{}); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("WriteLogsZip err = %v, want ErrNotExist", err)
	}
}
