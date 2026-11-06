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
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/signer"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/spf13/cobra"
)

// errCounterResetNotConfirmed is returned when --yes is absent: the command
// printed the planned change and wrote no records.
var errCounterResetNotConfirmed = errors.New(
	"no records written: re-run with --yes to apply",
)

func signerCounterResetCommand() *cobra.Command {
	var (
		configFile   string
		keyHex       string
		chainCounter uint64
		yes          bool
	)
	cmd := &cobra.Command{
		Use:   "counter-reset",
		Short: "Reset a cold key's opcert chain-counter records",
		Long: `Reset a cold key's opcert chain-counter records in the signer's
watermark store, the counterpart of the armory device's floor reset.

Sets the opcert-chain-floor record to --chain-counter, lower or higher than the
stored value, and deletes the opcert-chain-issued record. The reported counter
is trusted. The opcert-counter record (explicit issue counters) and the tx and
cip8 payload watermarks are not changed. The write is one transaction that also
bumps the key's opcert-chain-reset-gen record. The reset is fenced against
in-flight opcert requests: one that read the records before the reset and
commits after it is refused with a conflict and returns no signature. Pausing
opcert requests for the key avoids those refusals but is not required for
safety.

This is a local administrative command: it reads the signer config and writes
the store directly, and no API route exposes it. It refuses a mem store and
watermark mode off. Without --yes it opens the store read-only, prints the
change and writes no records; SQLite may still create its own -wal and -shm
files beside a file store.`,
		Run: func(cmd *cobra.Command, args []string) {
			if configFile == "" {
				configFile = os.Getenv("BURSA_CONFIG")
			}
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			cfg, err := config.LoadConfigFile(configFile)
			if err == nil {
				err = runSignerCounterReset(
					ctx,
					cmd.OutOrStdout(),
					cfg.Signer.Watermark,
					keyHex,
					chainCounter,
					yes,
				)
			}
			if err != nil {
				fmt.Fprintln(cmd.ErrOrStderr(), "error:", err)
				os.Exit(1)
			}
		},
	}
	cmd.Flags().StringVar(
		&configFile, "config", "",
		"path to YAML config file (env: BURSA_CONFIG)",
	)
	cmd.Flags().StringVar(
		&keyHex, "key", "", "cold key hash (56 hex characters)",
	)
	cmd.Flags().Uint64Var(
		&chainCounter, "chain-counter", 0,
		"the pool's current on-chain opcert counter",
	)
	cmd.Flags().BoolVar(
		&yes, "yes", false, "apply the reset; without it no records are written",
	)
	_ = cmd.MarkFlagRequired("key")
	_ = cmd.MarkFlagRequired("chain-counter")
	return cmd
}

func runSignerCounterReset(
	ctx context.Context,
	out io.Writer,
	wmCfg config.SignerWatermarkConfig,
	keyHex string,
	chainCounter uint64,
	yes bool,
) error {
	key, err := backend.ParseKeyHash(keyHex)
	if err != nil {
		return err
	}
	wm, mode, closeStore, err := signer.OpenResetStore(ctx, wmCfg, yes)
	if err != nil {
		return err
	}
	defer closeStore()
	before, after, err := signer.ResetOpCertChain(
		ctx, wm, mode, key, chainCounter, yes,
	)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "cold key %s\nbefore:\n", key)
	printOpCertRecords(out, before)
	if !yes {
		fmt.Fprintln(out, "would become:")
		printOpCertRecords(out, after)
		return errCounterResetNotConfirmed
	}
	fmt.Fprintln(out, "after:")
	printOpCertRecords(out, after)
	return nil
}

func printOpCertRecords(out io.Writer, r signer.OpCertRecords) {
	for _, row := range []struct {
		name string
		v    *uint64
	}{
		{"opcert-chain-floor", r.ChainFloor},
		{"opcert-chain-issued", r.ChainIssued},
		{"opcert-counter (unchanged)", r.Explicit},
	} {
		if row.v == nil {
			fmt.Fprintf(out, "  %-28s none\n", row.name)
			continue
		}
		fmt.Fprintf(out, "  %-28s %d\n", row.name, *row.v)
	}
}
