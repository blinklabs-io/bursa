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
	"slices"
	"strings"

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
		profile      string
		unprofiled   bool
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

A key served by a nitro, confidential-space, armory or sops backend with a profile
keeps its records under that profile. Pass --profile with that backend's
profile to reset them; the same transaction also deletes the key's
opcert-chain-issued record written before profile scoping, which the signer
still reads while the profile has none. A config with any such backend
requires --profile, or --unprofiled for a key served by a backend without a
profile; --profile must be the profile of a configured backend.

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
				profile, err = resetProfile(
					cfg.Signer.Backends, profile, unprofiled,
				)
			}
			if err == nil {
				err = runSignerCounterReset(
					ctx,
					cmd.OutOrStdout(),
					cfg.Signer.Watermark,
					keyHex,
					profile,
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
	cmd.Flags().StringVar(
		&profile, "profile", "",
		"the backend profile the key is served under; required when any backend has a profile",
	)
	cmd.Flags().BoolVar(
		&unprofiled, "unprofiled", false,
		"reset the records of a key served by a backend without a profile, in a config that also has profiled backends",
	)
	cmd.MarkFlagsMutuallyExclusive("profile", "unprofiled")
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
	profile string,
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
		ctx, wm, mode, key, profile, chainCounter, yes,
	)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "cold key %s\n", key)
	if profile != "" {
		fmt.Fprintf(out, "profile %s\n", profile)
	}
	fmt.Fprintln(out, "before:")
	printOpCertRecords(out, before, profile)
	if !yes {
		fmt.Fprintln(out, "would become:")
		printOpCertRecords(out, after, profile)
		return errCounterResetNotConfirmed
	}
	fmt.Fprintln(out, "after:")
	printOpCertRecords(out, after, profile)
	return nil
}

// profiledBackendTypes are the backend types that serve their keys under the
// configured profile, so their records carry it.
var profiledBackendTypes = map[string]bool{
	"nitro":              true,
	"confidential-space": true,
	"armory":             true,
	"sops":               true,
}

// resetProfile returns the profile whose records counter-reset changes: the
// --profile value, which must be the profile of a configured backend, or none.
// A config with a profiled backend needs --profile or --unprofiled, since the
// key may be served under a profile and its records are then kept under it.
func resetProfile(
	backends []config.SignerBackendConfig,
	profile string,
	unprofiled bool,
) (string, error) {
	if profile != "" && unprofiled {
		return "", errors.New(
			"--profile and --unprofiled are mutually exclusive",
		)
	}
	var (
		profiles []string
		found    bool
	)
	for _, b := range backends {
		if !profiledBackendTypes[b.Type] || b.Profile == "" {
			continue
		}
		if !slices.Contains(profiles, b.Profile) {
			profiles = append(profiles, b.Profile)
		}
		found = found || b.Profile == profile
	}
	slices.Sort(profiles)
	switch {
	case profile != "" && len(profiles) == 0:
		return "", fmt.Errorf(
			"--profile %q: no backend in the signer config has a profile",
			profile,
		)
	case profile != "" && !found:
		return "", fmt.Errorf(
			"--profile %q is not the profile of any backend in the signer config (%s)",
			profile,
			strings.Join(profiles, ", "),
		)
	case profile != "" || unprofiled || len(profiles) == 0:
		return profile, nil
	default:
		return "", fmt.Errorf(
			"the signer config has profiled backends (%s): pass --profile naming the one that serves the key, or --unprofiled for a key served by a backend without a profile",
			strings.Join(profiles, ", "),
		)
	}
}

// printOpCertRecords prints the records under profile; with a profile it adds
// the issued record written without one, which the reset also deletes.
func printOpCertRecords(
	out io.Writer,
	r signer.OpCertRecords,
	profile string,
) {
	type row struct {
		name string
		v    *uint64
	}
	rows := []row{
		{"opcert-chain-floor", r.ChainFloor},
		{"opcert-chain-issued", r.ChainIssued},
		{"opcert-counter (unchanged)", r.Explicit},
	}
	if profile != "" {
		rows = append(
			rows,
			row{"opcert-chain-issued (no profile)", r.LegacyChainIssued},
		)
	}
	for _, rw := range rows {
		if rw.v == nil {
			fmt.Fprintf(out, "  %-34s none\n", rw.name)
			continue
		}
		fmt.Fprintf(out, "  %-34s %d\n", rw.name, *rw.v)
	}
}
