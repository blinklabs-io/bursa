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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	bursa "github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/kesagent"
	"github.com/spf13/cobra"
)

// kesAgentControlCommand sends one command to a running agent's local
// control socket.
func kesAgentControlCommand() *cobra.Command {
	var configFile, socket, profile string
	cmd := &cobra.Command{
		Use:   "control",
		Short: "Send a key management command to the local KES agent",
		Long: `Send one command to a running KES agent over its local control socket and
print the agent's reply as JSON.

The socket is kes_agent.control_socket from the agent's config file, or
--socket. With several profiles, --profile names the one a key command acts
on; info without it lists every profile.

A key rotation is: gen-staged-key --out kes.vkey, issue an operational
certificate for that key with the pool's cold key, then install-key --opcert
node.cert.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	cmd.PersistentFlags().
		StringVar(&configFile, "config", "", "path to the agent's YAML config file (env: BURSA_CONFIG)")
	cmd.PersistentFlags().
		StringVar(&socket, "socket", "", "control socket path; overrides the config file")
	cmd.PersistentFlags().
		StringVar(&profile, "profile", "", "profile a command acts on, when the agent has several")

	run := func(c *cobra.Command, command kesagent.Command) error {
		path, err := controlSocketPath(configFile, socket)
		if err != nil {
			return err
		}
		command.Profile = profile
		reply, err := kesagent.ControlRequest(c.Context(), path, command)
		if err != nil {
			return err
		}
		return printControlReply(c.OutOrStdout(), reply)
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "info",
		Short: "Print the agent's key state",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			return run(c, kesagent.Command{Command: kesagent.CmdInfo})
		},
	})

	var vkeyOut string
	gen := &cobra.Command{
		Use:   "gen-staged-key",
		Short: "Generate a staged KES key and print its verification key",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			path, err := controlSocketPath(configFile, socket)
			if err != nil {
				return err
			}
			reply, err := kesagent.ControlRequest(
				c.Context(),
				path,
				kesagent.Command{Command: kesagent.CmdGenStagedKey, Profile: profile},
			)
			if err != nil {
				return err
			}
			// The reply is printed first, so the staged key's verification
			// key is shown even when the file cannot be written.
			if err := printControlReply(c.OutOrStdout(), reply); err != nil {
				return err
			}
			if vkeyOut == "" {
				return nil
			}
			return writeKESVKeyFile(vkeyOut, reply.KESVKey)
		},
	}
	gen.Flags().
		StringVar(&vkeyOut, "out", "", "also write the KES verification key to this file as a cardano-cli envelope")
	cmd.AddCommand(gen)

	var opcertFile string
	install := &cobra.Command{
		Use:   "install-key",
		Short: "Install the staged key with its operational certificate",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			opcert, err := readOpCertFile(opcertFile)
			if err != nil {
				return err
			}
			return run(c, kesagent.Command{
				Command: kesagent.CmdInstallKey,
				OpCert:  opcert,
			})
		},
	}
	install.Flags().
		StringVar(&opcertFile, "opcert", "", "operational certificate file (cardano-cli envelope)")
	_ = install.MarkFlagRequired("opcert")
	cmd.AddCommand(install)

	var target string
	drop := &cobra.Command{
		Use:   "drop-key",
		Short: "Drop the staged key, the active key, or both",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			switch target {
			case "staged", "active", "all":
			default:
				return fmt.Errorf(
					"--target must be staged, active or all, got %q",
					target,
				)
			}
			return run(c, kesagent.Command{
				Command: kesagent.CmdDropKey,
				Target:  target,
			})
		},
	}
	drop.Flags().StringVar(&target, "target", "", "staged, active or all")
	_ = drop.MarkFlagRequired("target")
	cmd.AddCommand(drop)

	return cmd
}

// controlSocketPath is socket when set, else the control socket in the
// agent's config file.
func controlSocketPath(configFile, socket string) (string, error) {
	if socket != "" {
		return socket, nil
	}
	if configFile == "" {
		configFile = os.Getenv("BURSA_CONFIG")
	}
	if configFile == "" {
		return "", errors.New("set --socket, or --config for the agent's config file")
	}
	cfg, err := config.LoadConfigFile(configFile)
	if err != nil {
		return "", fmt.Errorf("load config: %w", err)
	}
	if cfg.KESAgent.ControlSocket == "" {
		return "", errors.New("the config file sets no kes_agent.control_socket")
	}
	return cfg.KESAgent.ControlSocket, nil
}

// readOpCertFile reads an operational certificate envelope and returns its
// CBOR.
func readOpCertFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("read operational certificate: %w", err)
	}
	key, err := bursa.LoadKeyFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("parse operational certificate %s: %w", path, err)
	}
	if key.Type != "NodeOperationalCertificate" {
		return nil, fmt.Errorf(
			"%s is a %s, not an operational certificate",
			path,
			key.Type,
		)
	}
	return key.RawCBOR, nil
}

// writeKESVKeyFile writes vkey as a cardano-cli KES verification key
// envelope. It refuses to replace an existing file.
func writeKESVKeyFile(path string, vkey []byte) error {
	kf, err := bursa.GetKESVKey(vkey)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(kf, "", "    ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) //nolint:gosec // a verification key is public
	if err != nil {
		return fmt.Errorf("write KES verification key: %w", err)
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		_ = f.Close()
		return fmt.Errorf("write KES verification key: %w", err)
	}
	return f.Close()
}

// controlInfoView is AgentInfo with its byte fields in hex.
type controlInfoView struct {
	Version           string `json:"version"`
	Mode              string `json:"mode"`
	Profile           string `json:"profile,omitempty"`
	HasActiveKey      bool   `json:"has_active_key"`
	ActivePeriod      uint64 `json:"active_period"`
	ActiveStart       uint64 `json:"active_start"`
	ActiveEnd         uint64 `json:"active_end"`
	ActiveKESVKey     string `json:"active_kes_vkey,omitempty"`
	ActiveIssueNumber uint64 `json:"active_issue_number"`
	ActiveOpCert      string `json:"active_opcert,omitempty"`
	StagedKESVKey     string `json:"staged_kes_vkey,omitempty"`
	Exhausted         bool   `json:"exhausted"`
	CurrentPeriod     uint64 `json:"current_period"`
	MonotonicFloor    uint64 `json:"monotonic_floor"`
	FloorInitialized  bool   `json:"floor_initialized"`
}

func infoView(i kesagent.AgentInfo) controlInfoView {
	return controlInfoView{
		Version:           i.Version,
		Mode:              i.Mode,
		Profile:           i.Profile,
		HasActiveKey:      i.HasActiveKey,
		ActivePeriod:      i.ActivePeriod,
		ActiveStart:       i.ActiveStart,
		ActiveEnd:         i.ActiveEnd,
		ActiveKESVKey:     hex.EncodeToString(i.ActiveKESVKey),
		ActiveIssueNumber: i.ActiveIssueNumber,
		ActiveOpCert:      hex.EncodeToString(i.ActiveOpCert),
		StagedKESVKey:     hex.EncodeToString(i.StagedKESVKey),
		Exhausted:         i.Exhausted,
		CurrentPeriod:     i.CurrentPeriod,
		MonotonicFloor:    i.MonotonicFloor,
		FloorInitialized:  i.FloorInitialized,
	}
}

// printControlReply prints reply as JSON, byte fields in hex, and returns an
// error when the agent refused the command.
func printControlReply(w io.Writer, reply kesagent.Reply) error {
	view := struct {
		Ok       bool              `json:"ok"`
		Error    string            `json:"error,omitempty"`
		KESVKey  string            `json:"kes_vkey,omitempty"`
		Info     *controlInfoView  `json:"info,omitempty"`
		Profiles []controlInfoView `json:"profiles,omitempty"`
	}{
		Ok:      reply.Ok,
		Error:   reply.Error,
		KESVKey: hex.EncodeToString(reply.KESVKey),
	}
	if reply.Info != nil {
		v := infoView(*reply.Info)
		view.Info = &v
	}
	for _, p := range reply.Profiles {
		view.Profiles = append(view.Profiles, infoView(p))
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(view); err != nil {
		return err
	}
	if !reply.Ok {
		return fmt.Errorf("the agent refused the command: %s", reply.Error)
	}
	return nil
}
