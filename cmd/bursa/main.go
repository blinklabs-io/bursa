// Copyright 2023 Blink Labs Software
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
	"flag"
	"fmt"
	"os"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/logging"
)

func main() {
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(
			flag.CommandLine.Output(),
			"Usage: bursa [-h] <subcommand> [args]\n\nSubcommands:\n\n",
		)
		fmt.Fprintf(
			flag.CommandLine.Output(),
			" - %-18s  %s\n",
			"api",
			"run an API server",
		)
		fmt.Fprintf(
			flag.CommandLine.Output(),
			" - %-18s  %s\n",
			"cli",
			"run a terminal command",
		)
	}
	_ = fs.Parse(os.Args[1:]) // ignore parse errors

	// Load Config
	_, err := config.LoadConfig()
	if err != nil {
		fmt.Printf("Failed to load config: %s\n", err)
		os.Exit(1)
	}
	// Configure logging
	logging.Setup()
	logger := logging.GetLogger()
	// Sync logger on exit
	defer func() {
		if err := logger.Sync(); err != nil {
			// ignore error
			return
		}
	}()

	var subCommand string
	// Parse subcommand
	if len(fs.Args()) < 1 {
		fs.Usage()
		os.Exit(1)
	} else {
		subCommand = fs.Arg(0)
	}

	switch subCommand {
	case "api":
		apiMain()
	case "cli":
		cliMain()
	default:
		fmt.Printf("Unknown subcommand: %s\n", subCommand)
		os.Exit(1)
	}
}
