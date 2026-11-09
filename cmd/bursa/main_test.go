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
	"testing"

	"github.com/spf13/cobra"
)

// TestRunnableParentsRejectStrayArgs: a non-root cobra command with
// subcommands accepts stray arguments unless it sets Args, so a misspelled
// subcommand would run the parent instead (for a server command, start a
// second service). Every command that both runs and has subcommands must set
// Args.
func TestRunnableParentsRejectStrayArgs(t *testing.T) {
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c.HasParent() && c.Runnable() && c.HasSubCommands() && c.Args == nil {
			t.Errorf(
				"%q runs and has subcommands but sets no Args, so a misspelled subcommand runs it",
				c.CommandPath(),
			)
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(newRootCommand())
}
