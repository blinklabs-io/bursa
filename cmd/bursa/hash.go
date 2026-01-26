// Copyright 2025 Blink Labs Software
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
	"os"

	"github.com/blinklabs-io/bursa/internal/cli"
	"github.com/blinklabs-io/bursa/internal/logging"
	"github.com/spf13/cobra"
)

func hashCommand() *cobra.Command {
	hashCmd := cobra.Command{
		Use:   "hash",
		Short: "Hash utility commands",
		Long: `Commands for generating cryptographic hashes used in Cardano.

These commands create hashes for metadata files and other Cardano constructs.

Hash types:
  metadata  - Blake2b-256 hash of pool/DRep metadata JSON
  anchor-data - Blake2b-256 hash of anchor data (constitutions, governance proposals)

Examples:
  bursa hash metadata pool-metadata.json
  bursa hash anchor-data --text "Constitution content"
  bursa hash anchor-data --file-text constitution.txt`,
	}

	hashCmd.AddCommand(
		hashMetadataCommand(),
		hashAnchorDataCommand(),
	)
	return &hashCmd
}

func hashMetadataCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "metadata <file>",
		Short: "Generate Blake2b-256 hash of metadata JSON file",
		Long: `Generate a Blake2b-256 hash of a Cardano metadata JSON file.

This is used for pool metadata and DRep metadata registration.
The hash is calculated from the canonical JSON representation.

Supported metadata types:
  - pool: Pool registration metadata
  - drep: DRep registration metadata

Examples:
  bursa hash metadata pool-metadata.json
  bursa hash metadata --type pool pool-metadata.json
  bursa hash metadata --type drep drep-metadata
		`,
		Run: func(cmd *cobra.Command, args []string) {
			// Validate that a file argument is provided
			if len(args) == 0 {
				logging.GetLogger().Error("no metadata file specified", "usage", "bursa hash metadata <file>")
				os.Exit(1)
			}

			filePath := args[0]
			if filePath == "" {
				logging.GetLogger().Error("empty metadata file path specified")
				os.Exit(1)
			}

			metadataType, _ := cmd.Flags().GetString("type")

			// Validate metadata type
			if metadataType != "pool" && metadataType != "drep" {
				logging.GetLogger().Error("invalid metadata type", "type", metadataType, "valid_types", "pool, drep")
				os.Exit(1)
			}

			if err := cli.RunHashMetadata(filePath, metadataType); err != nil {
				logging.GetLogger().
					Error("failed to hash metadata", "error", err)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().
		String("type", "pool", "Metadata type (pool or drep)")

	return &cmd
}

func hashAnchorDataCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "anchor-data",
		Short: "Generate Blake2b-256 hash of anchor data",
		Long: `Generate a Blake2b-256 hash of anchor data used in Cardano governance.

This is used for constitutions, governance proposals, and other documents
that are anchored to on-chain governance actions.

Supported input types:
  - text: UTF-8 text content
  - file-text: Text file content
  - file-binary: Binary file content
  - url: HTTP/HTTPS URL content`,
		RunE: func(cmd *cobra.Command, args []string) error {
			text, _ := cmd.Flags().GetString("text")
			fileText, _ := cmd.Flags().GetString("file-text")
			fileBinary, _ := cmd.Flags().GetString("file-binary")
			url, _ := cmd.Flags().GetString("url")
			expectedHash, _ := cmd.Flags().GetString("expected-hash")
			outFile, _ := cmd.Flags().GetString("out-file")

			return cli.RunHashAnchorData(text, fileText, fileBinary, url, expectedHash, outFile)
		},
	}

	cmd.Flags().String("text", "", "UTF-8 text content to hash")
	cmd.Flags().String("file-text", "", "Path to text file to hash")
	cmd.Flags().String("file-binary", "", "Path to binary file to hash")
	cmd.Flags().String("url", "", "HTTP/HTTPS URL to content to hash")
	cmd.Flags().String("expected-hash", "", "Expected hash for verification")
	cmd.Flags().String("out-file", "", "Output file for the hash")

	// Make flags mutually exclusive for input sources
	cmd.MarkFlagsMutuallyExclusive("text", "file-text", "file-binary", "url")

	return &cmd
}
