// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBLSCommandRequiresSigningKeyFile(t *testing.T) {
	cmd := keyBLSCommand()
	cmd.SetArgs([]string{"--output-file", filepath.Join(t.TempDir(), "bls.json")})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "required flag(s) \"signing-key-file\"") {
		t.Fatalf("Execute error = %v, want required signing-key-file", err)
	}
}

func TestPoolOwnerCommandFlags(t *testing.T) {
	t.Parallel()
	cmd := keyPoolOwnerCommand()
	for _, name := range []string{
		"mnemonic-file", "password-file", "signing-key-file",
		"verification-key-file", "account-index", "index",
	} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("pool-owner is missing --%s", name)
		}
	}
	for _, name := range []string{"account-index", "index"} {
		if got := cmd.Flags().Lookup(name).DefValue; got != "0" {
			t.Errorf("--%s default = %q, want 0", name, got)
		}
	}
	registered := false
	for _, c := range keyCommand().Commands() {
		if c.Name() == "pool-owner" {
			registered = true
		}
	}
	if !registered {
		t.Error("pool-owner is not registered under key")
	}
}
