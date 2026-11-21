// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBLSCommandRequiresSigningKeyFile(t *testing.T) {
	cmd := keyBLSCommand()
	cmd.SetArgs(
		[]string{"--output-file", filepath.Join(t.TempDir(), "bls.json")},
	)
	err := cmd.Execute()
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"required flag(s) \"signing-key-file\"",
		) {
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

func TestPoolIDCommand(t *testing.T) {
	t.Parallel()
	cmd := keyPoolIDCommand()
	for _, name := range []string{
		"cold-vkey", "mnemonic-file", "output-format", "out-file", "index",
	} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("pool-id is missing --%s", name)
		}
	}
	registered := false
	for _, c := range keyCommand().Commands() {
		if c.Name() == "pool-id" {
			registered = true
		}
	}
	if !registered {
		t.Error("pool-id is not registered under key")
	}

	dir := t.TempDir()
	vkey := filepath.Join(dir, "pool-cold.vkey")
	if err := os.WriteFile(
		vkey,
		[]byte(`{"type":"StakePoolVerificationKey_ed25519","description":"",`+
			`"cborHex":"5820`+strings.Repeat("bb", 32)+`"}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "pool.id")
	run := keyPoolIDCommand()
	run.SetArgs([]string{"--cold-vkey", vkey, "--out-file", out})
	if err := run.Execute(); err != nil {
		t.Fatalf("Execute error = %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	const want = "pool18xzwue290fr79jz8ex568pcdgehqdgfa87cgkkefml4jyjgwm7e\n"
	if string(got) != want {
		t.Errorf("pool id = %q, want %q", got, want)
	}

	both := keyPoolIDCommand()
	both.SetArgs([]string{"--cold-vkey", vkey, "--mnemonic-file", "seed.txt"})
	if err := both.Execute(); err == nil {
		t.Error("--cold-vkey with --mnemonic-file was accepted")
	}
}
