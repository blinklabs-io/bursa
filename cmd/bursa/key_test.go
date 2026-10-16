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
