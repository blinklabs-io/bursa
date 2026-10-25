package main

import (
	"io"
	"testing"
)

func TestParseNetwork(t *testing.T) {
	tests := []struct {
		name    string
		env     string
		args    []string
		want    string
		wantErr bool
	}{
		{name: "default", want: "preview"},
		{name: "env", env: "preprod", want: "preprod"},
		{name: "short flag", args: []string{"-n", "musashi"}, want: "musashi"},
		{name: "long flag", args: []string{"--network", "dijkstra"}, want: "dijkstra"},
		{name: "flag beats env", env: "preprod", args: []string{"-n", "mainnet"}, want: "mainnet"},
		{name: "unknown", args: []string{"-n", "sanchonet"}, wantErr: true},
		{name: "unknown env", env: "nope", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("BURSA_NETWORK", tt.env)
			got, err := parseNetwork(tt.args, io.Discard)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("network = %q, want %q", got, tt.want)
			}
		})
	}
}
