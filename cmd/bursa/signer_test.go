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

import "testing"

func TestIsLocalListenAddress(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want bool
	}{
		{name: "localhost", addr: "localhost", want: true},
		{name: "localhost with spaces", addr: " localhost ", want: true},
		{name: "localhost uppercase", addr: "LOCALHOST", want: true},
		{name: "localhost with port", addr: "localhost:8080", want: true},
		{name: "ipv4 loopback", addr: "127.0.0.1", want: true},
		{name: "ipv6 loopback", addr: "::1", want: true},
		{name: "bracketed ipv6 loopback", addr: "[::1]", want: true},
		{name: "bracketed ipv6 loopback with spaces", addr: " [::1] ", want: true},
		{name: "bracketed ipv6 loopback with port", addr: "[::1]:8080", want: true},
		{name: "empty wildcard", addr: "", want: false},
		{name: "ipv4 wildcard", addr: "0.0.0.0", want: false},
		{name: "ipv6 wildcard", addr: "::", want: false},
		{name: "malformed bracket missing close", addr: "[::1", want: false},
		{name: "malformed bracket missing open", addr: "]:1", want: false},
		{name: "malformed bracket only", addr: "[", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLocalListenAddress(tt.addr); got != tt.want {
				t.Fatalf("isLocalListenAddress(%q) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}
