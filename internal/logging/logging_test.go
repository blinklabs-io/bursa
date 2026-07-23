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

package logging

import "testing"

func TestGetLoggerLazyInit(t *testing.T) {
	// Reset globals so GetLogger must lazily initialize.
	globalLogger = nil
	accessLogger = nil

	logger := GetLogger()
	if logger == nil {
		t.Fatal("GetLogger returned nil")
	}

	access := GetAccessLogger()
	if access == nil {
		t.Fatal("GetAccessLogger returned nil")
	}
}

func TestConfigureText(t *testing.T) {
	globalLogger = nil
	ConfigureText()
	if GetLogger() == nil {
		t.Fatal("expected logger after ConfigureText")
	}
}

func TestConfigureJSON(t *testing.T) {
	globalLogger = nil
	ConfigureJSON()
	if GetLogger() == nil {
		t.Fatal("expected logger after ConfigureJSON")
	}
}
