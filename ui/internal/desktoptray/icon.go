// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build webview

package desktoptray

import _ "embed"

// iconPNG is the tray icon. It is the same 128px app icon shipped for the
// browser extension (ui/extension/public/icons/icon128.png), copied into the
// package so go:embed can reach it. PNG is accepted directly by the Linux
// (AppIndicator) and macOS (NSImage) tray backends; on Windows systray prefers
// an .ico, so a Windows-native .ico variant is a follow-up nicety.
//
//go:embed icon128.png
var iconPNG []byte
