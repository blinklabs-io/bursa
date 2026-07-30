# Copyright 2026 Blink Labs Software
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# build-msi.ps1 - build a (optionally signed) Windows .msi installer for the
# Bursa desktop wallet. Bursa is a SINGLE GUI binary (bursa-wallet.exe, built
# with `-tags webview`), installed under %ProgramFiles%\Bursa\ with a Start
# Menu shortcut.
#
# The script is fully parameterized via environment variables. Signing is
# SKIPPED with a clear warning when the jsign credentials are not provided, so
# it produces an UNSIGNED msi locally and a signed msi in CI.
#
# Run on a NATIVE Windows runner: the webview build needs CGO + a C toolchain
# (e.g. MSYS2 mingw-w64 gcc / clang) and cannot be cross-compiled. The web
# bundle (ui/internal/webui/dist) must be built before the Go build so the
# //go:embed target is populated.

#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Write-Log  { param([string]$m) Write-Host "==> $m" -ForegroundColor Blue }
function Write-Warn { param([string]$m) Write-Warning $m }
function Die        { param([string]$m) Write-Error $m; exit 1 }

# ---------------------------------------------------------------------------
# Configuration (all overridable via environment)
# ---------------------------------------------------------------------------

# Resolve repository paths relative to this script so it works from any CWD.
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = (Resolve-Path (Join-Path $ScriptDir '..\..')).Path
$UiDir     = Join-Path $RepoRoot 'ui'

# The wallet lives in the nested ui/ Go module; version ldflags mirror the
# Makefile's UI_GO_LDFLAGS pattern against that module path.
$UiGoModule = ((Select-String -Path (Join-Path $UiDir 'go.mod') -Pattern '^module').Line -split '\s+')[1]

# Version string. Defaults to the git tag/description; strips a leading "v".
# NOTE: MSI ProductVersion must be <=3 dot-separated integers (a.b.c). The raw
# `git describe` form (e.g. 0.39.1-36-g1234567) is NOT a valid MSI version, so
# for releases set VERSION to a clean semver. We sanitize for local dev builds.
$Version = $env:VERSION
if ([string]::IsNullOrEmpty($Version)) {
    $Version = (& git -C $RepoRoot describe --tags --always --dirty 2>$null)
    if ([string]::IsNullOrEmpty($Version)) { $Version = '0.0.0' }
}
$Version = $Version -replace '^v', ''

# Sanitize to the first 3 numeric dotted fields for the MSI ProductVersion.
$MsiVersion = '0.0.0'
$m = [regex]::Match($Version, '^(\d+(?:\.\d+){0,2})')
if ($m.Success) { $MsiVersion = $m.Value }
if ($MsiVersion -ne $Version) {
    Write-Warn "VERSION '$Version' is not a valid MSI version; using '$MsiVersion' for the MSI ProductVersion. Set VERSION to a clean semver for releases."
}

# Commit hash for the version ldflags.
$CommitHash = (& git -C $RepoRoot rev-parse --short HEAD 2>$null)
if ([string]::IsNullOrEmpty($CommitHash)) { $CommitHash = 'unknown' }

# Target architecture: amd64 (default) or arm64.
$Arch = $env:ARCH
if ([string]::IsNullOrEmpty($Arch)) { $Arch = 'amd64' }
# $MsiArch feeds the output filename (release convention: amd64/arm64).
# $WixArch is the WiX `-arch` platform token, which uses x64/arm64 (NOT amd64).
switch ($Arch) {
    'amd64' { $GoArch = 'amd64'; $MsiArch = 'amd64'; $WixArch = 'x64' }
    'x86_64'{ $GoArch = 'amd64'; $MsiArch = 'amd64'; $WixArch = 'x64' }
    'arm64' { $GoArch = 'arm64'; $MsiArch = 'arm64'; $WixArch = 'arm64' }
    default { Die "unsupported ARCH '$Arch' (use amd64 or arm64)" }
}

# Pinned WiX toolset version (installed as a dotnet global/local tool in CI).
$WixVersion = if ($env:WIX_VERSION) { $env:WIX_VERSION } else { '4.0.5' }

# Output / work locations.
$DistDir  = if ($env:DIST_DIR)  { $env:DIST_DIR }  else { Join-Path $RepoRoot 'dist' }
$BuildDir = if ($env:BUILD_DIR) { $env:BUILD_DIR } else { Join-Path $RepoRoot 'build\windows' }
$BinDir   = Join-Path $BuildDir 'bin'
$MsiName  = "bursa-wallet-$Version-windows-$MsiArch.msi"
$FinalMsi = Join-Path $DistDir $MsiName

# Pre-built binary input. When BURSA_EXE points at an existing file, the
# Build-Binary step is skipped and that file is packaged directly. CI uses this
# to feed in a binary already individually code-signed by an earlier step
# (signing inside the MSI requires the embedded PE be signed BEFORE the MSI is
# built; jsign of the MSI itself does not sign the contents).
$BursaExeIn = $env:BURSA_EXE

# Set SKIP_WEB_BUILD=1 to reuse an already-built web bundle
# (ui/internal/webui/dist) instead of re-running the npm build.
$SkipWebBuild = $env:SKIP_WEB_BUILD

# Icon source (already present in the repo).
$IconSrc = if ($env:ICON_SRC) { $env:ICON_SRC } else { Join-Path $RepoRoot '.github\assets\bursa.ico' }

# WebView2 Evergreen runtime bootstrapper bundling. The webview GUI renders via
# the Edge WebView2 runtime; Windows 11 ships it, but some Windows 10 / Server
# SKUs do not. We bundle Microsoft's official Evergreen bootstrapper and the
# MSI runs it silently at install time only when the runtime is absent.
#   BUNDLE_WEBVIEW2=0   disable bundling (host must already have WebView2)
#   WEBVIEW2_SETUP      path to a pre-downloaded MicrosoftEdgeWebview2Setup.exe
#   WEBVIEW2_URL        override the evergreen bootstrapper download URL
#   WEBVIEW2_SHA256     optional expected SHA-256 of the bootstrapper. The
#                       evergreen bootstrapper is a live download whose hash
#                       changes over time, so it is NOT pinned by default; set
#                       this to enforce a specific known-good hash.
$BundleWebView2 = if ($null -ne $env:BUNDLE_WEBVIEW2) { $env:BUNDLE_WEBVIEW2 } else { '1' }
$WebView2SetupIn = $env:WEBVIEW2_SETUP
$WebView2Url = if ($env:WEBVIEW2_URL) { $env:WEBVIEW2_URL } else { 'https://go.microsoft.com/fwlink/p/?LinkId=2124703' }
$WebView2Sha256 = $env:WEBVIEW2_SHA256

# Resolved, staged bootstrapper path (empty => not bundled; the .wxs guards on
# the sentinel "NONE"). Populated by Resolve-WebView2.
$script:WebView2Setup = ''

# Signing (jsign) parameters - empty => skip signing with a warning.
$JsignJar      = $env:JSIGN_JAR
$JsignKeystore = $env:JSIGN_KEYSTORE
$JsignStorePass= $env:JSIGN_STOREPASS
$JsignStoreType= $env:JSIGN_STORETYPE
$JsignAlias    = $env:JSIGN_ALIAS
$JsignCertFile = $env:JSIGN_CERTFILE
$JsignTsaUrl   = if ($env:JSIGN_TSAURL)  { $env:JSIGN_TSAURL }  else { 'http://timestamp.digicert.com' }
$JsignTsMode   = if ($env:JSIGN_TSMODE)  { $env:JSIGN_TSMODE }  else { 'RFC3161' }
$JsignAlg        = if ($env:JSIGN_ALG)         { $env:JSIGN_ALG }              else { 'SHA-256' }
$JsignTsRetries  = if ($env:JSIGN_TSRETRIES)   { [int]$env:JSIGN_TSRETRIES }   else { 3 }
$JsignTsRetryWait= if ($env:JSIGN_TSRETRYWAIT) { [int]$env:JSIGN_TSRETRYWAIT } else { 10 }

# ---------------------------------------------------------------------------
# 1. Build the single webview wallet binary
# ---------------------------------------------------------------------------

function Build-Binary {
    Write-Log "Building bursa-wallet.exe (version=$Version, commit=$CommitHash, arch=$GoArch)"

    # Build the web bundle first so the //go:embed dist target is populated.
    if ($SkipWebBuild -in @('1', 'true', 'yes')) {
        Write-Log "SKIP_WEB_BUILD set - reusing existing web bundle"
    } else {
        Write-Log "Building web bundle (npm ci && npm run build)"
        Push-Location (Join-Path $UiDir 'web')
        try {
            & npm ci
            if ($LASTEXITCODE -ne 0) { Die 'npm ci failed' }
            & npm run build
            if ($LASTEXITCODE -ne 0) { Die 'npm run build failed' }
        } finally { Pop-Location }
    }

    # Mirror the Makefile's UI version-ldflags pattern. -H=windowsgui links the
    # GUI subsystem so the wallet does not spawn a console window on launch.
    $ldflags = "-s -w " +
        "-X '$UiGoModule/internal/version.Version=$Version' " +
        "-X '$UiGoModule/internal/version.CommitHash=$CommitHash' " +
        "-H=windowsgui"

    New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

    # bursa-wallet.exe: CGO enabled + `-tags webview` for the native WebView2
    # GUI. This REQUIRES cgo and a C compiler (MSYS2 mingw-w64 gcc for x64, or
    # clang for arm64); it cannot be cross-compiled from macOS/Linux.
    Write-Log "Building bursa-wallet.exe (CGO_ENABLED=1 -tags webview -H=windowsgui)"
    $env:GOOS   = 'windows'
    $env:GOARCH = $GoArch
    $env:CGO_ENABLED = '1'
    Push-Location $UiDir
    try {
        & go build -ldflags $ldflags -tags webview `
            -o (Join-Path $BinDir 'bursa-wallet.exe') ./cmd/bursa-wallet
        if ($LASTEXITCODE -ne 0) { Die 'bursa-wallet.exe build failed (need cgo + a C toolchain such as MSYS2 mingw-w64 gcc)' }
    } finally { Pop-Location }
}

# ---------------------------------------------------------------------------
# 1b. Fetch + stage the WebView2 Evergreen bootstrapper
# ---------------------------------------------------------------------------

function Resolve-WebView2 {
    if ($BundleWebView2 -in @('0', 'false', 'no', 'off')) {
        Write-Warn "BUNDLE_WEBVIEW2=$BundleWebView2 - NOT bundling the WebView2 runtime. The host must already have Edge WebView2 installed."
        return
    }

    New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
    $dest = Join-Path $BinDir 'MicrosoftEdgeWebview2Setup.exe'

    if (-not [string]::IsNullOrEmpty($WebView2SetupIn)) {
        if (-not (Test-Path $WebView2SetupIn)) { Die "WEBVIEW2_SETUP not found at $WebView2SetupIn" }
        Write-Log "Using WEBVIEW2_SETUP=$WebView2SetupIn"
        Copy-Item $WebView2SetupIn $dest -Force
    } else {
        Write-Log "Downloading WebView2 Evergreen bootstrapper"
        # Windows PowerShell 5.1 defaults to TLS 1.0/1.1, which the CDN rejects;
        # force TLS 1.2. Suppressing the progress bar speeds the download.
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $prevProgress = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'
        try {
            Invoke-WebRequest -Uri $WebView2Url -OutFile $dest -UseBasicParsing
        } finally {
            $ProgressPreference = $prevProgress
        }
    }

    # Optional integrity check. The evergreen bootstrapper is a live download
    # whose hash changes over time, so it is only enforced when WEBVIEW2_SHA256
    # is supplied.
    if (-not [string]::IsNullOrEmpty($WebView2Sha256)) {
        $actualHash = (Get-FileHash -Path $dest -Algorithm SHA256).Hash.ToLower()
        if ($actualHash -ne $WebView2Sha256.ToLower()) {
            Die "WebView2 bootstrapper hash mismatch`nexpected $($WebView2Sha256.ToLower())`ngot      $actualHash"
        }
        Write-Log "Verified WebView2 bootstrapper SHA-256"
    }

    # Authenticode gate. The evergreen bootstrapper is unpinned by default (its
    # hash floats), so - hash or no hash - always require that the staged exe
    # carries a present, chain-trusted Authenticode signature before bundling
    # it. This is the integrity guarantee when WEBVIEW2_SHA256 is unset, and a
    # defense-in-depth check when it is set. Fail the build on anything that is
    # not 'Valid'.
    if (Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue) {
        $wvSig = Get-AuthenticodeSignature -FilePath $dest
        if ($wvSig.Status -ne 'Valid') {
            Die "WebView2 bootstrapper Authenticode signature is not valid (status: $($wvSig.Status)) at $dest; refusing to bundle an unsigned/untrusted bootstrapper."
        }
        $wvSigner = if ($wvSig.SignerCertificate) { $wvSig.SignerCertificate.Subject } else { '<unknown>' }
        Write-Log "Verified WebView2 bootstrapper Authenticode signature (Valid): $wvSigner"
    } else {
        Die "Get-AuthenticodeSignature unavailable - cannot verify the WebView2 bootstrapper signature; refusing to bundle it. Set BUNDLE_WEBVIEW2=0 to skip bundling."
    }

    $script:WebView2Setup = $dest
    Write-Log "Staged WebView2 Evergreen bootstrapper"
}

# ---------------------------------------------------------------------------
# 2. Build the MSI with the WiX toolchain
# ---------------------------------------------------------------------------

function Build-Msi {
    Write-Log "Building MSI with WiX v$WixVersion"
    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

    if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
        Die "WiX 'wix' command not found. Install the pinned toolset with: dotnet tool install --global wix --version $WixVersion"
    }

    # Ensure the Util extension (util:CloseApplication) is available, pinned to
    # the toolset version. Idempotent.
    & wix extension add -g "WixToolset.Util.wixext/$WixVersion"
    if ($LASTEXITCODE -ne 0) { Die 'wix extension add WixToolset.Util.wixext failed' }

    # Prefer a caller-supplied (typically pre-signed) binary; fall back to the
    # binary Build-Binary placed under $BinDir.
    $BursaExeSrc = if ($BursaExeIn) { $BursaExeIn } else { Join-Path $BinDir 'bursa-wallet.exe' }
    if (-not (Test-Path $BursaExeSrc)) { Die "bursa-wallet.exe not found at $BursaExeSrc" }

    # WebView2Setup is ALWAYS passed; bursa.wxs guards its component + custom
    # action on it != "NONE". A sentinel (not an empty string) avoids relying on
    # `wix -d Name=` empty-value / undefined-variable handling.
    $webView2Setup = if ($script:WebView2Setup) { $script:WebView2Setup } else { 'NONE' }
    $wixArgs = @(
        'build', (Join-Path $ScriptDir 'bursa.wxs'),
        '-arch', $WixArch,
        '-ext', 'WixToolset.Util.wixext',
        '-d', "Version=$MsiVersion",
        '-d', "BursaExe=$BursaExeSrc",
        '-d', "BursaIco=$IconSrc",
        '-d', "WebView2Setup=$webView2Setup",
        '-o', $FinalMsi
    )
    & wix @wixArgs
    if ($LASTEXITCODE -ne 0) { Die 'wix build failed' }

    Write-Log "Built: $FinalMsi"
}

# ---------------------------------------------------------------------------
# 3. Sign the MSI with the EV certificate via jsign (or skip with a warning)
# ---------------------------------------------------------------------------

function Sign-Msi {
    if ([string]::IsNullOrEmpty($JsignKeystore) -or [string]::IsNullOrEmpty($JsignStorePass)) {
        Write-Warn "JSIGN_KEYSTORE / JSIGN_STOREPASS unset - SKIPPING code signing (jsign)."
        Write-Warn "Producing an UNSIGNED installer: $FinalMsi"
        Write-Warn "It will trigger SmartScreen / 'Unknown publisher' on other machines."
        return
    }

    Write-Log "Signing MSI with jsign (storetype=$JsignStoreType, alias=$JsignAlias)"

    $jsignArgs = @(
        '--keystore',    $JsignKeystore,
        '--storepass',   $JsignStorePass,
        '--alg',         $JsignAlg,
        '--tsaurl',      $JsignTsaUrl,
        '--tsmode',      $JsignTsMode,
        '--tsretries',   $JsignTsRetries,
        '--tsretrywait', $JsignTsRetryWait,
        '--name',        'Bursa',
        '--url',         'https://github.com/blinklabs-io/bursa'
    )
    if (-not [string]::IsNullOrEmpty($JsignStoreType)) { $jsignArgs += @('--storetype', $JsignStoreType) }
    if (-not [string]::IsNullOrEmpty($JsignAlias))     { $jsignArgs += @('--alias', $JsignAlias) }
    if (-not [string]::IsNullOrEmpty($JsignCertFile))  { $jsignArgs += @('--certfile', $JsignCertFile) }
    $jsignArgs += $FinalMsi

    if (-not [string]::IsNullOrEmpty($JsignJar)) {
        & java -jar $JsignJar @jsignArgs
    } elseif (Get-Command jsign -ErrorAction SilentlyContinue) {
        & jsign @jsignArgs
    } else {
        Die "jsign not found: set JSIGN_JAR to jsign.jar or install a 'jsign' launcher on PATH."
    }
    if ($LASTEXITCODE -ne 0) { Die 'jsign signing failed' }

    # Independently confirm the MSI is signed, chain-trusted AND timestamped.
    # (jsign can exit 0 while the timestamp step silently failed.)
    if (Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue) {
        $sig = Get-AuthenticodeSignature $FinalMsi
        if ($sig.Status -ne 'Valid') { Die "MSI signature not valid: $($sig.Status)" }
        if ($null -eq $sig.TimeStamperCertificate) { Die 'MSI signature is not timestamped' }
        Write-Log "Verified MSI signature: Valid, timestamped"
    }

    Write-Log "Signed. Verify on Windows with: signtool verify /pa $MsiName"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Log 'Bursa Windows installer build'
Write-Log "  version : $Version (msi: $MsiVersion)"
Write-Log "  arch    : $MsiArch (GOARCH=$GoArch)"
Write-Log "  output  : $FinalMsi"

if ($BursaExeIn) {
    # BURSA_EXE was requested: fail fast if it does not exist rather than
    # silently falling through to Build-Binary. In CI, BURSA_EXE points at a
    # binary already code-signed by an earlier step, so quietly building a fresh
    # (unsigned) one to substitute for it would ship an unsigned exe inside a
    # "signed" MSI. Refuse instead.
    if (-not (Test-Path $BursaExeIn)) {
        Die "BURSA_EXE set to '$BursaExeIn' but no file exists there; refusing to substitute a freshly-built (possibly unsigned) binary. Unset BURSA_EXE to build one, or point it at the prebuilt exe."
    }
    Write-Log "Skipping go build: using prebuilt binary"
    Write-Log "  bursa-wallet.exe : $BursaExeIn"
} else {
    Build-Binary
}
Resolve-WebView2
Build-Msi
Sign-Msi

Write-Log "Done: $FinalMsi"
if ([string]::IsNullOrEmpty($JsignKeystore) -or [string]::IsNullOrEmpty($JsignStorePass)) {
    Write-Warn 'This is an UNSIGNED build (local/dev). It will warn under SmartScreen on other machines.'
} else {
    Write-Log "Verify with: signtool verify /pa $MsiName"
}
