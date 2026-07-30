# Determine root directory
ROOT_DIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

# Default GOOS to the host's Go environment. The webview conditionals below
# (the -H=windowsgui GUI linker flag and the .exe output suffix) key off this
# variable; without a default it is empty when GOOS is not exported, dropping
# both on native Windows hosts. A GOOS set in the environment or on the command
# line still wins (?= only assigns when unset).
GOOS ?= $(shell go env GOOS)

# Gather all .go files for use in dependencies below
GO_FILES=$(shell find $(ROOT_DIR) -name '*.go')

# Gather list of expected binaries
BINARIES=$(shell cd $(ROOT_DIR)/cmd && ls -1 | grep -v ^common)

# Extract Go module name from go.mod
GOMODULE=$(shell grep ^module $(ROOT_DIR)/go.mod | awk '{ print $$2 }')

# Set version strings based on git tag and current ref
GO_LDFLAGS=-ldflags "-X '$(GOMODULE)/internal/version.Version=$(shell git describe --tags --exact-match 2>/dev/null)' -X '$(GOMODULE)/internal/version.CommitHash=$(shell git rev-parse --short HEAD)'"

# The nested ui/ module is a separate Go module; mirror the version-ldflags
# pattern against its module path for the embedded-SPA wallet binary.
UI_GOMODULE=$(shell grep ^module $(ROOT_DIR)/ui/go.mod | awk '{ print $$2 }')
UI_LDFLAGS_CONTENT=-X '$(UI_GOMODULE)/internal/version.Version=$(shell git describe --tags --exact-match 2>/dev/null)' -X '$(UI_GOMODULE)/internal/version.CommitHash=$(shell git rev-parse --short HEAD)'
UI_GO_LDFLAGS=-ldflags "$(UI_LDFLAGS_CONTENT)"
# The webview desktop build must link the Windows GUI subsystem so launching it
# does not spawn a console window. -H=windowsgui is only valid for
# GOOS=windows, so it is appended conditionally.
UI_WEBVIEW_LDFLAGS=-ldflags "$(UI_LDFLAGS_CONTENT)$(if $(filter windows,$(GOOS)), -H=windowsgui,)"

.PHONY: build wallet wallet-binary wallet-webview wallet-binary-webview bundle-macos pkg-macos pkg-macos-adhoc mod-tidy clean test

# Alias for building program binary
build: $(BINARIES)

# Build the embedded-SPA wallet binary from the nested ui/ module. The web
# bundle is built first so the //go:embed dist target is populated, then the
# default (pure-Go, non-webview) bursa-wallet binary is compiled.
wallet:
	cd ui/web && npm ci && npm run build
	$(MAKE) wallet-binary

# Compile only the bursa-wallet Go binary, assuming the web bundle has already
# been built into the //go:embed dist target. Honors GOOS/GOARCH for the
# release cross-build matrix; the default build is pure Go and cross-compiles
# without CGO. The webview variant is intentionally NOT built here.
wallet-binary:
	cd ui && go build \
		$(UI_GO_LDFLAGS) \
		-o bursa-wallet \
		./cmd/bursa-wallet

# Build the webview desktop wallet: the web bundle first, then the CGO +
# `-tags webview` variant (native system webview: WKWebView/mac, WebView2/win,
# webkit2gtk/linux). CANNOT be cross-compiled; build on a native runner of the
# target arch with a C toolchain + the platform webview dev headers present.
wallet-webview:
	cd ui/web && npm ci && npm run build
	$(MAKE) wallet-binary-webview

# Compile only the webview bursa-wallet binary, assuming the web bundle has
# already been built into the //go:embed dist target. Honors GOOS/GOARCH.
wallet-binary-webview:
	cd ui && CGO_ENABLED=1 go build \
		$(UI_WEBVIEW_LDFLAGS) \
		-tags webview \
		-o bursa-wallet$(if $(filter windows,$(GOOS)),.exe,) \
		./cmd/bursa-wallet

# Build an ad-hoc-signed macOS Bursa.app + .pkg for LOCAL testing (no Developer
# ID needed). The pkg itself is unsigned; install with
# `sudo installer -pkg <pkg> -target /`. Alias of pkg-macos-adhoc for symmetry
# with adder's bundle-macos.
bundle-macos: pkg-macos-adhoc

# Build a (signed + notarized when secrets are set) macOS .pkg installer
# containing Bursa.app. See packaging/macos/build-pkg.sh for the env-var
# contract.
pkg-macos:
	./packaging/macos/build-pkg.sh

# Build an ad-hoc-signed macOS .pkg for LOCAL testing (no Developer ID needed).
pkg-macos-adhoc:
	ADHOC=1 ./packaging/macos/build-pkg.sh

# Builds and installs binary in ~/.local/bin
install: build
	mv $(BINARIES) $(HOME)/.local/bin

uninstall:
	rm -f $(HOME)/.local/bin/$(BINARIES)

mod-tidy:
	# Needed to fetch new dependencies and add them to go.mod
	go mod tidy

clean:
	rm -f $(BINARIES)

format: mod-tidy
	go fmt ./...
	gofmt -s -w $(GO_FILES)

golines:
	golines -w --ignore-generated --chain-split-dots --max-len=80 --reformat-tags .

swagger:
	swag f -g api.go -d internal/api,.
	swag i -g api.go -d internal/api,.

test: mod-tidy
	go test -v -race ./...

# Build our program binaries
# Depends on GO_FILES to determine when rebuild is needed
$(BINARIES): mod-tidy $(GO_FILES)
	go build \
		$(GO_LDFLAGS) \
		-o $(@) \
		./cmd/$(@)
