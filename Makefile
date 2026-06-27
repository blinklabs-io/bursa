# Determine root directory
ROOT_DIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

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
UI_GO_LDFLAGS=-ldflags "-X '$(UI_GOMODULE)/internal/version.Version=$(shell git describe --tags --exact-match 2>/dev/null)' -X '$(UI_GOMODULE)/internal/version.CommitHash=$(shell git rev-parse --short HEAD)'"

.PHONY: build wallet wallet-binary mod-tidy clean test

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
