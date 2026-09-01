#!/usr/bin/env bash
#
# Deterministic contract test for publish-image-manifests.sh.
#
# A release run cannot be rehearsed, so this test replaces `docker` with a stub
# that records its argv and asserts the exact source and destination tags the
# script would use, in order. The regression it guards is a manifest composed
# from an architecture tag the build matrix never published.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
publisher="$script_dir/publish-image-manifests.sh"
ci_workflow="$script_dir/../workflows/ci-docker.yml"
publish_workflow="$script_dir/../workflows/publish.yml"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

failures=0

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  failures=$((failures + 1))
}

assert_equals() {
  local expected="$1" actual="$2" description="$3"
  if [[ "$actual" != "$expected" ]]; then
    fail "$description"
    printf 'expected:\n%s\nactual:\n%s\n' "$expected" "$actual" >&2
  fi
}

assert_contains() {
  local haystack="$1" needle="$2" description="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    fail "$description"
    printf 'missing: %s\n' "$needle" >&2
  fi
}

assert_not_contains() {
  local haystack="$1" needle="$2" description="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    fail "$description"
    printf 'unexpected: %s\nactual:\n%s\n' "$needle" "$haystack" >&2
  fi
}

# Stub docker: log argv, and answer `inspect` with a stable per-tag digest so
# the recorded outputs are reproducible.
mkdir "$tmpdir/bin"
cat > "$tmpdir/bin/docker" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf '%s|' "$@" >> "$DOCKER_LOG"
printf '\n' >> "$DOCKER_LOG"
if [[ "${1:-}" == buildx && "${2:-}" == imagetools && "${3:-}" == inspect ]]; then
  printf 'sha256:digest-of-%s\n' "${!#}"
fi
STUB
chmod +x "$tmpdir/bin/docker"

run_publisher() {
  local name="$1" tags="$2" version="$3"
  DOCKER_LOG="$tmpdir/$name.log"
  : > "$DOCKER_LOG"
  : > "$tmpdir/$name.out"
  PATH="$tmpdir/bin:$PATH" DOCKER_LOG="$DOCKER_LOG" \
    GITHUB_OUTPUT="$tmpdir/$name.out" \
    IMAGE_TAGS="$tags" PRIMARY_VERSION="$version" \
    bash "$publisher"
}

expect_failure() {
  local name="$1" tags="$2" version="$3" description="$4"
  if run_publisher "$name" "$tags" "$version" 2>"$tmpdir/$name.err"; then
    fail "$description (expected a non-zero exit)"
  fi
}

# --- Release run: versioned tags plus a floating latest alias ---------------
release_tags=$(printf '%s\n' \
  'blinklabs/bursa:0.17.0' \
  'blinklabs/bursa:latest' \
  'ghcr.io/blinklabs-io/bursa:0.17.0' \
  'ghcr.io/blinklabs-io/bursa:latest')
run_publisher release "$release_tags" '0.17.0'

release_expected=$(printf '%s\n' \
  'buildx|imagetools|create|-t|blinklabs/bursa:0.17.0|blinklabs/bursa:0.17.0-amd64|blinklabs/bursa:0.17.0-arm64|' \
  'buildx|imagetools|create|-t|ghcr.io/blinklabs-io/bursa:0.17.0|ghcr.io/blinklabs-io/bursa:0.17.0-amd64|ghcr.io/blinklabs-io/bursa:0.17.0-arm64|' \
  'buildx|imagetools|create|-t|blinklabs/bursa:latest|blinklabs/bursa:0.17.0|' \
  'buildx|imagetools|create|-t|ghcr.io/blinklabs-io/bursa:latest|ghcr.io/blinklabs-io/bursa:0.17.0|' \
  'buildx|imagetools|inspect|--format|{{.Manifest.Digest}}|blinklabs/bursa:0.17.0|' \
  'buildx|imagetools|inspect|--format|{{.Manifest.Digest}}|ghcr.io/blinklabs-io/bursa:0.17.0|')
release_log="$(<"$tmpdir/release.log")"
assert_equals "$release_expected" "$release_log" \
  'release run composes versioned manifests first, then floating aliases'

# The exact failure from the v0.17.0 run: a floating architecture tag the build
# matrix never published being used as a manifest input.
assert_not_contains "$release_log" 'latest-amd64' \
  'release run never reads a latest-amd64 input'
assert_not_contains "$release_log" 'latest-arm64' \
  'release run never reads a latest-arm64 input'

# Attestation digests must name the versioned manifests, not the aliases.
release_output=$(printf '%s\n' \
  'dockerhub-digest=sha256:digest-of-blinklabs/bursa:0.17.0' \
  'ghcr-digest=sha256:digest-of-ghcr.io/blinklabs-io/bursa:0.17.0')
assert_equals "$release_output" "$(<"$tmpdir/release.out")" \
  'release digests are bound to the versioned manifests'

# --- Prerelease run: versioned tags, no floating alias ----------------------
prerelease_tags=$(printf '%s\n' \
  'blinklabs/bursa:0.18.0-rc1' \
  'ghcr.io/blinklabs-io/bursa:0.18.0-rc1')
run_publisher prerelease "$prerelease_tags" '0.18.0-rc1'
prerelease_expected=$(printf '%s\n' \
  'buildx|imagetools|create|-t|blinklabs/bursa:0.18.0-rc1|blinklabs/bursa:0.18.0-rc1-amd64|blinklabs/bursa:0.18.0-rc1-arm64|' \
  'buildx|imagetools|create|-t|ghcr.io/blinklabs-io/bursa:0.18.0-rc1|ghcr.io/blinklabs-io/bursa:0.18.0-rc1-amd64|ghcr.io/blinklabs-io/bursa:0.18.0-rc1-arm64|' \
  'buildx|imagetools|inspect|--format|{{.Manifest.Digest}}|blinklabs/bursa:0.18.0-rc1|' \
  'buildx|imagetools|inspect|--format|{{.Manifest.Digest}}|ghcr.io/blinklabs-io/bursa:0.18.0-rc1|')
assert_equals "$prerelease_expected" "$(<"$tmpdir/prerelease.log")" \
  'a prerelease composes its versioned manifests and adds no alias'

# --- Branch run: a single versioned tag per registry, no alias --------------
branch_tags=$(printf '%s\n' \
  'blinklabs/bursa:main' \
  'ghcr.io/blinklabs-io/bursa:main')
run_publisher branch "$branch_tags" 'main'
branch_expected=$(printf '%s\n' \
  'buildx|imagetools|create|-t|blinklabs/bursa:main|blinklabs/bursa:main-amd64|blinklabs/bursa:main-arm64|' \
  'buildx|imagetools|create|-t|ghcr.io/blinklabs-io/bursa:main|ghcr.io/blinklabs-io/bursa:main-amd64|ghcr.io/blinklabs-io/bursa:main-arm64|' \
  'buildx|imagetools|inspect|--format|{{.Manifest.Digest}}|blinklabs/bursa:main|' \
  'buildx|imagetools|inspect|--format|{{.Manifest.Digest}}|ghcr.io/blinklabs-io/bursa:main|')
assert_equals "$branch_expected" "$(<"$tmpdir/branch.log")" \
  'a branch run composes only its branch manifests'

# --- Guard rails ------------------------------------------------------------
expect_failure alias_without_version \
  "$(printf '%s\n' 'blinklabs/bursa:latest' 'ghcr.io/blinklabs-io/bursa:latest')" \
  '0.17.0' \
  'a tag list of aliases alone is rejected'
expect_failure single_registry \
  'blinklabs/bursa:0.17.0' \
  '0.17.0' \
  'a tag list missing a registry is rejected'

# --- Workflow wiring --------------------------------------------------------
# The script only protects the release if the workflows actually call it, and
# the test only protects the script if CI actually runs it.
publish_contents="$(<"$publish_workflow")"
assert_contains "$publish_contents" 'bash .github/scripts/publish-image-manifests.sh' \
  'the publish workflow composes manifests through this script'
# shellcheck disable=SC2016 # literal workflow text, not a shell expansion
assert_contains "$publish_contents" 'IMAGE_TAGS: ${{ steps.meta.outputs.tags }}' \
  'the publish workflow passes the metadata tag list to the script'
# shellcheck disable=SC2016 # literal workflow text, not a shell expansion
assert_contains "$publish_contents" 'PRIMARY_VERSION: ${{ steps.meta.outputs.version }}' \
  'the publish workflow passes the primary version to the script'
assert_contains "$publish_contents" 'latest=false' \
  'the per-architecture build publishes no floating tag of its own'
# The script composes "<tag>-amd64"/"<tag>-arm64"; if the matrix stopped
# suffixing its tags those inputs would not exist, and this test would still
# pass while the release failed. Assert the other half of the wiring too.
# shellcheck disable=SC2016 # literal workflow text, not a shell expansion
assert_contains "$publish_contents" 'suffix=-${{ matrix.arch }}' \
  'the per-architecture build suffixes its tags with the architecture'

ci_contents="$(<"$ci_workflow")"
assert_contains "$ci_contents" 'bash .github/scripts/test-image-manifests.sh' \
  'Docker CI runs this contract test'
assert_contains "$ci_contents" '.github/scripts/**' \
  'Docker CI triggers when the manifest script changes'
assert_contains "$ci_contents" '.github/workflows/publish.yml' \
  'Docker CI triggers when the manifest wiring changes'

if [[ "$failures" -ne 0 ]]; then
  printf '\n%d image manifest assertion(s) failed\n' "$failures" >&2
  exit 1
fi
echo "image manifest publish tests passed"
