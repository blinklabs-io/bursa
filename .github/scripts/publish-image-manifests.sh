#!/usr/bin/env bash
#
# Compose the multi-architecture image manifests for a publish run.
#
# The build matrix publishes one image per architecture, tagged with the
# versioned tag plus an `-amd64` / `-arm64` suffix. It deliberately publishes no
# floating tag: a floating tag pushed from each architecture job would race, and
# the winner would be a single-architecture image.
#
# This script therefore does two distinct things, in order:
#
#   1. Compose every versioned tag from the architecture tags the matrix
#      actually published.
#   2. Point each floating alias (`:latest`) at the versioned manifest composed
#      in step 1, so an alias never exists before the manifest it names.
#
# Inputs:
#   IMAGE_TAGS      newline-separated tag list from docker/metadata-action
#   PRIMARY_VERSION metadata-action's `version` output, i.e. the versioned tag
#                   that floating aliases resolve to
#   GITHUB_OUTPUT   step output file
set -euo pipefail

: "${IMAGE_TAGS:?IMAGE_TAGS is required}"
: "${PRIMARY_VERSION:?PRIMARY_VERSION is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

declare -A seen=()
declare -a versioned=()
declare -a floating=()
dockerhub_tag=""
ghcr_tag=""

while IFS= read -r tag; do
  tag="${tag%$'\r'}"
  [[ -z "$tag" ]] && continue
  [[ -n "${seen[$tag]+set}" ]] && continue
  seen["$tag"]=1

  # Split on the final colon so a registry host:port stays with the image.
  image="${tag%:*}"
  version="${tag##*:}"

  if [[ "$version" == latest ]]; then
    floating+=("$image")
    continue
  fi

  versioned+=("$tag")
  # Attestations must name the versioned manifest, so record the first
  # versioned tag seen for each registry.
  if [[ "$tag" == ghcr.io/* ]]; then
    [[ -z "$ghcr_tag" ]] && ghcr_tag="$tag"
  else
    [[ -z "$dockerhub_tag" ]] && dockerhub_tag="$tag"
  fi
done <<< "$IMAGE_TAGS"

if [[ ${#versioned[@]} -eq 0 ]]; then
  echo "no versioned image manifest tags were planned" >&2
  exit 1
fi
if [[ -z "$dockerhub_tag" || -z "$ghcr_tag" ]]; then
  echo "expected a versioned tag for both Docker Hub and GHCR" >&2
  echo "planned: ${versioned[*]}" >&2
  exit 1
fi

# Step 1: versioned manifests, composed from the published architecture tags.
#
# Use `docker buildx imagetools create`, not `docker manifest create`: buildx
# pushes each per-architecture tag as an OCI image index (image + provenance
# attestation), and `docker manifest create` refuses to nest one, failing with
# "<tag>-amd64 is a manifest list". imagetools composes the per-architecture
# indexes into a single multi-architecture index and pushes it in one step.
for tag in "${versioned[@]}"; do
  docker buildx imagetools create -t "$tag" \
    "${tag}-amd64" \
    "${tag}-arm64"
done

# Step 2: floating aliases, resolved from the versioned manifest just composed.
for image in "${floating[@]}"; do
  source_tag="${image}:${PRIMARY_VERSION}"
  found=""
  for tag in "${versioned[@]}"; do
    [[ "$tag" == "$source_tag" ]] && found=1 && break
  done
  if [[ -z "$found" ]]; then
    echo "cannot alias ${image}:latest: no versioned manifest ${source_tag}" >&2
    exit 1
  fi
  docker buildx imagetools create -t "${image}:latest" "$source_tag"
done

dockerhub_digest="$(docker buildx imagetools inspect --format '{{.Manifest.Digest}}' "$dockerhub_tag")"
ghcr_digest="$(docker buildx imagetools inspect --format '{{.Manifest.Digest}}' "$ghcr_tag")"
printf 'dockerhub-digest=%s\n' "$dockerhub_digest" >> "$GITHUB_OUTPUT"
printf 'ghcr-digest=%s\n' "$ghcr_digest" >> "$GITHUB_OUTPUT"
