#!/usr/bin/env bash

set -euo pipefail

docker run --rm --user "$(id -u):$(id -g)" -v "${PWD}:/local" openapitools/openapi-generator-cli:v7.18.0 generate -i /local/docs/swagger.yaml --git-user-id blinklabs-io --git-repo-id bursa -g go -o /local/openapi -c /local/openapi-config.yml
git apply openapi-overrides.patch
gofmt -s -w openapi
cd openapi && go mod tidy
