#!/usr/bin/env bash

docker run --rm -v "${PWD}:/local" openapitools/openapi-generator-cli generate -i /local/docs/swagger.yaml --git-user-id blinklabs-io --git-repo-id bursa -g go -o /local/openapi -c /local/openapi-config.yml
make format golines
cd openapi && sed -i '' 's/go 1.23/go 1.24.0/' go.mod && go mod tidy
