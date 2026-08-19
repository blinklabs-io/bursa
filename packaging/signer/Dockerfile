# Container image for the bursa signer and KES agent. Both are subcommands of
# the single `bursa` binary, so one image serves both daemons; pick the daemon
# with the container command (`signer` or `kes-agent`).
#
# Build from the repository root:
#   docker build -f packaging/signer/Dockerfile -t bursa-signer .
#
# Run the signer (the -v /var/lib/... mount below is only needed if using the
# `file` (SQLite) watermark type - it needs a writable, persistent path):
#   docker run --rm -p 8090:8090 \
#     -v /etc/bursa/signer:/etc/bursa/signer:ro \
#     -v /var/lib/bursa/signer:/var/lib/bursa/signer \
#     -e SIGNER_JWT_SECRET \
#     bursa-signer signer --config /etc/bursa/signer/signer.yaml
#
# Run the KES agent (share the socket dir with the block producer; the guard
# file directory must also be a writable, persistent volume owned by/writable
# by UID 65532):
#   docker run --rm \
#     -v /run/bursa/kes-agent:/run/bursa/kes-agent \
#     -v /etc/bursa/kes-agent:/etc/bursa/kes-agent:ro \
#     -v /var/lib/bursa/kes-agent:/var/lib/bursa/kes-agent \
#     --ulimit memlock=67108864:67108864 \
#     bursa-signer kes-agent --config /etc/bursa/kes-agent/kes-agent.yaml

FROM ghcr.io/blinklabs-io/go:1.26.3-1 AS build
WORKDIR /code
COPY go.* .
RUN go mod download
COPY . .
# Root module is pure Go; the signer/kes-agent need no CGO.
RUN CGO_ENABLED=0 make build

# `static`, not `glibc-dynamic`: CGO_ENABLED=0 above produces a fully static
# binary that never links glibc, so the dedicated static base is the correct
# (and smaller) match.
FROM cgr.dev/chainguard/static AS bursa
COPY --from=build /code/bursa /bin/
# Chainguard images run as a non-root user (65532) by default.
EXPOSE 8090
ENTRYPOINT ["bursa"]
CMD ["signer"]
