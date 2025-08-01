FROM ghcr.io/blinklabs-io/go:1.24.5-1 AS build

WORKDIR /code
COPY go.* .
RUN go mod download
COPY . .
RUN make build

FROM cgr.dev/chainguard/glibc-dynamic AS bursa
COPY --from=build /code/bursa /bin/
ENTRYPOINT ["bursa"]
