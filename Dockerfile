# Keyway: single static Go binary. Pure-Go SQLite (modernc.org/sqlite, no
# CGO) means the builder output runs on scratch with zero shared libs.

FROM golang:1.26-alpine AS build
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/keyway ./cmd/keyway && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/demo-sso ./examples/demo-sso

FROM scratch
# CA bundle: without it the container cannot TLS to any IdP (OIDC discovery
# fails with "certificate signed by unknown authority"). Still no shell.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
# Non-root: numeric UID keeps the image portable across runtimes that
# ignore /etc/passwd. /data holds the SQLite file plus SP key/cert.
COPY --from=build /out/keyway /keyway
COPY --from=build /out/demo-sso /demo-sso
USER 65532:65532
WORKDIR /data
EXPOSE 8080
ENTRYPOINT ["/keyway"]
