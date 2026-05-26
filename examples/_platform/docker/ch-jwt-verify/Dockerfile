# Self-contained build of the ch-jwt-verify sidecar from local source.
# Used by docker-compose.yml so the example runs without needing a
# published image. Build context is the repo root (../..) so the
# multi-stage build sees go.mod + cmd/. pkg/oauth was extracted to
# github.com/altinity/go-mcp-oauth-sdk; go mod download fetches it.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
RUN CGO_ENABLED=0 go build \
    -ldflags="-s -w -X main.version=docker-compose" \
    -o /out/ch-jwt-verify ./cmd/ch-jwt-verify

FROM alpine:3.23
RUN apk --no-cache add ca-certificates
COPY --from=build /out/ch-jwt-verify /bin/ch-jwt-verify
EXPOSE 9999
ENTRYPOINT ["/bin/ch-jwt-verify"]
