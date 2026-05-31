# syntax=docker/dockerfile:1.6
#
# Exalm container image.
#
# Two stages:
#   1. build  — golang:1.26-alpine with CGO disabled, produces a static binary
#   2. runtime — distroless static-debian12 nonroot for minimal attack surface
#
# Build args:
#   VERSION     — semver tag, baked into the binary via -ldflags
#   COMMIT      — short git SHA
#   BUILD_DATE  — RFC3339 UTC timestamp
#
# Usage:
#   docker build -t exalm:dev .
#   docker run --rm -p 7433:7433 \
#       -e ANTHROPIC_API_KEY=sk-ant-... \
#       -e EXALM_LLM_PROVIDER=claude \
#       exalm:dev

# -----------------------------------------------------------------------------
# Stage 1: build
# -----------------------------------------------------------------------------
FROM golang:1.26-alpine AS build

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /src

# Cache module downloads in a dedicated layer.
# pkg/plugin/go.mod must be present before `go mod download` so the
# replace directive (replace github.com/exalm-ai/exalm/pkg/plugin => ./pkg/plugin)
# in go.mod can resolve the local sub-module without hitting the proxy.
COPY go.mod go.sum ./
COPY pkg/plugin/go.mod pkg/plugin/go.mod
RUN go mod download

# Copy the rest of the source.
COPY . .

# Build a fully static binary. CGO_ENABLED=0 + GOOS=linux guarantees the
# resulting binary runs on distroless without glibc dependencies.
RUN CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags "-s -w \
            -X github.com/exalm-ai/exalm/internal/version.Version=${VERSION} \
            -X github.com/exalm-ai/exalm/internal/version.Commit=${COMMIT} \
            -X github.com/exalm-ai/exalm/internal/version.BuildDate=${BUILD_DATE}" \
        -o /out/exalm ./cmd/exalm

# -----------------------------------------------------------------------------
# Stage 2: runtime
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="exalm" \
      org.opencontainers.image.description="Open-source AI ops assistant" \
      org.opencontainers.image.source="https://github.com/exalm-ai/exalm" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Exalm"

COPY --from=build /out/exalm /usr/local/bin/exalm

EXPOSE 7433
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/exalm"]
CMD ["serve", "--port=7433", "--open-browser=false", "--interval=60s"]
