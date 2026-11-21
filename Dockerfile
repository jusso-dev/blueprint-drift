# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=1.0.0
ARG COMMIT=none

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o /out/blueprint-drift ./cmd/blueprint-drift

FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="blueprint-drift" \
      org.opencontainers.image.description="Read-only ASD Blueprint for Secure Cloud drift checker and IRAP evidence pack generator" \
      org.opencontainers.image.source="https://github.com/jusso-dev/blueprint-drift" \
      org.opencontainers.image.licenses="MIT"

COPY --from=builder /out/blueprint-drift /usr/local/bin/blueprint-drift
COPY --from=builder /src/blueprint/settings /etc/blueprint-drift/settings

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/blueprint-drift"]
CMD ["version"]
