# syntax=docker/dockerfile:1.23

ARG GO_VERSION=1.26.5

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build

WORKDIR /src

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=0.2.1
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
ARG MODIFIED=false

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download && go mod verify

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build \
      -trimpath \
      -buildvcs=false \
      -ldflags="-s -w -buildid= \
        -X github.com/Naenier/orynelo/internal/buildinfo.version=${VERSION} \
        -X github.com/Naenier/orynelo/internal/buildinfo.commit=${COMMIT} \
        -X github.com/Naenier/orynelo/internal/buildinfo.buildDate=${BUILD_DATE} \
        -X github.com/Naenier/orynelo/internal/buildinfo.modified=${MODIFIED}" \
      -o /out/orynelo \
      ./cmd/orynelo && \
    mkdir -p /out/home/nonroot

FROM gcr.io/distroless/static-debian13:nonroot

ARG COMMIT=unknown
ARG BUILD_DATE=unknown
ARG VERSION=0.2.1

LABEL org.opencontainers.image.title="Orynelo" \
      org.opencontainers.image.description="Evidence-based network reachability diagnostics" \
      org.opencontainers.image.url="https://github.com/Naenier/orynelo" \
      org.opencontainers.image.source="https://github.com/Naenier/orynelo" \
      org.opencontainers.image.documentation="https://github.com/Naenier/orynelo#readme" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.version="${VERSION}"

COPY --from=build --chown=nonroot:nonroot /out/orynelo /orynelo
COPY --from=build --chown=nonroot:nonroot /out/home/ /home/

USER nonroot:nonroot
ENV HOME=/home/nonroot
WORKDIR /home/nonroot
ENTRYPOINT ["/orynelo"]
