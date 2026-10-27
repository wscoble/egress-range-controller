# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY api/ api/
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags='-s -w -buildid=' -o /out/egress-range-controller ./cmd

FROM gcr.io/distroless/static:nonroot
LABEL org.opencontainers.image.source=https://github.com/wscoble/egress-range-controller \
      org.opencontainers.image.licenses=Apache-2.0
COPY --from=build /out/egress-range-controller /egress-range-controller
USER 65532:65532
ENTRYPOINT ["/egress-range-controller"]
