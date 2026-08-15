FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.25.12-alpine3.23@sha256:cc985ef6f9c3bf9ece7488129c9abe0a150388ccdfa428d886fc709dca0b230a AS build

ARG TARGETOS
ARG TARGETARCH
ARG AEB_VERSION=devel
ARG AEB_COMMIT=unknown

WORKDIR /src
COPY runner ./runner
RUN cd runner && CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -mod=vendor -trimpath -buildvcs=false -ldflags="-s -w -X main.releaseVersion=$AEB_VERSION -X main.releaseCommit=$AEB_COMMIT" -o /out/aeb-gauntlet .

FROM docker.io/library/alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

ARG AEB_VERSION=devel
ARG AEB_COMMIT=unknown

LABEL org.opencontainers.image.title="Agent Egress Bench runner"
LABEL org.opencontainers.image.description="Tool-neutral Agent Egress Bench runner and corpus"
LABEL org.opencontainers.image.source="https://github.com/luckyPipewrench/agent-egress-bench"
LABEL org.opencontainers.image.version="$AEB_VERSION"
LABEL org.opencontainers.image.revision="$AEB_COMMIT"
LABEL org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /out/aeb-gauntlet /usr/local/bin/aeb-gauntlet
COPY cases /opt/aeb/cases
COPY schemas /opt/aeb/schemas
COPY contracts /opt/aeb/contracts
COPY capability-registry/aeb.core-capabilities /opt/aeb/capability-registry/aeb.core-capabilities
COPY examples /opt/aeb/examples
COPY LICENSE NOTICE README.md /opt/aeb/

ENV AEB_CASES_DIR=/opt/aeb/cases
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/aeb-gauntlet"]
