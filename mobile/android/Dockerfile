# Copyright 2026 Blink Labs Software
# Licensed under the Apache License, Version 2.0.
#
# Android build environment for the Bursa mobile wallet. This is the CANONICAL
# Android build mechanism: it provides the full toolchain (Go + Node/npm +
# gomobile + Android SDK + NDK + JDK 17 + Gradle) so the AAR and APK build
# identically in CI and on a developer's machine, with no host Android SDK
# required.
#
# It does NOT help iOS: Xcode requires macOS and cannot run in a Linux container.
# The iOS xcframework + .app are built on a macOS CI runner / a Mac (see the CI
# workflow's `ios` job and ../README.md).
#
# Build the image (run from the repo root so the build context is the repo):
#   docker build --platform linux/amd64 -f mobile/android/Dockerfile -t bursa-android-build .
# Then run the build (mounts the repo + an output dir for the APK):
#   docker run --rm -v "$PWD":/code -v "$PWD/out":/out bursa-android-build
# (See mobile/android/build-in-docker.sh, the image's default entrypoint.)

FROM eclipse-temurin:17-jdk-noble

# --- Versions (override at build time with --build-arg) -----------------------
# Pin everything so the image — and therefore the artifact — is reproducible.
ARG GO_VERSION=1.26.0
ARG GO_LINUX_AMD64_SHA256=aac1b08a0fb0c4e0a7c1555beb7b59180b05dfc5a3d62e40e9de90cd42f88235
ARG NODE_VERSION=22.21.1
ARG ANDROID_CMDLINE_TOOLS_VERSION=11076708
ARG ANDROID_CMDLINE_TOOLS_SHA256=2d2d50857e4eb553af5a6dc3ad507a17adf43d115264b1afc116f95c92e5e258
ARG ANDROID_PLATFORM=android-35
ARG ANDROID_BUILD_TOOLS=35.0.0
ARG ANDROID_NDK_VERSION=27.2.12479018
ARG GRADLE_VERSION=8.11.1
ARG GRADLE_SHA256=f397b287023acdba1e9f6fc5ea72d22dd63669d59ed4a289a29b1a76eee151c6
ARG GOMOBILE_VERSION=v0.0.0-20260611195102-4dd8f1dbf5d2
ARG TARGETARCH
ARG BUILDER_UID=1000
ARG BUILDER_GID=1000

ENV DEBIAN_FRONTEND=noninteractive
ENV GRADLE_VERSION="${GRADLE_VERSION}"

RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
        amd64) ;; \
        arm64) echo "linux/arm64 Android container builds are not supported because gomobile init fails on linux/arm64; rebuild with --platform linux/amd64" >&2; exit 1 ;; \
        *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates unzip git make xz-utils \
    && rm -rf /var/lib/apt/lists/*

# --- Go -----------------------------------------------------------------------
# Fetch the Go toolchain for the supported image host architecture (amd64).
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
        amd64) goarch=amd64; go_sha256="${GO_LINUX_AMD64_SHA256}" ;; \
        *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${goarch}.tar.gz" -o /tmp/go.tgz; \
    echo "${go_sha256}  /tmp/go.tgz" | sha256sum -c -; \
    tar -C /usr/local -xzf /tmp/go.tgz; \
    rm /tmp/go.tgz
ENV GOPATH="/home/builder/go"
ENV PATH="/usr/local/go/bin:${GOPATH}/bin:${PATH}"

# --- Node/npm ----------------------------------------------------------------
# Needed by build-in-docker.sh so the canonical local Docker build embeds the
# production SPA instead of the committed webui placeholder.
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
        amd64) nodearch=x64 ;; \
        *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    nodefile="node-v${NODE_VERSION}-linux-${nodearch}.tar.xz"; \
    curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/${nodefile}" -o "/tmp/${nodefile}"; \
    curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/SHASUMS256.txt" -o /tmp/node-SHASUMS256.txt; \
    awk -v nodefile="${nodefile}" '$2 == nodefile { print; found = 1 } END { exit !found }' /tmp/node-SHASUMS256.txt > /tmp/node-SHASUMS256-selected.txt; \
    cd /tmp; \
    sha256sum -c node-SHASUMS256-selected.txt; \
    tar -C /usr/local --strip-components=1 -xJf "/tmp/${nodefile}"; \
    rm "/tmp/${nodefile}" /tmp/node-SHASUMS256.txt /tmp/node-SHASUMS256-selected.txt; \
    node --version; \
    npm --version

# --- Android SDK + NDK --------------------------------------------------------
ENV ANDROID_HOME="/opt/android-sdk"
ENV ANDROID_SDK_ROOT="${ANDROID_HOME}"
RUN set -eux; \
    mkdir -p "${ANDROID_HOME}/cmdline-tools"; \
    curl -fsSL "https://dl.google.com/android/repository/commandlinetools-linux-${ANDROID_CMDLINE_TOOLS_VERSION}_latest.zip" -o /tmp/cmdline-tools.zip; \
    echo "${ANDROID_CMDLINE_TOOLS_SHA256}  /tmp/cmdline-tools.zip" | sha256sum -c -; \
    unzip -q /tmp/cmdline-tools.zip -d "${ANDROID_HOME}/cmdline-tools"; \
    mv "${ANDROID_HOME}/cmdline-tools/cmdline-tools" "${ANDROID_HOME}/cmdline-tools/latest"; \
    rm /tmp/cmdline-tools.zip
ENV PATH="${ANDROID_HOME}/cmdline-tools/latest/bin:${ANDROID_HOME}/platform-tools:${PATH}"
RUN set -eux; \
    yes | sdkmanager --licenses >/dev/null; \
    sdkmanager --install \
        "platform-tools" \
        "platforms;${ANDROID_PLATFORM}" \
        "build-tools;${ANDROID_BUILD_TOOLS}" \
        "ndk;${ANDROID_NDK_VERSION}" >/dev/null
ENV ANDROID_NDK_HOME="${ANDROID_HOME}/ndk/${ANDROID_NDK_VERSION}"
ENV ANDROID_NDK_ROOT="${ANDROID_NDK_HOME}"

# --- Gradle -------------------------------------------------------------------
# Installed so the build script can materialize the project's Gradle wrapper
# (gradle wrapper) and then run ./gradlew, keeping the in-repo wrapper authoritative.
RUN set -eux; \
    curl -fsSL "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" -o /tmp/gradle.zip; \
    echo "${GRADLE_SHA256}  /tmp/gradle.zip" | sha256sum -c -; \
    unzip -q /tmp/gradle.zip -d /opt; \
    rm /tmp/gradle.zip; \
    ln -s "/opt/gradle-${GRADLE_VERSION}/bin/gradle" /usr/local/bin/gradle

# --- Non-root build user ------------------------------------------------------
ENV HOME="/home/builder"
RUN set -eux; \
    groupadd --gid "${BUILDER_GID}" builder; \
    useradd --uid "${BUILDER_UID}" --gid "${BUILDER_GID}" --create-home --shell /usr/sbin/nologin builder; \
    mkdir -p "${GOPATH}"; \
    chown -R builder:builder /home/builder

# --- gomobile -----------------------------------------------------------------
USER builder
RUN set -eux; \
    go install "golang.org/x/mobile/cmd/gomobile@${GOMOBILE_VERSION}"; \
    go install "golang.org/x/mobile/cmd/gobind@${GOMOBILE_VERSION}"; \
    gomobile init

USER root
WORKDIR /code
COPY mobile/android/build-in-docker.sh /usr/local/bin/build-in-docker.sh
RUN set -eux; \
    chmod +x /usr/local/bin/build-in-docker.sh; \
    chown builder:builder /code
USER builder
ENTRYPOINT ["/usr/local/bin/build-in-docker.sh"]
