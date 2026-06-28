# Copyright 2026 Blink Labs Software
# Licensed under the Apache License, Version 2.0.
#
# Android build environment for the Bursa mobile wallet. This is the CANONICAL
# Android build mechanism: it provides the full toolchain (Go + gomobile +
# Android SDK + NDK + JDK 17 + Gradle) so the AAR and APK build identically in
# CI and on a developer's machine, with no host Android SDK required.
#
# It does NOT help iOS: Xcode requires macOS and cannot run in a Linux container.
# The iOS xcframework + .app are built on a macOS CI runner / a Mac (see the CI
# workflow's `ios` job and ../README.md).
#
# Build the image (run from the repo root so the build context is the repo):
#   docker build -f mobile/android/Dockerfile -t bursa-android-build .
# Then run the build (mounts the repo + an output dir for the APK):
#   docker run --rm -v "$PWD":/code -v "$PWD/out":/out bursa-android-build
# (See mobile/android/build-in-docker.sh, the image's default entrypoint.)

FROM eclipse-temurin:17-jdk-noble

# --- Versions (override at build time with --build-arg) -----------------------
# Pin everything so the image — and therefore the artifact — is reproducible.
ARG GO_VERSION=1.26.0
ARG ANDROID_CMDLINE_TOOLS_VERSION=11076708
ARG ANDROID_PLATFORM=android-35
ARG ANDROID_BUILD_TOOLS=35.0.0
ARG ANDROID_NDK_VERSION=27.2.12479018
ARG GRADLE_VERSION=8.11.1
ARG GOMOBILE_VERSION=latest
ARG TARGETARCH

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates unzip git make \
    && rm -rf /var/lib/apt/lists/*

# --- Go -----------------------------------------------------------------------
# Fetch the Go toolchain for the image's host architecture (amd64 or arm64).
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
        amd64) goarch=amd64 ;; \
        arm64) goarch=arm64 ;; \
        *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${goarch}.tar.gz" -o /tmp/go.tgz; \
    tar -C /usr/local -xzf /tmp/go.tgz; \
    rm /tmp/go.tgz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV GOPATH="/root/go"

# --- Android SDK + NDK --------------------------------------------------------
ENV ANDROID_HOME="/opt/android-sdk"
ENV ANDROID_SDK_ROOT="${ANDROID_HOME}"
RUN set -eux; \
    mkdir -p "${ANDROID_HOME}/cmdline-tools"; \
    curl -fsSL "https://dl.google.com/android/repository/commandlinetools-linux-${ANDROID_CMDLINE_TOOLS_VERSION}_latest.zip" -o /tmp/cmdline-tools.zip; \
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
    unzip -q /tmp/gradle.zip -d /opt; \
    rm /tmp/gradle.zip; \
    ln -s "/opt/gradle-${GRADLE_VERSION}/bin/gradle" /usr/local/bin/gradle

# --- gomobile -----------------------------------------------------------------
RUN set -eux; \
    go install "golang.org/x/mobile/cmd/gomobile@${GOMOBILE_VERSION}"; \
    go install "golang.org/x/mobile/cmd/gobind@${GOMOBILE_VERSION}"; \
    gomobile init

WORKDIR /code
COPY mobile/android/build-in-docker.sh /usr/local/bin/build-in-docker.sh
RUN chmod +x /usr/local/bin/build-in-docker.sh
ENTRYPOINT ["/usr/local/bin/build-in-docker.sh"]
