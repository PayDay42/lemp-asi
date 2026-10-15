#!/usr/bin/env bash
# Fetch and build lemp.asi's two libraries into vendor/ (gitignored):
#   Opus 1.5.2, statically cross-built with MinGW-w64, and miniaudio 0.11.22.
# Pinned versions; the miniaudio header is checked by its SHA-256.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p vendor
if [ ! -f vendor/opus/build-mingw64/libopus.a ]; then
    [ -d vendor/opus ] || git clone --depth 1 --branch v1.5.2 https://github.com/xiph/opus.git vendor/opus
    cmake -S vendor/opus -B vendor/opus/build-mingw64 -DCMAKE_SYSTEM_NAME=Windows \
        -DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc \
        -DCMAKE_C_FLAGS="-ffile-prefix-map=$PWD/vendor/opus=opus" \
        -DCMAKE_BUILD_TYPE=Release -DOPUS_BUILD_SHARED_LIBRARY=OFF -DOPUS_BUILD_TESTING=OFF \
        -DOPUS_BUILD_PROGRAMS=OFF -DOPUS_STACK_PROTECTOR=OFF -DOPUS_FORTIFY_SOURCE=OFF
    cmake --build vendor/opus/build-mingw64 -j"$(nproc)"
fi
if [ ! -f vendor/miniaudio/miniaudio.h ]; then
    mkdir -p vendor/miniaudio
    curl -sSfLo vendor/miniaudio/miniaudio.h https://raw.githubusercontent.com/mackron/miniaudio/0.11.22/miniaudio.h
    curl -sSfLo vendor/miniaudio/LICENSE https://raw.githubusercontent.com/mackron/miniaudio/0.11.22/LICENSE
fi
echo "9019743287e443c55e5737a7297f38e5e358561701d6db2d905afb114390c410  vendor/miniaudio/miniaudio.h" | sha256sum -c -
