#!/usr/bin/env bash
# Cross-compile an ASI (64-bit Windows DLL) on Linux.
# usage: ./build.sh [lemp|<probe>...]   (default: lemp)
#
# lemp.asi is the mod's one ASI: lemp.cpp plus the modules below, each its own
# translation unit (lemp.h). The research probes still build one file each.
set -euo pipefail
cd "$(dirname "$0")"
CXX=${CXX:-x86_64-w64-mingw32-g++}
LEMP_MODULES=(lemp crash_log join_patch loadmap_hook mp_menu mp_save nofocuspause online_api repl_probe lemp_voice lemp_voice_audio)
FLAGS=(-O2 -std=c++17 -municode -Wall -Wno-unused-parameter)
# No build machine's paths in the binary (__FILE__ in asserts and logs): they
# named the build machine's paths. libopus.a is built the same
# way (fetch-deps.sh).
FLAGS+=(-ffile-prefix-map="$(cd ../.. && pwd)"=lemp)
# The LEMP release this lemp.asi belongs to, compiled in (lemp_online.h
# kRelease): the DLC's ModVersion must equal it. VERSION beside this script
# (the published repository), else the project's.
REL_FILE=VERSION; [ -f "$REL_FILE" ] || REL_FILE=../../VERSION
LEMP_RELEASE=${LEMP_RELEASE:-$(tr -d ' \r\n' < "$REL_FILE")}
[[ "$LEMP_RELEASE" =~ ^[0-9]+(\.[0-9]+){1,3}$ ]] || { echo "build.sh: no release in $REL_FILE: '$LEMP_RELEASE'" >&2; exit 1; }
FLAGS+=(-DLEMP_RELEASE="\"$LEMP_RELEASE\"")
# Voice chat's libraries (fetch-deps.sh): vendor/ sits in the main checkout, also
# when this runs from a worktree (gitignored, so a worktree has none).
VENDOR=${VENDOR:-$(cd "$(git rev-parse --path-format=absolute --git-common-dir)/.." && pwd)/vendor}
VOICE_INC=(-I"$VENDOR/miniaudio" -I"$VENDOR/opus/include")
FLAGS+=(-ffile-prefix-map="$VENDOR"=vendor)
VOICE_LIB=(-L"$VENDOR/opus/build-mingw64" -lopus -lole32)
LINK=(-shared -static -static-libgcc -static-libstdc++ -Wl,--subsystem,windows -s)
if [ $# -gt 0 ]; then targets=("$@"); else targets=(lemp); fi
for t in "${targets[@]}"; do
    if [ "$t" = lemp ]; then
        obj="$(mktemp -d)"
        trap 'rm -rf "$obj"' EXIT
        objs=()
        for m in "${LEMP_MODULES[@]}"; do
            "$CXX" -c "${FLAGS[@]}" "${VOICE_INC[@]}" -o "$obj/$m.o" "$m.cpp" &
            objs+=("$obj/$m.o")
        done
        for job in $(jobs -p); do wait "$job"; done   # a failed compile fails the build
        # -lwinhttp -lws2_32 -lbcrypt: mp_save's lemp_online.h (the MP server)
        "$CXX" "${LINK[@]}" -o lemp.asi "${objs[@]}" "${VOICE_LIB[@]}" -lwinhttp -lws2_32 -lbcrypt
    else
        "$CXX" "${LINK[@]}" -o "$t.asi" "$t.cpp" "${FLAGS[@]}"
    fi
    echo "built: $PWD/$t.asi  ($(stat -c%s "$t.asi") bytes, release $LEMP_RELEASE)"
done
