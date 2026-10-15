# lemp.asi

[![Latest tag](https://img.shields.io/github/v/tag/PayDay42/lemp-asi?label=release)](https://github.com/PayDay42/lemp-asi/tags)
[![License: MIT](https://img.shields.io/github/license/PayDay42/lemp-asi)](LICENSE)

The native plugin of **LEMP**, Mass Effect 3's horde mode multiplayer for the
Mass Effect Legendary Edition. The mod itself is a DLC folder
(`DLC_MOD_LEMultiplayer`); `lemp.asi` is the part that runs as code inside
`MassEffect3.exe`, loaded by an ASI loader (LEBinkProxy). It provides what the
DLC's UnrealScript cannot: the online lobby and matchmaking through the LEMP
master server, NAT hole punching, the multiplayer save records, voice chat,
the main menu's Multiplayer entry, the crash log, and the build key players
are matched on.

Each release from 0.4.11 on has a tag, `v<version>`, holding the sources
`lemp.asi` of that release was built from.

## Building

Cross-compiled on Linux with MinGW-w64 (`x86_64-w64-mingw32-g++`, C++17):

```sh
./fetch-deps.sh      # vendor/opus (v1.5.2, built static) and vendor/miniaudio (0.11.22)
./build.sh           # -> lemp.asi
```

`build.sh` also builds the research probes named on its command line; with
no arguments it builds `lemp.asi` only. It compiles in the release from
`VERSION`: the LEMP DLC refuses a `lemp.asi` of another release.

The binary is built with `-ffile-prefix-map`, so it carries no path of the
machine it was built on.

## Licence

MIT (`LICENSE`). Statically linked: Opus (BSD-3-Clause,
<https://opus-codec.org>) and miniaudio (public domain / MIT-0,
<https://miniaud.io>); `fetch-deps.sh` puts their licence files in `vendor/`.

Mass Effect is a trademark of EA International (Studio and Publishing) Ltd.
LEMP is not affiliated with or endorsed by EA or BioWare.
