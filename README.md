# cutecontainer

Unified `.cute` toolchain. Container format, compression, encryption, spectral film codec, encrypted archives, game asset volumes, and a cross-platform archive manager — in one C11 library with zero external dependencies.

## Quick start

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
ctest --output-on-failure
```

On Windows (MSVC):
```bash
cmake -B build -G "Visual Studio 17 2022"
cmake --build build --config Release
ctest --test-dir build -C Release
```

## Link

```bash
cc -o myapp myapp.c -Iinclude -Lbuild -lcutecontainer -ldl -lpthread
```

On Windows, also link `bcrypt.lib`. On macOS, the build links Security, Metal, AVFoundation, VideoToolbox, and OpenCL frameworks automatically.

## Modules

| Module | Prefix | What it does |
|--------|--------|-------------|
| **container** | `cc_` | Unified `.cute` file format — typed payloads, stackable compression + encryption layers, legacy format detection |
| **press** | `cp_` | Extreme compression — 4-way interleaved rANS entropy coding, LZ match finding, per-arch ASM |
| **crypt** | `cc_` | Post-quantum encryption — AES-256-GCM, SHA3-256, ML-KEM-768 (Kyber), Curve25519, cascade signing, fuse tokens |
| **film** | `cf_` | Spectral image codec — 128/256/512-bit wavelength bands, CIE 1931, film curves, Metal/OpenCL GPU, ProRes hardware encode |
| **depo** | | Encrypted containers — password + temporal + fuse-limited locks, role-based archives, append-only ledger |
| **sdk** | `cc_` | Module registry + dynamic plugin loader — built-in modules + runtime `.dylib`/`.so`/`.dll` loading |
| **compute** | `cc_` | Cross-platform GPU abstraction — Metal → OpenCL → CPU fallback, runtime capability probing |
| **wal** | `cc_` | Write-ahead log — cleartext fast-access index, 1,228x faster than full container open, hash-chained integrity |
| **volume** | `cc_vol_` | Game asset volumes — pack thousands of assets into one `.cute` file, mount + on-demand decompress |
| **wrap** | `cc_wrap_` | Universal content description — 44+ typed metadata schemas for image, video, 3D, game, office, ML |
| **archive** | `cc_archive_` | Multi-format archive support — `.cute`, `.zip`, `.tar`, `.7z` read/write + self-extracting executables |

## Volume system

Pack assets into a single `.cute` volume with per-asset compression, on-demand loading, and a writable overlay for user data:

```c
// build a volume
cc_vol_builder *b = cc_vol_builder_create("game.cute");
cc_vol_builder_add_file(b, "textures/hero.png", "art/hero.png", CC_VOL_COMPRESS);
cc_vol_builder_add_file(b, "scripts/main.lua", "src/main.lua", CC_VOL_RAW);
cc_vol_builder_set_wrap(b, CC_WRAP_TEXTURE);
cc_vol_builder_set_group(b, 1);
cc_vol_builder_finish(b);

// mount and use
cc_volume *vol = cc_vol_mount("game.cute");
void *tex = cc_vol_load(vol, "textures/hero.png", &len);

// writable overlay (saves, config, mods)
cc_vol_write_overlay(vol, "saves/slot1.sav", data, len);
void *cfg = cc_vol_load_overlay(vol, "config.json", &len); // overlay → volume fallback

// executable volumes
cc_vol_builder_add_entry_point(b, CC_PLAT_MACOS, CC_INTERP_NONE, "bin/game", "", CC_EXEC_SANDBOX);
cc_vol_exec(vol); // extracts entry point, injects $CUTE_VOLUME/$CUTE_SAVES, launches
```

## WAL rail

Cleartext index appended to containers. Answers "what's in this file?" without decrypting or decompressing:

```c
cc_wal *w = cc_wal_open(file_data, file_len);           // read from EOF
cc_content_type type = cc_wal_content_type(w);           // 3.6 ns
uint64_t size = cc_wal_original_size(w);                 // 3.6 ns
uint16_t layers = cc_wal_layer_flags(w);                 // 3.6 ns
// vs cc_container_open(): 712 us (1,228x slower — must decompress)
```

## Platform support

|  | macOS ARM | macOS Intel | Linux | Windows |
|--|-----------|-------------|-------|---------|
| CPU codecs | aarch64 ASM | x86_64 ASM | x86_64 ASM | C fallback (MSVC) |
| GPU compute | Metal + OpenCL | Metal + OpenCL | OpenCL | OpenCL |
| ProRes | Media engine HW | VideoToolbox SW | — | — |
| HW encode | Media engine | VideoToolbox | NVENC/QSV/AMF | NVENC/QSV/AMF |
| GUI | Cocoa (grid browser) | Cocoa | — | — |
| Dynamic modules | .dylib | .dylib | .so | .dll |
| CSPRNG | SecRandomCopyBytes | SecRandomCopyBytes | getrandom() | BCryptGenRandom |

## CLI

```
cutecontainer compress file.txt        → file.txt.cute
cutecontainer decompress file.cute     → file.txt
cutecontainer info file.cute           → type, layers, size
cutecontainer modules                  → list loaded modules
cutecontainer lock file.txt            → encrypted .cute (password)
cutecontainer unlock file.cute         → decrypted
```

## Dynamic module SDK

```c
// my_codec.c → my_codec.dylib
#include <cutecontainer/sdk.h>

const cc_module *cc_module_init(void) {
    static const cc_module m = {
        .name = "my-codec",
        .type = CC_TYPE_CUSTOM,
        .sdk_version = CC_SDK_VERSION,
        .caps = CC_CAP_ENCODE | CC_CAP_DECODE,
        .probe = my_probe,
        .encode = my_encode,
        .decode = my_decode,
        .free_buf = free,
    };
    return &m;
}
```

Drop in `~/.cutecontainer/modules/` — loaded automatically.

## File structure

```
include/cutecontainer/     18 headers (public API)
src/container/             container format I/O
src/core/                  SDK, modules, WAL, volume, wrap, archive
src/press/                 rANS + LZ compression
src/crypt/                 AES, SHA3, Kyber, pipe, cascade, fuse, token
src/film/                  spectral codec, CIE, develop, Metal, ProRes
src/depo/                  encrypted containers, lock modes, ledger
src/compute/               Metal/OpenCL/CPU abstraction
src/cli/                   command-line tool
lm/                        macOS GUI (grid-based archive browser)
asm/aarch64/               ARM64 assembly (press, crypt, film)
asm/x86_64/                x86-64 assembly (press, crypt, film)
metal/                     Metal compute shaders
opencl/                    OpenCL compute kernels
tests/                     test suites + benchmarks
docs/                      HTML documentation
```
