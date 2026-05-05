cmake_minimum_required(VERSION 3.16)

# Windows: ASM not supported under MSVC — C fallbacks used instead
if(WIN32 AND MSVC)
    project(cutecontainer C)
else()
    project(cutecontainer C ASM)
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Windows: suppress CRT deprecation warnings
if(MSVC)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
endif()

# ---- Architecture detection ----

set(CC_ARCH "generic")
if(WIN32 AND MSVC)
    # MSVC: no inline ASM support — always use C fallbacks
    set(CC_ARCH "generic")
    add_compile_definitions(CP_ARCH_GENERIC CC_ARCH_GENERIC CF_ARCH_GENERIC)
    message(STATUS "cutecontainer: arch = generic (MSVC — C fallbacks)")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
    set(CC_ARCH "aarch64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
    set(CC_ARCH "x86_64")
endif()
if(NOT MSVC)
    message(STATUS "cutecontainer: arch = ${CC_ARCH}")
endif()

# ──────────────────────────────────────────────────────────────
# press module — rANS + LZ compression
# ──────────────────────────────────────────────────────────────

set(PRESS_SOURCES
    src/press/compress.c
    src/press/decompress.c
    src/press/freq.c
    src/press/xxhash32.c
    src/press/rans_fallback.c
    src/press/match_fallback.c
    src/press/memcopy_fallback.c
)

set(PRESS_ASM "")
if(NOT MSVC)
    if(CC_ARCH STREQUAL "aarch64")
        set(PRESS_ASM
            asm/aarch64/press/rans_encode.S
            asm/aarch64/press/rans_decode.S
            asm/aarch64/press/match_find.S
            asm/aarch64/press/memcopy.S
        )
    elseif(CC_ARCH STREQUAL "x86_64")
        set(PRESS_ASM
            asm/x86_64/press/rans_encode.S
            asm/x86_64/press/rans_decode.S
            asm/x86_64/press/match_find.S
            asm/x86_64/press/memcopy.S
        )
    endif()
endif()

# ──────────────────────────────────────────────────────────────
# crypt module — AES, SHA3, Kyber, pipe, cascade, fuse, token
# ──────────────────────────────────────────────────────────────

set(CRYPT_SOURCES
    src/crypt/aes256.c
    src/crypt/sha3.c
    src/crypt/kyber.c
    src/crypt/pipe.c
    src/crypt/cutehash.c
    src/crypt/cascade.c
    src/crypt/curve.c
    src/crypt/fuse.c
    src/crypt/token.c
)

set(CRYPT_ASM "")
if(NOT MSVC)
    if(CC_ARCH STREQUAL "aarch64")
        set(CRYPT_ASM
            asm/aarch64/crypt/aes256.S
            asm/aarch64/crypt/ntt.S
        )
        # cascade asm uses Mach-O relocations (@PAGE/@PAGEOFF) — Apple only
        if(APPLE)
            list(APPEND CRYPT_ASM
                asm/aarch64/crypt/cascade/fe25519.S
                asm/aarch64/crypt/cascade/scalarmult.S
                asm/aarch64/crypt/cascade/cutehash.S
            )
        endif()
        add_compile_definitions(CP_ARCH_AARCH64 CC_ARCH_AARCH64 CF_ARCH_AARCH64)
    elseif(CC_ARCH STREQUAL "x86_64")
        set(CRYPT_ASM
            asm/x86_64/crypt/aes256.S
            asm/x86_64/crypt/ntt.S
            asm/x86_64/crypt/cascade/fe25519.S
            asm/x86_64/crypt/cascade/scalarmult.S
            asm/x86_64/crypt/cascade/cutehash.S
        )
        add_compile_definitions(CP_ARCH_X86_64 CC_ARCH_X86_64 CF_ARCH_X86_64)
    else()
        add_compile_definitions(CP_ARCH_GENERIC CC_ARCH_GENERIC CF_ARCH_GENERIC)
    endif()
endif()

# ──────────────────────────────────────────────────────────────
# film module — spectral codec, CIE, develop, Metal, ProRes
# ──────────────────────────────────────────────────────────────

set(FILM_SOURCES
    src/film/spectral.c
    src/film/encode.c
    src/film/decode.c
    src/film/cie1931.c
    src/film/spectral_rgb.c
    src/film/film_develop.c
    src/film/delta_fallback.c
    src/film/deinterleave_fallback.c
)

set(FILM_ASM "")
if(NOT MSVC)
    if(CC_ARCH STREQUAL "aarch64")
        set(FILM_ASM
            asm/aarch64/film/delta.S
            asm/aarch64/film/deinterleave.S
        )
    elseif(CC_ARCH STREQUAL "x86_64")
        set(FILM_ASM
            asm/x86_64/film/delta.S
            asm/x86_64/film/deinterleave.S
        )
    endif()
endif()

# Apple platform sources (Metal + ProRes)
set(FILM_APPLE_SOURCES "")
set(APPLE_FRAMEWORKS "")

if(APPLE)
    enable_language(OBJC)
    set(FILM_APPLE_SOURCES
        src/film/metal_spectral.m
        src/film/prores.m
    )
    set(APPLE_FRAMEWORKS
        "-framework Metal"
        "-framework Foundation"
        "-framework AVFoundation"
        "-framework VideoToolbox"
        "-framework CoreVideo"
        "-framework CoreMedia"
        "-framework Security"
    )
endif()

# ──────────────────────────────────────────────────────────────
# container module — unified .cute format
# ──────────────────────────────────────────────────────────────

# ──────────────────────────────────────────────────────────────
# compute module — cross-platform GPU abstraction
# ──────────────────────────────────────────────────────────────

set(COMPUTE_SOURCES
    src/compute/compute.c
    src/compute/backend_cpu.c
    src/compute/backend_opencl.c
)

# Find OpenCL
if(APPLE)
    find_library(OPENCL_FW OpenCL)
else()
    find_package(OpenCL QUIET)
endif()

set(CONTAINER_SOURCES
    src/container/container.c
)

# ──────────────────────────────────────────────────────────────
# core SDK — module registry + dynamic loader + built-in modules
# ──────────────────────────────────────────────────────────────

set(CORE_SOURCES
    src/core/sdk.c
    src/core/press_module.c
    src/core/crypt_module.c
    src/core/film_module.c
    src/core/depo_module.c
    src/core/wrap.c
    src/core/wal.c
    src/core/volume.c
    src/core/archive.c
)

# ──────────────────────────────────────────────────────────────
# depo module — encrypted containers, lock modes, archives
# ──────────────────────────────────────────────────────────────

if(CMAKE_SYSTEM_NAME STREQUAL "Generic")
    # Switch / bare-metal: depo uses POSIX terminal I/O, mmap, etc.
    set(DEPO_SOURCES "")
else()
    set(DEPO_SOURCES src/depo/depo.c)
endif()

# ──────────────────────────────────────────────────────────────
# unified library (libcutecontainer.a)
# ──────────────────────────────────────────────────────────────

add_library(cutecontainer STATIC
    ${CONTAINER_SOURCES}
    ${CORE_SOURCES}
    ${COMPUTE_SOURCES}
    ${PRESS_SOURCES}  ${PRESS_ASM}
    ${CRYPT_SOURCES}  ${CRYPT_ASM}
    ${FILM_SOURCES}   ${FILM_ASM}
    ${FILM_APPLE_SOURCES}
    ${DEPO_SOURCES}
)

find_package(Threads REQUIRED)

target_include_directories(cutecontainer PUBLIC include)
target_link_libraries(cutecontainer PUBLIC ${APPLE_FRAMEWORKS} Threads::Threads)

if(APPLE)
    find_library(COMPRESSION_FW Compression)
    if(COMPRESSION_FW)
        target_link_libraries(cutecontainer PUBLIC ${COMPRESSION_FW})
    endif()
endif()

# Link OpenCL
if(APPLE AND OPENCL_FW)
    target_link_libraries(cutecontainer PUBLIC ${OPENCL_FW})
elseif(OpenCL_FOUND)
    target_link_libraries(cutecontainer PUBLIC OpenCL::OpenCL)
endif()

# dlopen for dynamic module loading (Unix, not bare-metal)
if(NOT WIN32 AND NOT CMAKE_SYSTEM_NAME STREQUAL "Generic")
    target_link_libraries(cutecontainer PUBLIC dl)
endif()

# Windows: bcrypt for CSPRNG (BCryptGenRandom)
if(WIN32)
    target_link_libraries(cutecontainer PUBLIC bcrypt)
endif()

if(APPLE)
    find_library(SECURITY_FW Security)
    if(SECURITY_FW)
        target_link_libraries(cutecontainer PUBLIC ${SECURITY_FW})
    endif()
endif()

# ──────────────────────────────────────────────────────────────
# standalone targets (CLI, GUI, tests)
# ──────────────────────────────────────────────────────────────

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR AND NOT CMAKE_SYSTEM_NAME STREQUAL "Generic")

    # CLI
    add_executable(cutecontainer-cli src/cli/main.c)
    target_link_libraries(cutecontainer-cli cutecontainer)

    # GUI (macOS only)
    if(APPLE)
        add_executable(cutecontainer-lm MACOSX_BUNDLE lm/main.m)
        target_link_libraries(cutecontainer-lm cutecontainer
            "-framework Cocoa"
            "-framework Metal"
            "-framework Foundation"
            "-framework Security"
            "-framework UniformTypeIdentifiers"
            "-framework QuartzCore"
        )
        set_target_properties(cutecontainer-lm PROPERTIES
            MACOSX_BUNDLE_BUNDLE_NAME "cutecontainer"
            MACOSX_BUNDLE_GUI_IDENTIFIER "com.cutecontainer.lm"
        )
    endif()

    # Tests
    enable_testing()

    add_executable(test_container tests/test_container.c)
    target_link_libraries(test_container cutecontainer)
    add_test(NAME container COMMAND test_container)

    add_executable(test_film tests/test_film.c)
    target_link_libraries(test_film cutecontainer)
    add_test(NAME film COMMAND test_film)

    add_executable(test_wrap tests/test_wrap.c)
    target_link_libraries(test_wrap cutecontainer)
    add_test(NAME wrap COMMAND test_wrap)

    add_executable(test_wal tests/test_wal.c)
    target_link_libraries(test_wal cutecontainer)
    add_test(NAME wal COMMAND test_wal)

    add_executable(bench_wal tests/bench_wal.c)
    target_link_libraries(bench_wal cutecontainer)

    add_executable(test_volume tests/test_volume.c)
    target_link_libraries(test_volume cutecontainer)
    add_test(NAME volume COMMAND test_volume)
endif()
