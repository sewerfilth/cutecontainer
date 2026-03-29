/*
 * compute.h — cross-platform GPU compute abstraction
 *
 * Provides a single API that dispatches to the best available backend:
 *   - Metal    (macOS / iOS)
 *   - OpenCL   (macOS / Linux / Windows)
 *   - Vulkan compute (Linux / Windows — future)
 *   - CPU fallback (always available)
 *
 * Kernels are written once in a portable subset and compiled at
 * runtime for the target backend. The abstraction handles device
 * selection, buffer management, and dispatch.
 */

#ifndef CUTECONTAINER_COMPUTE_H
#define CUTECONTAINER_COMPUTE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Backend selection ---- */

typedef enum {
    CC_COMPUTE_CPU     = 0,     /* always available */
    CC_COMPUTE_METAL   = 1,     /* macOS / iOS */
    CC_COMPUTE_OPENCL  = 2,     /* macOS / Linux / Windows */
    CC_COMPUTE_VULKAN  = 3,     /* Linux / Windows */
    CC_COMPUTE_CUDA    = 4,     /* NVIDIA (via NVMe / CUDA interop) */
} cc_compute_backend;

/* ---- Platform capability flags ---- */

/* GPU compute */
#define CC_PLATFORM_HAS_METAL     0x00000001
#define CC_PLATFORM_HAS_OPENCL    0x00000002
#define CC_PLATFORM_HAS_VULKAN    0x00000004
#define CC_PLATFORM_HAS_CUDA      0x00000008

/* CPU SIMD */
#define CC_PLATFORM_HAS_AVX2      0x00000010
#define CC_PLATFORM_HAS_AVX512    0x00000020
#define CC_PLATFORM_HAS_NEON      0x00000040
#define CC_PLATFORM_HAS_SVE       0x00000080  /* ARM SVE / SVE2 (Neoverse) */

/* CPU crypto / specialized */
#define CC_PLATFORM_HAS_AES_NI    0x00000100  /* x86 AES-NI */
#define CC_PLATFORM_HAS_AESE      0x00000200  /* ARM AESE/AESMC crypto ext */
#define CC_PLATFORM_HAS_SHA_NI    0x00000400  /* x86 SHA-NI (SHA256 accel) */
#define CC_PLATFORM_HAS_SHA3      0x00000800  /* ARM SHA3 instructions */
#define CC_PLATFORM_HAS_SHA512    0x00001000  /* ARM SHA512 instructions */
#define CC_PLATFORM_HAS_CRC32     0x00002000  /* CRC32 instructions */
#define CC_PLATFORM_HAS_PMULL     0x00004000  /* ARM polynomial multiply (GCM) */

/* media / specialized HW */
#define CC_PLATFORM_HAS_PRORES_HW 0x00008000  /* Apple media engine ProRes */
#define CC_PLATFORM_HAS_NVENC     0x00010000  /* NVIDIA hardware encoder */
#define CC_PLATFORM_HAS_NVDEC     0x00020000  /* NVIDIA hardware decoder */
#define CC_PLATFORM_HAS_AMF       0x00040000  /* AMD Advanced Media Framework */
#define CC_PLATFORM_HAS_QSV       0x00080000  /* Intel Quick Sync Video */
#define CC_PLATFORM_HAS_VPU       0x00100000  /* Intel VPU / NPU */

/* NVMe / storage ── */
#define CC_PLATFORM_HAS_NVME      0x00200000  /* NVMe storage detected */
#define CC_PLATFORM_HAS_NVME_CMB  0x00400000  /* NVMe Controller Memory Buffer */
#define CC_PLATFORM_HAS_NVME_ZNS  0x00800000  /* NVMe Zoned Namespaces */
#define CC_PLATFORM_HAS_NVME_KV   0x01000000  /* NVMe Key-Value commands */
#define CC_PLATFORM_HAS_NVME_CS   0x02000000  /* NVMe Computational Storage */
#define CC_PLATFORM_HAS_NVME_CMR  0x04000000  /* NVMe Copy / Move / Remap */

/* ---- Device info ---- */

typedef struct {
    cc_compute_backend backend;
    char               name[128];
    uint64_t           memory;          /* device memory in bytes */
    uint32_t           compute_units;
    uint32_t           max_workgroup;
    uint32_t           platform_caps;   /* CC_PLATFORM_HAS_* flags */
} cc_device_info;

/* ── NVMe storage tier ──────────────────────────────────────────
 *
 * When NVMe devices are present, cutecontainer can:
 *   - Bypass the filesystem for large containers (direct I/O)
 *   - Use NVMe CMB (Controller Memory Buffer) for zero-copy
 *     GPU↔storage transfers (GPUDirect Storage / Metal IOSurface)
 *   - Use NVMe Computational Storage (CS) to offload compression
 *     and hashing to the storage controller itself
 *   - Use NVMe Zoned Namespaces (ZNS) for append-optimized
 *     ledger/WAL writes (depo module)
 *   - Use NVMe Key-Value (KV) commands for container registry
 *     (content-addressable by SHA3 hash)
 * ────────────────────────────────────────────────────────────── */

typedef struct {
    char        model[64];
    char        serial[32];
    char        firmware[16];
    uint64_t    capacity;           /* bytes */
    uint64_t    unwritten;          /* free space */
    uint32_t    max_transfer;       /* max transfer size in bytes */
    uint32_t    queue_depth;        /* max outstanding commands */
    uint32_t    caps;               /* CC_PLATFORM_HAS_NVME_* subset */
    uint16_t    pci_vid;            /* PCI vendor ID */
    uint16_t    pci_did;            /* PCI device ID */
} cc_nvme_info;

/* Probe NVMe devices on the system.
 * Returns count of NVMe devices found. */
int cc_nvme_probe(cc_nvme_info *out, int max_devices);

/* ── NVMe direct I/O (bypass filesystem for large containers) ── */

typedef struct cc_nvme_handle cc_nvme_handle;

/* Open an NVMe namespace for direct I/O. */
cc_nvme_handle *cc_nvme_open(int device_index);

/* Read directly from NVMe (aligned, no filesystem overhead). */
int cc_nvme_read(cc_nvme_handle *h, uint64_t offset, void *buf, size_t len);

/* Write directly to NVMe. */
int cc_nvme_write(cc_nvme_handle *h, uint64_t offset, const void *buf, size_t len);

/* Flush (ensure persistence). */
int cc_nvme_flush(cc_nvme_handle *h);

void cc_nvme_close(cc_nvme_handle *h);

/* ── NVMe Computational Storage ──
 *
 * If the NVMe controller supports CS (Computational Storage),
 * offload compression and hashing to the drive itself.
 * Data never crosses the PCIe bus — processed in-place on the SSD. */

/* Compress a region on-device (NVMe CS). Returns compressed size. */
int64_t cc_nvme_compress(cc_nvme_handle *h, uint64_t src_offset, size_t src_len,
                         uint64_t dst_offset);

/* Hash a region on-device (NVMe CS). Writes 32 bytes to hash_out. */
int cc_nvme_hash(cc_nvme_handle *h, uint64_t offset, size_t len,
                 uint8_t hash_out[32]);

/* ── NVMe Key-Value store ──
 *
 * Content-addressable container store using NVMe KV commands.
 * Key = SHA3-256 hash of container. Value = container bytes.
 * Enables deduplication and instant lookup by content hash. */

int cc_nvme_kv_put(cc_nvme_handle *h, const uint8_t key[32],
                   const void *value, size_t len);
int cc_nvme_kv_get(cc_nvme_handle *h, const uint8_t key[32],
                   void *value, size_t cap, size_t *out_len);
int cc_nvme_kv_exists(cc_nvme_handle *h, const uint8_t key[32]);
int cc_nvme_kv_delete(cc_nvme_handle *h, const uint8_t key[32]);

/* ---- Compute context ---- */

typedef struct cc_compute_ctx cc_compute_ctx;

/* Probe available backends and return capability flags. */
uint32_t cc_compute_probe(void);

/* Get info about the best available device. */
int cc_compute_device_info(cc_device_info *info);

/* Create a compute context with the best available backend.
 * Falls back: Metal → OpenCL → CPU. */
cc_compute_ctx *cc_compute_create(void);

/* Create with a specific backend (returns NULL if unavailable). */
cc_compute_ctx *cc_compute_create_with(cc_compute_backend backend);

/* Which backend is this context using? */
cc_compute_backend cc_compute_get_backend(const cc_compute_ctx *ctx);

/* ---- Buffers ---- */

typedef struct cc_compute_buf cc_compute_buf;

cc_compute_buf *cc_compute_buf_create(cc_compute_ctx *ctx, size_t size);
cc_compute_buf *cc_compute_buf_create_from(cc_compute_ctx *ctx, const void *data, size_t size);
int             cc_compute_buf_upload(cc_compute_buf *buf, const void *data, size_t size);
int             cc_compute_buf_download(cc_compute_buf *buf, void *data, size_t size);
void            cc_compute_buf_destroy(cc_compute_buf *buf);

/* ---- Kernel dispatch ---- */

typedef struct cc_compute_kernel cc_compute_kernel;

/* Compile a kernel from source. Language is inferred from backend:
 * Metal → MSL, OpenCL → OpenCL C. source_name = entry point function name. */
cc_compute_kernel *cc_compute_kernel_compile(cc_compute_ctx *ctx,
                                              const char *source,
                                              const char *entry_point);

/* Set kernel arguments. */
int cc_compute_kernel_set_buf(cc_compute_kernel *k, int index, cc_compute_buf *buf);
int cc_compute_kernel_set_bytes(cc_compute_kernel *k, int index, const void *data, size_t size);

/* Dispatch 1D grid. */
int cc_compute_dispatch(cc_compute_kernel *k, uint32_t count);

/* Dispatch 2D grid. */
int cc_compute_dispatch_2d(cc_compute_kernel *k, uint32_t width, uint32_t height);

/* Wait for all dispatched work to complete. */
int cc_compute_finish(cc_compute_ctx *ctx);

void cc_compute_kernel_destroy(cc_compute_kernel *k);
void cc_compute_destroy(cc_compute_ctx *ctx);

/* ---- Convenience: run a built-in kernel by name ---- */

/* Pre-registered kernels (compiled on first use):
 *   "spectral_to_rgba"   — CIE 1931 spectral integration
 *   "film_develop"       — fused fold + film curve + spectral→RGB
 */
int cc_compute_run_builtin(cc_compute_ctx *ctx, const char *kernel_name,
                           cc_compute_buf **bufs, int buf_count,
                           const void *params, size_t params_size,
                           uint32_t count);

#ifdef __cplusplus
}
#endif

#endif /* CUTECONTAINER_COMPUTE_H */
