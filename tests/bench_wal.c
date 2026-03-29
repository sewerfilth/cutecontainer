/*
 * bench_wal.c — WAL rail speed benchmark
 *
 * Measures: append throughput, serialize/deserialize, fast query,
 * chain verify, collection scan, and comparison vs full container open.
 */

#include "cutecontainer/wal.h"
#include "cutecontainer/container.h"
#include "cutecontainer/press.h"
#include "cutecontainer/crypt/sha3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __APPLE__
#include <mach/mach_time.h>
static double ns_per_tick(void) {
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    return (double)tb.numer / (double)tb.denom;
}
static uint64_t tick(void) { return mach_absolute_time(); }
#elif defined(_WIN32)
#include <windows.h>
static double ns_per_tick(void) {
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    return 1000000000.0 / (double)freq.QuadPart;
}
static uint64_t tick(void) {
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return (uint64_t)t.QuadPart;
}
#else
static double ns_per_tick(void) { return 1.0; }
static uint64_t tick(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
#endif

static double elapsed_us(uint64_t start, uint64_t end) {
    return (double)(end - start) * ns_per_tick() / 1000.0;
}

/* ──────────────────────────────────────────────────────────── */

static void bench_append(void)
{
    printf("  WAL append (10K entries) ... ");
    cc_wal *w = cc_wal_create();
    uint8_t hash[32]; memset(hash, 0xAA, 32);

    uint64_t t0 = tick();
    for (int i = 0; i < 10000; i++) {
        cc_wal_log_created(w, CC_TYPE_FILM, CC_LAYER_COMPRESSED,
                           (uint64_t)i * 1024, (uint64_t)i * 128, hash);
    }
    uint64_t t1 = tick();

    double us = elapsed_us(t0, t1);
    printf("%.1f us total, %.0f ns/entry, %.1fM entries/sec\n",
           us, us * 1000.0 / 10000.0, 10000.0 / us);
    cc_wal_destroy(w);
}

static void bench_serialize(void)
{
    printf("  WAL serialize (1K entries) ... ");
    cc_wal *w = cc_wal_create();
    uint8_t hash[32] = {0};
    for (int i = 0; i < 1000; i++)
        cc_wal_log_created(w, CC_TYPE_FILM, 0, 1000, 1000, hash);

    uint8_t *buf = NULL; size_t len = 0;

    uint64_t t0 = tick();
    for (int i = 0; i < 100; i++) {
        cc_wal_serialize(w, &buf, &len);
        free(buf); buf = NULL;
    }
    uint64_t t1 = tick();

    /* one last for deserialization benchmark */
    cc_wal_serialize(w, &buf, &len);
    cc_wal_destroy(w);

    double us = elapsed_us(t0, t1);
    printf("%.1f us/serialize, %zu bytes (%.1f KB)\n",
           us / 100.0, len, (double)len / 1024.0);

    /* deserialize */
    printf("  WAL deserialize (1K entries) ... ");
    t0 = tick();
    for (int i = 0; i < 100; i++) {
        cc_wal *w2 = cc_wal_open(buf, len);
        cc_wal_destroy(w2);
    }
    t1 = tick();
    us = elapsed_us(t0, t1);
    printf("%.1f us/deserialize\n", us / 100.0);

    free(buf);
}

static void bench_fast_query(void)
{
    printf("  WAL fast query (summary read) ... ");
    cc_wal *w = cc_wal_create();
    uint8_t hash[32] = {0};
    for (int i = 0; i < 1000; i++)
        cc_wal_log_created(w, CC_TYPE_FILM, CC_LAYER_COMPRESSED | CC_LAYER_ENCRYPTED,
                           4096000, 512000, hash);

    volatile cc_content_type t;
    volatile uint64_t sz;
    volatile uint16_t lf;

    uint64_t t0 = tick();
    for (int i = 0; i < 1000000; i++) {
        t = cc_wal_content_type(w);
        sz = cc_wal_original_size(w);
        lf = cc_wal_layer_flags(w);
    }
    uint64_t t1 = tick();
    (void)t; (void)sz; (void)lf;

    double us = elapsed_us(t0, t1);
    printf("%.1f ns/query (3 fields, 1M iterations)\n", us * 1000.0 / 1000000.0);
    cc_wal_destroy(w);
}

static void bench_chain_verify(void)
{
    printf("  WAL chain verify (1K entries) ... ");
    cc_wal *w = cc_wal_create();
    uint8_t hash[32] = {0};
    for (int i = 0; i < 1000; i++)
        cc_wal_log_created(w, CC_TYPE_RAW, 0, 1000, 1000, hash);

    uint64_t t0 = tick();
    for (int i = 0; i < 100; i++)
        cc_wal_verify_chain(w);
    uint64_t t1 = tick();

    double us = elapsed_us(t0, t1);
    printf("%.1f us/verify (100 runs, %.0f ns/entry)\n",
           us / 100.0, us * 1000.0 / 100.0 / 1000.0);
    cc_wal_destroy(w);
}

static void bench_collection_scan(void)
{
    printf("  WAL collection scan (10K entries, 100 collections) ... ");
    cc_wal *w = cc_wal_create();
    uint8_t hash[32] = {0};

    for (int i = 0; i < 10000; i++) {
        cc_wal_log_created(w, CC_TYPE_FILM, 0, 1000, 1000, hash);
        uint8_t coll[16] = {0};
        coll[0] = (uint8_t)(i % 100);
        cc_wal_log_collection(w, coll, (uint32_t)(i / 100));
    }

    uint8_t target[16] = {42};
    uint32_t found[256];

    uint64_t t0 = tick();
    for (int i = 0; i < 1000; i++)
        cc_wal_find_collection(w, target, found, 256);
    uint64_t t1 = tick();

    double us = elapsed_us(t0, t1);
    int n = cc_wal_find_collection(w, target, found, 256);
    printf("%.1f us/scan (%d matches in 20K entries)\n", us / 1000.0, n);
    cc_wal_destroy(w);
}

static void bench_vs_container_open(void)
{
    printf("\n  --- WAL vs full container open ---\n");

    /* create a compressed container with some data */
    size_t data_sz = 256 * 1024;
    uint8_t *data = malloc(data_sz);
    for (size_t i = 0; i < data_sz; i++) data[i] = (uint8_t)(i & 0x3F);

    cc_container *c = cc_container_create(CC_TYPE_FILM);
    cc_container_set_payload(c, data, data_sz);
    cc_container_set_layers(c, CC_LAYER_COMPRESSED);
    uint8_t *container_buf = NULL; size_t container_len = 0;
    cc_container_write(c, &container_buf, &container_len);
    cc_container_destroy(c);
    free(data);

    /* append a WAL trailer */
    cc_wal *w = cc_wal_create();
    uint8_t hash[32];
    cc_sha3_256(container_buf, container_len, hash);
    cc_wal_log_created(w, CC_TYPE_FILM, CC_LAYER_COMPRESSED,
                       data_sz, container_len, hash);
    cc_wal_log_wrapped(w, 2);

    uint8_t *wal_buf = NULL; size_t wal_len = 0;
    cc_wal_serialize(w, &wal_buf, &wal_len);
    cc_wal_destroy(w);

    /* create combined file: container + WAL trailer */
    size_t total = container_len + wal_len;
    uint8_t *combined = malloc(total);
    memcpy(combined, container_buf, container_len);
    memcpy(combined + container_len, wal_buf, wal_len);
    free(container_buf);
    free(wal_buf);

    /* benchmark: full container open (decompress) */
    uint64_t t0 = tick();
    for (int i = 0; i < 100; i++) {
        cc_container *c2 = cc_container_open(combined, container_len);
        cc_content_type tp = cc_container_type(c2);
        size_t ps = 0;
        cc_container_payload(c2, &ps);
        (void)tp; (void)ps;
        cc_container_destroy(c2);
    }
    uint64_t t1 = tick();
    double full_us = elapsed_us(t0, t1) / 100.0;

    /* benchmark: WAL fast read (no decompress) */
    t0 = tick();
    for (int i = 0; i < 100; i++) {
        cc_wal *w2 = cc_wal_open(combined, total);
        cc_content_type tp = cc_wal_content_type(w2);
        uint64_t orig = cc_wal_original_size(w2);
        uint16_t layers = cc_wal_layer_flags(w2);
        (void)tp; (void)orig; (void)layers;
        cc_wal_destroy(w2);
    }
    t1 = tick();
    double wal_us = elapsed_us(t0, t1) / 100.0;

    printf("  container open (256KB compressed): %.1f us\n", full_us);
    printf("  WAL fast read (no decompress):     %.1f us\n", wal_us);
    printf("  speedup:                           %.0fx faster\n", full_us / wal_us);
    printf("  container size: %.1f KB | WAL overhead: %zu bytes\n",
           (double)container_len / 1024.0, wal_len);

    free(combined);
}

int main(void)
{
    printf("WAL rail benchmarks:\n\n");
    bench_append();
    bench_serialize();
    bench_fast_query();
    bench_chain_verify();
    bench_collection_scan();
    bench_vs_container_open();
    printf("\ndone.\n");
    return 0;
}
