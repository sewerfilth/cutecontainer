/*
 * test_wal.c — WAL rail roundtrip, chain integrity, collection queries
 */

#include "cutecontainer/wal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_roundtrip(void)
{
    printf("  roundtrip ... ");

    cc_wal *w = cc_wal_create();
    if (!w) { printf("FAIL (create)\n"); return 1; }

    uint8_t hash[32] = {0};
    memset(hash, 0xAB, 32);
    cc_wal_log_created(w, CC_TYPE_FILM, CC_LAYER_COMPRESSED, 1000000, 120000, hash);
    cc_wal_log_wrapped(w, 3);

    if (cc_wal_count(w) != 2) { printf("FAIL (count)\n"); cc_wal_destroy(w); return 1; }

    /* serialize */
    uint8_t *buf = NULL;
    size_t len = 0;
    if (cc_wal_serialize(w, &buf, &len) != 0) { printf("FAIL (serialize)\n"); cc_wal_destroy(w); return 1; }
    cc_wal_destroy(w);

    /* deserialize */
    cc_wal *w2 = cc_wal_open(buf, len);
    free(buf);
    if (!w2) { printf("FAIL (open)\n"); return 1; }

    if (cc_wal_count(w2) != 2) { printf("FAIL (rt count)\n"); cc_wal_destroy(w2); return 1; }
    if (cc_wal_content_type(w2) != CC_TYPE_FILM) { printf("FAIL (type)\n"); cc_wal_destroy(w2); return 1; }
    if (cc_wal_original_size(w2) != 1000000) { printf("FAIL (orig_size)\n"); cc_wal_destroy(w2); return 1; }
    if (cc_wal_stored_size(w2) != 120000) { printf("FAIL (stored_size)\n"); cc_wal_destroy(w2); return 1; }
    if (cc_wal_wrap_count(w2) != 3) { printf("FAIL (wrap_count)\n"); cc_wal_destroy(w2); return 1; }

    cc_wal_destroy(w2);
    printf("OK (%zu bytes WAL for 2 entries)\n", len);
    return 0;
}

static int test_chain_integrity(void)
{
    printf("  chain integrity ... ");

    cc_wal *w = cc_wal_create();
    uint8_t hash[32] = {0};
    cc_wal_log_created(w, CC_TYPE_RAW, 0, 500, 500, hash);
    cc_wal_log_wrapped(w, 1);
    cc_wal_log_wrapped(w, 2);

    if (cc_wal_verify_chain(w) != 0) { printf("FAIL (valid chain)\n"); cc_wal_destroy(w); return 1; }

    /* tamper with an entry */
    cc_wal_entry *e = (cc_wal_entry *)cc_wal_get(w, 1);
    e->timestamp ^= 0xFF; /* corrupt */

    if (cc_wal_verify_chain(w) == 0) { printf("FAIL (should detect tamper)\n"); cc_wal_destroy(w); return 1; }

    cc_wal_destroy(w);
    printf("OK\n");
    return 0;
}

static int test_collection(void)
{
    printf("  collection queries ... ");

    cc_wal *w = cc_wal_create();
    uint8_t hash[32] = {0};
    uint8_t coll_a[16] = {1};
    uint8_t coll_b[16] = {2};

    cc_wal_log_created(w, CC_TYPE_FILM, 0, 100, 100, hash);
    cc_wal_log_collection(w, coll_a, 0);

    cc_wal_log_created(w, CC_TYPE_FILM, 0, 200, 200, hash);
    cc_wal_log_collection(w, coll_a, 1);

    cc_wal_log_created(w, CC_TYPE_PRESS, 0, 300, 300, hash);
    cc_wal_log_collection(w, coll_b, 0);

    uint32_t found[8];
    int n = cc_wal_find_collection(w, coll_a, found, 8);
    if (n != 2) { printf("FAIL (found %d, expected 2)\n", n); cc_wal_destroy(w); return 1; }

    n = cc_wal_find_collection(w, coll_b, found, 8);
    if (n != 1) { printf("FAIL (found %d, expected 1)\n", n); cc_wal_destroy(w); return 1; }

    cc_wal_destroy(w);
    printf("OK\n");
    return 0;
}

static int test_fast_queries(void)
{
    printf("  fast queries (no decrypt) ... ");

    cc_wal *w = cc_wal_create();
    uint8_t hash[32];
    memset(hash, 0xCD, 32);
    cc_wal_log_created(w, CC_TYPE_FILM, CC_LAYER_COMPRESSED | CC_LAYER_ENCRYPTED,
                       4096000, 512000, hash);
    cc_wal_log_wrapped(w, 5);

    /* all these are O(1) reads from the summary — no payload access */
    if (cc_wal_content_type(w) != CC_TYPE_FILM) { printf("FAIL\n"); cc_wal_destroy(w); return 1; }
    if (cc_wal_layer_flags(w) != (CC_LAYER_COMPRESSED | CC_LAYER_ENCRYPTED)) { printf("FAIL\n"); cc_wal_destroy(w); return 1; }
    if (cc_wal_original_size(w) != 4096000) { printf("FAIL\n"); cc_wal_destroy(w); return 1; }
    if (cc_wal_stored_size(w) != 512000) { printf("FAIL\n"); cc_wal_destroy(w); return 1; }
    if (cc_wal_wrap_count(w) != 5) { printf("FAIL\n"); cc_wal_destroy(w); return 1; }
    if (cc_wal_created_at(w) == 0) { printf("FAIL (no timestamp)\n"); cc_wal_destroy(w); return 1; }

    cc_wal_destroy(w);
    printf("OK\n");
    return 0;
}

int main(void)
{
    int fails = 0;
    printf("WAL tests:\n");
    fails += test_roundtrip();
    fails += test_chain_integrity();
    fails += test_collection();
    fails += test_fast_queries();
    printf("\n%s (%d failures)\n", fails ? "FAIL" : "ALL PASSED", fails);
    return fails ? 1 : 0;
}
