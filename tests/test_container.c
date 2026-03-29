/*
 * test_container.c — container format roundtrip + detection tests
 */

#include "cutecontainer/container.h"
#include "cutecontainer/press.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_roundtrip(void) {
    printf("  roundtrip (RAW) ... ");
    const char *payload = "hello from cutecontainer";
    cc_container *c = cc_container_create(CC_TYPE_RAW);
    cc_container_set_payload(c, payload, strlen(payload));
    uint8_t *buf = NULL; size_t len = 0;
    int rc = cc_container_write(c, &buf, &len);
    cc_container_destroy(c);
    if (rc != CC_OK) { printf("FAIL\n"); return 1; }
    cc_container *c2 = cc_container_open(buf, len); free(buf);
    if (!c2 || cc_container_type(c2) != CC_TYPE_RAW) { printf("FAIL\n"); return 1; }
    size_t ps; const char *p = cc_container_payload(c2, &ps);
    if (ps != strlen(payload) || memcmp(p, payload, ps)) { printf("FAIL\n"); cc_container_destroy(c2); return 1; }
    cc_container_destroy(c2);
    printf("OK\n"); return 0;
}

static int test_compressed(void) {
    printf("  roundtrip (PRESS layer) ... ");
    size_t sz = 4096; uint8_t *data = malloc(sz);
    for (size_t i = 0; i < sz; i++) data[i] = (uint8_t)(i & 0x0F);
    cc_container *c = cc_container_create(CC_TYPE_FILM);
    cc_container_set_payload(c, data, sz);
    cc_container_set_layers(c, CC_LAYER_COMPRESSED);
    uint8_t *buf = NULL; size_t len = 0;
    int rc = cc_container_write(c, &buf, &len); cc_container_destroy(c);
    if (rc != CC_OK) { free(data); printf("FAIL\n"); return 1; }
    cc_container *c2 = cc_container_open(buf, len); free(buf);
    if (!c2) { free(data); printf("FAIL\n"); return 1; }
    size_t ps; const uint8_t *p = cc_container_payload(c2, &ps);
    if (ps != sz || memcmp(p, data, sz)) { free(data); cc_container_destroy(c2); printf("FAIL\n"); return 1; }
    cc_container_destroy(c2); free(data);
    printf("OK\n"); return 0;
}

static int test_detect(void) {
    printf("  legacy detection ... ");
    uint8_t prss[] = {'P','R','S','S',0x01,0x00};
    uint8_t cute1[] = {'C','U','T','E',0x01,0x00};
    uint8_t cute4[] = {'C','U','T','E',0x04,0x00};
    uint8_t cfsp[] = {'C','F','S','P',0x01,0x00};
    if (cc_container_detect(prss,6) != CC_TYPE_PRESS) { printf("FAIL\n"); return 1; }
    if (cc_container_detect(cute1,6) != CC_TYPE_CRYPT) { printf("FAIL\n"); return 1; }
    if (cc_container_detect(cute4,6) != CC_TYPE_DEPO) { printf("FAIL\n"); return 1; }
    if (cc_container_detect(cfsp,6) != CC_TYPE_FILM) { printf("FAIL\n"); return 1; }
    printf("OK\n"); return 0;
}

int main(void) {
    int fails = 0;
    printf("cutecontainer tests:\n");
    fails += test_roundtrip();
    fails += test_compressed();
    fails += test_detect();
    printf("\n%s (%d failures)\n", fails ? "FAIL" : "ALL PASSED", fails);
    return fails ? 1 : 0;
}
