/*
 * cutecontainer Switch homebrew demo
 *
 * Demonstrates press (compression) and crypt (encryption) on Nintendo Switch.
 */
#include <switch.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <cutecontainer/press.h>
#include <cutecontainer/crypt.h>

static void demo_compress(void) {
    const char *input = "The quick brown fox jumps over the lazy dog. "
                        "The quick brown fox jumps over the lazy dog. "
                        "The quick brown fox jumps over the lazy dog. ";
    size_t in_len = strlen(input);

    uint8_t compressed[512];
    int64_t comp_len = cp_compress((const uint8_t *)input, in_len,
                                   compressed, sizeof(compressed), 1);

    printf("  input:      %zu bytes\n", in_len);
    if (comp_len > 0) {
        printf("  compressed: %lld bytes (%.0f%%)\n", (long long)comp_len,
               100.0 * comp_len / in_len);
        printf("  result:     OK\n");

        uint8_t decompressed[512];
        int64_t dec_len = cp_decompress(compressed, (size_t)comp_len,
                                        decompressed, sizeof(decompressed));
        printf("  roundtrip:  %s\n\n",
               dec_len == (int64_t)in_len && memcmp(decompressed, input, in_len) == 0
                   ? "OK" : "FAIL");
    } else {
        printf("  result:     FAIL (%lld)\n\n", (long long)comp_len);
    }
}

static void demo_hash(void) {
    const char *data = "Hello from Nintendo Switch!";
    uint8_t hash[32];
    cc_sha3_256((const uint8_t *)data, strlen(data), hash);

    printf("  input: %s\n", data);
    printf("  SHA3:  ");
    for (int i = 0; i < 16; i++) printf("%02x", hash[i]);
    printf("...\n\n");
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;

    consoleInit(NULL);

    printf("=== cutecontainer demo ===\n\n");

    printf("[compression]\n");
    demo_compress();

    printf("[SHA3-256 hash]\n");
    demo_hash();

    printf("Press + to exit.\n");

    padConfigureInput(1, HidNpadStyleSet_NpadStandard);
    PadState pad;
    padInitializeDefault(&pad);

    while (appletMainLoop()) {
        padUpdate(&pad);
        if (padGetButtonsDown(&pad) & HidNpadButton_Plus)
            break;
        consoleUpdate(NULL);
    }

    consoleExit(NULL);
    return 0;
}
