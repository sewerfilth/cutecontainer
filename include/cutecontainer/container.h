/*
 * container.h — unified .cute container format
 *
 * Shared envelope for all modules. Type-tagged payloads with
 * stackable compression (press) and encryption (crypt) layers.
 */

#ifndef CUTECONTAINER_CONTAINER_H
#define CUTECONTAINER_CONTAINER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CC_MAGIC             "CUTE"
#define CC_CONTAINER_VERSION 0x05
#define CC_HEADER_SIZE       64

typedef enum {
    CC_TYPE_UNKNOWN = 0x00,
    CC_TYPE_RAW     = 0x01,
    CC_TYPE_PRESS   = 0x02,
    CC_TYPE_CRYPT   = 0x03,
    CC_TYPE_FILM    = 0x04,
    CC_TYPE_DEPO    = 0x05,
} cc_content_type;

#define CC_LAYER_NONE        0x0000
#define CC_LAYER_COMPRESSED  0x0001
#define CC_LAYER_ENCRYPTED   0x0002

#define CC_OK               0
#define CC_ERR_IO           (-1)
#define CC_ERR_FORMAT       (-2)
#define CC_ERR_VERSION      (-3)
#define CC_ERR_NOMEM        (-4)

typedef struct cc_container cc_container;

cc_container   *cc_container_create(cc_content_type type);
cc_container   *cc_container_open(const uint8_t *data, size_t data_len);
cc_container   *cc_container_open_file(const char *path);

void            cc_container_set_meta(cc_container *c, const void *meta, size_t meta_size);
void            cc_container_set_payload(cc_container *c, const void *data, size_t size);
void            cc_container_set_layers(cc_container *c, uint16_t layer_flags);
void            cc_container_set_encrypt_key(cc_container *c, const uint8_t pk[1184]);
void            cc_container_set_decrypt_key(cc_container *c, const uint8_t sk[2400]);

int             cc_container_write(cc_container *c, uint8_t **out, size_t *out_len);
int             cc_container_write_file(cc_container *c, const char *path);

cc_content_type cc_container_type(const cc_container *c);
const void     *cc_container_meta(const cc_container *c, size_t *meta_size);
const void     *cc_container_payload(const cc_container *c, size_t *payload_size);
uint16_t        cc_container_layers(const cc_container *c);
uint64_t        cc_container_original_size(const cc_container *c);

cc_content_type cc_container_detect(const uint8_t *data, size_t data_len);
const char     *cc_content_type_name(cc_content_type type);
void            cc_container_destroy(cc_container *c);

#ifdef __cplusplus
}
#endif

#endif /* CUTECONTAINER_CONTAINER_H */
