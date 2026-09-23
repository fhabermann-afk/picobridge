#ifndef CONTROLLER_STORE_H
#define CONTROLLER_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CONTROLLER_STORE_SLOT_COUNT 5u
#define CONTROLLER_STORE_KEY_LEN 32u
#define CONTROLLER_STORE_SCHEMA 1u
#define CONTROLLER_STORE_MAGIC 0x50424353u /* "PBCS" */
#define CONTROLLER_STORE_COMMIT 0x43534d54u /* "CSMT" */

typedef enum {
    CONTROLLER_ROLE_NONE = 0,
    CONTROLLER_ROLE_OPERATOR = 1,
    CONTROLLER_ROLE_ADMIN = 2,
    CONTROLLER_ROLE_RECOVERY_ADMIN = 3,
} controller_role_t;

typedef struct {
    uint8_t role;
    uint8_t public_key[CONTROLLER_STORE_KEY_LEN];
} controller_slot_t;

typedef struct {
    uint32_t generation;
    controller_slot_t slots[CONTROLLER_STORE_SLOT_COUNT];
} controller_store_t;

typedef enum {
    CONTROLLER_STORE_OK = 0,
    CONTROLLER_STORE_ERR_ARGUMENT,
    CONTROLLER_STORE_ERR_FORMAT,
    CONTROLLER_STORE_ERR_FULL,
    CONTROLLER_STORE_ERR_DUPLICATE,
    CONTROLLER_STORE_ERR_ROLE,
    CONTROLLER_STORE_ERR_IMMUTABLE,
    CONTROLLER_STORE_ERR_NOT_FOUND,
} controller_store_status_t;

/* On-flash record, deliberately fixed-width and page-padding independent. */
typedef struct {
    uint32_t magic;
    uint16_t schema;
    uint16_t reserved;
    uint32_t generation;
    controller_slot_t slots[CONTROLLER_STORE_SLOT_COUNT];
    uint32_t crc32;
    uint32_t commit;
} controller_store_record_t;

void controller_store_empty(controller_store_t *store);
controller_store_status_t controller_store_boot(controller_store_t *out,
                                                 const uint8_t *sector_a, size_t sector_a_len,
                                                 const uint8_t *sector_b, size_t sector_b_len);
controller_store_status_t controller_store_initialise(controller_store_t *store,
                                                       const uint8_t recovery_public_key[CONTROLLER_STORE_KEY_LEN]);
controller_store_status_t controller_store_encode(const controller_store_t *store,
                                                  uint8_t *out, size_t out_len);
controller_store_status_t controller_store_find(const controller_store_t *store,
                                                const uint8_t public_key[CONTROLLER_STORE_KEY_LEN],
                                                size_t *slot_out, controller_role_t *role_out);
controller_store_status_t controller_store_add(controller_store_t *store, size_t caller_slot,
                                               const uint8_t public_key[CONTROLLER_STORE_KEY_LEN],
                                               controller_role_t role, size_t *slot_out);
controller_store_status_t controller_store_revoke(controller_store_t *store, size_t caller_slot,
                                                  size_t target_slot);
bool controller_store_is_admin(const controller_store_t *store, size_t slot);

#endif
