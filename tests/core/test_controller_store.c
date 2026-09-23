#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "controller_store.h"

static unsigned failures;

#define CHECK(condition) do { if (!(condition)) { \
    printf("FAIL %s:%d: %s\n", __func__, __LINE__, #condition); ++failures; return; \
} } while (0)

static void key(uint8_t out[CONTROLLER_STORE_KEY_LEN], uint8_t tag) {
    memset(out, tag, CONTROLLER_STORE_KEY_LEN);
    out[0] = tag;
}

static void encode(const controller_store_t *store, uint8_t sector[4096]) {
    memset(sector, 0xff, 4096);
    CHECK(controller_store_encode(store, sector, 4096) == CONTROLLER_STORE_OK);
}

static void test_recovery_initialization_and_roundtrip(void) {
    uint8_t recovery[32], sector[4096];
    controller_store_t source, loaded;
    key(recovery, 1);
    CHECK(controller_store_initialise(&source, recovery) == CONTROLLER_STORE_OK);
    CHECK(source.generation == 1);
    CHECK(source.slots[0].role == CONTROLLER_ROLE_RECOVERY_ADMIN);
    encode(&source, sector);
    CHECK(controller_store_boot(&loaded, sector, sizeof(sector), NULL, 0) == CONTROLLER_STORE_OK);
    CHECK(loaded.generation == 1);
    CHECK(loaded.slots[0].role == CONTROLLER_ROLE_RECOVERY_ADMIN);
    CHECK(memcmp(loaded.slots[0].public_key, recovery, 32) == 0);
}

static void test_torn_or_corrupt_newer_snapshot_falls_back(void) {
    uint8_t recovery[32], a[4096], b[4096], candidate[32];
    controller_store_t old, newer, loaded;
    key(recovery, 1); key(candidate, 2);
    CHECK(controller_store_initialise(&old, recovery) == CONTROLLER_STORE_OK);
    encode(&old, a);
    newer = old;
    CHECK(controller_store_add(&newer, 0, candidate, CONTROLLER_ROLE_OPERATOR, NULL) == CONTROLLER_STORE_OK);
    encode(&newer, b);
    b[sizeof(controller_store_record_t) - 1] ^= 1u; /* corrupt commit marker */
    CHECK(controller_store_boot(&loaded, a, sizeof(a), b, sizeof(b)) == CONTROLLER_STORE_OK);
    CHECK(loaded.generation == old.generation);
    CHECK(controller_store_find(&loaded, candidate, NULL, NULL) == CONTROLLER_STORE_ERR_NOT_FOUND);
}

static void test_highest_complete_generation_wins(void) {
    uint8_t recovery[32], operator_key[32], a[4096], b[4096];
    controller_store_t old, newer, loaded;
    key(recovery, 1); key(operator_key, 3);
    CHECK(controller_store_initialise(&old, recovery) == CONTROLLER_STORE_OK);
    encode(&old, a);
    newer = old;
    CHECK(controller_store_add(&newer, 0, operator_key, CONTROLLER_ROLE_OPERATOR, NULL) == CONTROLLER_STORE_OK);
    encode(&newer, b);
    CHECK(controller_store_boot(&loaded, a, sizeof(a), b, sizeof(b)) == CONTROLLER_STORE_OK);
    CHECK(loaded.generation == newer.generation);
    CHECK(controller_store_find(&loaded, operator_key, NULL, NULL) == CONTROLLER_STORE_OK);
}

static void test_three_controllers_and_role_boundaries(void) {
    uint8_t recovery[32], k1[32], k2[32], k3[32], k4[32];
    controller_store_t store;
    size_t first_operator;
    key(recovery, 1); key(k1, 2); key(k2, 3); key(k3, 4); key(k4, 5);
    CHECK(controller_store_initialise(&store, recovery) == CONTROLLER_STORE_OK);
    CHECK(controller_store_add(&store, 0, k1, CONTROLLER_ROLE_OPERATOR, &first_operator) == CONTROLLER_STORE_OK);
    CHECK(controller_store_add(&store, 0, k2, CONTROLLER_ROLE_OPERATOR, NULL) == CONTROLLER_STORE_OK);
    CHECK(controller_store_add(&store, 0, k3, CONTROLLER_ROLE_ADMIN, NULL) == CONTROLLER_STORE_OK);
    CHECK(controller_store_add(&store, first_operator, k4, CONTROLLER_ROLE_OPERATOR, NULL) == CONTROLLER_STORE_ERR_ROLE);
    CHECK(controller_store_find(&store, k1, NULL, NULL) == CONTROLLER_STORE_OK);
    CHECK(controller_store_find(&store, k2, NULL, NULL) == CONTROLLER_STORE_OK);
    CHECK(controller_store_find(&store, k3, NULL, NULL) == CONTROLLER_STORE_OK);
}

static void test_recovery_immutable_and_revocation(void) {
    uint8_t recovery[32], operator_key[32];
    controller_store_t store;
    size_t operator_slot;
    key(recovery, 1); key(operator_key, 2);
    CHECK(controller_store_initialise(&store, recovery) == CONTROLLER_STORE_OK);
    CHECK(controller_store_add(&store, 0, operator_key, CONTROLLER_ROLE_OPERATOR, &operator_slot) == CONTROLLER_STORE_OK);
    CHECK(controller_store_revoke(&store, 0, 0) == CONTROLLER_STORE_ERR_IMMUTABLE);
    CHECK(controller_store_revoke(&store, operator_slot, 0) == CONTROLLER_STORE_ERR_ROLE);
    CHECK(controller_store_revoke(&store, 0, operator_slot) == CONTROLLER_STORE_OK);
    CHECK(controller_store_find(&store, operator_key, NULL, NULL) == CONTROLLER_STORE_ERR_NOT_FOUND);
}

static void test_rejects_duplicate_and_invalid_record(void) {
    uint8_t recovery[32], sector[4096];
    controller_store_t store, loaded;
    key(recovery, 7);
    CHECK(controller_store_initialise(&store, recovery) == CONTROLLER_STORE_OK);
    CHECK(controller_store_add(&store, 0, recovery, CONTROLLER_ROLE_OPERATOR, NULL) == CONTROLLER_STORE_ERR_DUPLICATE);
    encode(&store, sector);
    sector[20] ^= 1u; /* content changed without CRC update */
    CHECK(controller_store_boot(&loaded, sector, sizeof(sector), NULL, 0) == CONTROLLER_STORE_ERR_FORMAT);
}

int main(void) {
    test_recovery_initialization_and_roundtrip();
    test_torn_or_corrupt_newer_snapshot_falls_back();
    test_highest_complete_generation_wins();
    test_three_controllers_and_role_boundaries();
    test_recovery_immutable_and_revocation();
    test_rejects_duplicate_and_invalid_record();
    if (failures) return 1;
    puts("6 controller-store tests, 0 failures");
    return 0;
}
