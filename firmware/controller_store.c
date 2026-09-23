#include "controller_store.h"

#include <string.h>

_Static_assert(sizeof(controller_slot_t) == 33u, "controller slot layout changed");

static bool role_valid(uint8_t role) {
    return role == CONTROLLER_ROLE_NONE || role == CONTROLLER_ROLE_OPERATOR ||
           role == CONTROLLER_ROLE_ADMIN || role == CONTROLLER_ROLE_RECOVERY_ADMIN;
}

static bool key_is_zero(const uint8_t key[CONTROLLER_STORE_KEY_LEN]) {
    uint8_t value = 0;
    for (size_t i = 0; i < CONTROLLER_STORE_KEY_LEN; ++i) value |= key[i];
    return value == 0;
}

static bool ct_equal(const uint8_t *left, const uint8_t *right, size_t len) {
    volatile uint8_t different = 0;
    for (size_t i = 0; i < len; ++i) different |= left[i] ^ right[i];
    return different == 0;
}

static uint32_t crc32(const uint8_t *data, size_t len) {
    uint32_t crc = 0xffffffffu;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (unsigned bit = 0; bit < 8u; ++bit) {
            uint32_t mask = -(crc & 1u);
            crc = (crc >> 1u) ^ (0xedb88320u & mask);
        }
    }
    return ~crc;
}

void controller_store_empty(controller_store_t *store) {
    if (store) memset(store, 0, sizeof(*store));
}

static bool record_valid(const uint8_t *data, size_t len, controller_store_t *out) {
    if (!data || len < sizeof(controller_store_record_t)) return false;
    controller_store_record_t record;
    memcpy(&record, data, sizeof(record));
    if (record.magic != CONTROLLER_STORE_MAGIC || record.schema != CONTROLLER_STORE_SCHEMA ||
        record.reserved != 0u || record.commit != CONTROLLER_STORE_COMMIT ||
        record.crc32 != crc32((const uint8_t *)&record, offsetof(controller_store_record_t, crc32))) return false;
    unsigned recovery_count = 0;
    for (size_t i = 0; i < CONTROLLER_STORE_SLOT_COUNT; ++i) {
        if (!role_valid(record.slots[i].role)) return false;
        if (record.slots[i].role == CONTROLLER_ROLE_NONE) {
            if (!key_is_zero(record.slots[i].public_key)) return false;
        } else if (key_is_zero(record.slots[i].public_key)) {
            return false;
        }
        if (record.slots[i].role == CONTROLLER_ROLE_RECOVERY_ADMIN) ++recovery_count;
        for (size_t j = 0; j < i; ++j) {
            if (record.slots[i].role != CONTROLLER_ROLE_NONE &&
                record.slots[j].role != CONTROLLER_ROLE_NONE &&
                ct_equal(record.slots[i].public_key, record.slots[j].public_key, CONTROLLER_STORE_KEY_LEN)) return false;
        }
    }
    if (record.slots[0].role != CONTROLLER_ROLE_RECOVERY_ADMIN || recovery_count != 1u) return false;
    if (out) {
        out->generation = record.generation;
        memcpy(out->slots, record.slots, sizeof(out->slots));
    }
    return true;
}

controller_store_status_t controller_store_boot(controller_store_t *out,
                                                 const uint8_t *sector_a, size_t sector_a_len,
                                                 const uint8_t *sector_b, size_t sector_b_len) {
    if (!out) return CONTROLLER_STORE_ERR_ARGUMENT;
    controller_store_t a, b;
    bool a_ok = record_valid(sector_a, sector_a_len, &a);
    bool b_ok = record_valid(sector_b, sector_b_len, &b);
    if (!a_ok && !b_ok) {
        controller_store_empty(out);
        return CONTROLLER_STORE_ERR_FORMAT;
    }
    *out = (!b_ok || (a_ok && a.generation >= b.generation)) ? a : b;
    return CONTROLLER_STORE_OK;
}

controller_store_status_t controller_store_initialise(controller_store_t *store,
                                                       const uint8_t recovery_public_key[CONTROLLER_STORE_KEY_LEN]) {
    if (!store || !recovery_public_key || key_is_zero(recovery_public_key)) return CONTROLLER_STORE_ERR_ARGUMENT;
    controller_store_empty(store);
    store->generation = 1u;
    store->slots[0].role = CONTROLLER_ROLE_RECOVERY_ADMIN;
    memcpy(store->slots[0].public_key, recovery_public_key, CONTROLLER_STORE_KEY_LEN);
    return CONTROLLER_STORE_OK;
}

controller_store_status_t controller_store_encode(const controller_store_t *store,
                                                  uint8_t *out, size_t out_len) {
    if (!store || !out || out_len < sizeof(controller_store_record_t)) return CONTROLLER_STORE_ERR_ARGUMENT;
    controller_store_record_t record;
    memset(&record, 0xff, sizeof(record));
    record.magic = CONTROLLER_STORE_MAGIC;
    record.schema = CONTROLLER_STORE_SCHEMA;
    record.reserved = 0u;
    record.generation = store->generation;
    memcpy(record.slots, store->slots, sizeof(record.slots));
    record.crc32 = crc32((const uint8_t *)&record, offsetof(controller_store_record_t, crc32));
    record.commit = CONTROLLER_STORE_COMMIT;
    memset(out, 0xff, out_len);
    memcpy(out, &record, sizeof(record));
    return CONTROLLER_STORE_OK;
}

controller_store_status_t controller_store_find(const controller_store_t *store,
                                                const uint8_t public_key[CONTROLLER_STORE_KEY_LEN],
                                                size_t *slot_out, controller_role_t *role_out) {
    if (!store || !public_key) return CONTROLLER_STORE_ERR_ARGUMENT;
    for (size_t i = 0; i < CONTROLLER_STORE_SLOT_COUNT; ++i) {
        if (store->slots[i].role != CONTROLLER_ROLE_NONE &&
            ct_equal(store->slots[i].public_key, public_key, CONTROLLER_STORE_KEY_LEN)) {
            if (slot_out) *slot_out = i;
            if (role_out) *role_out = (controller_role_t)store->slots[i].role;
            return CONTROLLER_STORE_OK;
        }
    }
    return CONTROLLER_STORE_ERR_NOT_FOUND;
}

bool controller_store_is_admin(const controller_store_t *store, size_t slot) {
    return store && slot < CONTROLLER_STORE_SLOT_COUNT &&
           (store->slots[slot].role == CONTROLLER_ROLE_ADMIN ||
            store->slots[slot].role == CONTROLLER_ROLE_RECOVERY_ADMIN);
}

controller_store_status_t controller_store_add(controller_store_t *store, size_t caller_slot,
                                               const uint8_t public_key[CONTROLLER_STORE_KEY_LEN],
                                               controller_role_t role, size_t *slot_out) {
    if (!store || !public_key || key_is_zero(public_key) ||
        (role != CONTROLLER_ROLE_OPERATOR && role != CONTROLLER_ROLE_ADMIN)) return CONTROLLER_STORE_ERR_ARGUMENT;
    if (!controller_store_is_admin(store, caller_slot)) return CONTROLLER_STORE_ERR_ROLE;
    if (controller_store_find(store, public_key, NULL, NULL) == CONTROLLER_STORE_OK) return CONTROLLER_STORE_ERR_DUPLICATE;
    for (size_t i = 1; i < CONTROLLER_STORE_SLOT_COUNT; ++i) {
        if (store->slots[i].role == CONTROLLER_ROLE_NONE) {
            store->slots[i].role = (uint8_t)role;
            memcpy(store->slots[i].public_key, public_key, CONTROLLER_STORE_KEY_LEN);
            ++store->generation;
            if (slot_out) *slot_out = i;
            return CONTROLLER_STORE_OK;
        }
    }
    return CONTROLLER_STORE_ERR_FULL;
}

controller_store_status_t controller_store_revoke(controller_store_t *store, size_t caller_slot,
                                                  size_t target_slot) {
    if (!store || caller_slot >= CONTROLLER_STORE_SLOT_COUNT || target_slot >= CONTROLLER_STORE_SLOT_COUNT) return CONTROLLER_STORE_ERR_ARGUMENT;
    if (!controller_store_is_admin(store, caller_slot)) return CONTROLLER_STORE_ERR_ROLE;
    if (target_slot == 0u) return CONTROLLER_STORE_ERR_IMMUTABLE;
    if (store->slots[target_slot].role == CONTROLLER_ROLE_NONE) return CONTROLLER_STORE_ERR_NOT_FOUND;
    memset(&store->slots[target_slot], 0, sizeof(store->slots[target_slot]));
    ++store->generation;
    return CONTROLLER_STORE_OK;
}
