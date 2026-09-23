#include "controller_store_flash.h"

#include <string.h>

#include "hardware/flash.h"
#include "pico/btstack_flash_bank.h"
#include "pico/error.h"
#include "pico/flash.h"
#include "pico/platform.h"

#define CONTROLLER_STORE_SECTORS 2u
#define CONTROLLER_STORE_FLASH_BYTES (CONTROLLER_STORE_SECTORS * FLASH_SECTOR_SIZE)
#define CONTROLLER_STORE_FLASH_OFFSET (PICO_FLASH_BANK_STORAGE_OFFSET - CONTROLLER_STORE_FLASH_BYTES)
#define CONTROLLER_STORE_XIP_OFFSET (XIP_BASE + CONTROLLER_STORE_FLASH_OFFSET)

_Static_assert((CONTROLLER_STORE_FLASH_OFFSET % FLASH_SECTOR_SIZE) == 0u, "store must be sector aligned");
_Static_assert(CONTROLLER_STORE_FLASH_OFFSET + CONTROLLER_STORE_FLASH_BYTES <= PICO_FLASH_BANK_STORAGE_OFFSET,
               "controller store overlaps BTstack flash bank");
_Static_assert(PICO_FLASH_BANK_STORAGE_OFFSET + PICO_FLASH_BANK_TOTAL_SIZE <= PICO_FLASH_SIZE_BYTES,
               "BTstack flash bank exceeds device flash");

/* Keep the page buffer in SRAM.  flash_safe_execute disables IRQs and ensures
 * the inactive core cannot read XIP before invoking this operation. */
typedef struct {
    uint32_t offset;
    uint8_t sector[FLASH_SECTOR_SIZE];
} controller_store_flash_op_t;

static controller_store_flash_op_t flash_op;

static void __not_in_flash_func(program_sector)(void *arg) {
    controller_store_flash_op_t *op = (controller_store_flash_op_t *)arg;
    flash_range_erase(op->offset, FLASH_SECTOR_SIZE);
    /* Commit marker is written in a second program operation. Before that it
     * remains erased (all ones), so reset/power-loss cannot produce a valid
     * newer record. Reprogramming only changes 1 bits to 0 bits. */
    uint8_t first_page[FLASH_PAGE_SIZE];
    memcpy(first_page, op->sector, sizeof(first_page));
    size_t commit_offset = offsetof(controller_store_record_t, commit);
    memset(first_page + commit_offset, 0xff, sizeof(uint32_t));
    flash_range_program(op->offset, first_page, FLASH_PAGE_SIZE);
    for (uint32_t page = FLASH_PAGE_SIZE; page < FLASH_SECTOR_SIZE; page += FLASH_PAGE_SIZE) {
        flash_range_program(op->offset + page, op->sector + page, FLASH_PAGE_SIZE);
    }
    flash_range_program(op->offset, op->sector, FLASH_PAGE_SIZE);
    memset(first_page, 0, sizeof(first_page));
}

static const uint8_t *sector_ptr(uint32_t offset) {
    return (const uint8_t *)(uintptr_t)(XIP_BASE + offset);
}

static controller_store_status_t boot_existing(controller_store_t *store) {
    const uint8_t *a = sector_ptr(CONTROLLER_STORE_FLASH_OFFSET);
    const uint8_t *b = sector_ptr(CONTROLLER_STORE_FLASH_OFFSET + FLASH_SECTOR_SIZE);
    return controller_store_boot(store, a, FLASH_SECTOR_SIZE, b, FLASH_SECTOR_SIZE);
}

controller_store_status_t controller_store_flash_commit(const controller_store_t *store) {
    if (!store) return CONTROLLER_STORE_ERR_ARGUMENT;
    controller_store_t current;
    controller_store_status_t current_status = boot_existing(&current);
    uint32_t target = CONTROLLER_STORE_FLASH_OFFSET;
    if (current_status == CONTROLLER_STORE_OK && current.generation == store->generation) {
        return CONTROLLER_STORE_ERR_ARGUMENT;
    }
    if (current_status == CONTROLLER_STORE_OK) {
        const uint8_t *a = sector_ptr(CONTROLLER_STORE_FLASH_OFFSET);
        controller_store_t a_store;
        if (controller_store_boot(&a_store, a, FLASH_SECTOR_SIZE, NULL, 0) == CONTROLLER_STORE_OK &&
            a_store.generation == current.generation) {
            target += FLASH_SECTOR_SIZE;
        }
    }
    memset(&flash_op, 0xff, sizeof(flash_op));
    flash_op.offset = target;
    if (controller_store_encode(store, flash_op.sector, sizeof(flash_op.sector)) != CONTROLLER_STORE_OK) {
        return CONTROLLER_STORE_ERR_FORMAT;
    }
    if (flash_safe_execute(program_sector, &flash_op, 1000u) != PICO_OK) {
        memset(&flash_op, 0, sizeof(flash_op));
        return CONTROLLER_STORE_ERR_FORMAT;
    }
    memset(&flash_op, 0, sizeof(flash_op));
    controller_store_t verified;
    if (boot_existing(&verified) != CONTROLLER_STORE_OK || verified.generation != store->generation) {
        return CONTROLLER_STORE_ERR_FORMAT;
    }
    return CONTROLLER_STORE_OK;
}

static bool sectors_are_erased(void) {
    const uint8_t *a = sector_ptr(CONTROLLER_STORE_FLASH_OFFSET);
    const uint8_t *b = sector_ptr(CONTROLLER_STORE_FLASH_OFFSET + FLASH_SECTOR_SIZE);
    uint8_t changed = 0;
    for (size_t i = 0; i < FLASH_SECTOR_SIZE; ++i) changed |= (uint8_t)(a[i] ^ 0xffu) | (uint8_t)(b[i] ^ 0xffu);
    return changed == 0;
}

controller_store_status_t controller_store_flash_boot_or_seed(
    controller_store_t *store, const uint8_t recovery_public_key[CONTROLLER_STORE_KEY_LEN]) {
    if (!store || !recovery_public_key) return CONTROLLER_STORE_ERR_ARGUMENT;
    controller_store_status_t status = boot_existing(store);
    if (status == CONTROLLER_STORE_OK) return CONTROLLER_STORE_OK;
    /* Never silently replace a damaged existing trust store. Initial seeding is
     * permitted only when both dedicated sectors are physically erased. */
    if (!sectors_are_erased()) return CONTROLLER_STORE_ERR_FORMAT;
    status = controller_store_initialise(store, recovery_public_key);
    if (status != CONTROLLER_STORE_OK) return status;
    return controller_store_flash_commit(store);
}
