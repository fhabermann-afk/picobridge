#include "radio_provision_flash.h"

#include <string.h>

#include "hardware/flash.h"
#include "pico/error.h"
#include "pico/flash.h"
#include "pico/platform.h"

_Static_assert(RADIO_HAVE_FLASH_LAYOUT,
               "radio provisioning requires the SDK-derived flash layout");

typedef struct {
    uint32_t offset;
    uint8_t sector[RADIO_SECTOR_SIZE];
} radio_flash_op_t;

static radio_flash_op_t radio_flash_op;

static void __not_in_flash_func(radio_program_sector)(void *arg) {
    radio_flash_op_t *op = (radio_flash_op_t *)arg;
    flash_range_erase(op->offset, RADIO_SECTOR_SIZE);
    for (uint32_t page = 0; page < RADIO_SECTOR_SIZE; page += FLASH_PAGE_SIZE) {
        flash_range_program(op->offset + page, op->sector + page, FLASH_PAGE_SIZE);
    }
}

static void __not_in_flash_func(radio_erase_sector)(void *arg) {
    radio_flash_op_t *op = (radio_flash_op_t *)arg;
    flash_range_erase(op->offset, RADIO_SECTOR_SIZE);
}

bool radio_provision_flash_write_and_verify(const uint8_t sector_image[RADIO_SECTOR_SIZE]) {
    if (!sector_image) return false;
    /* Validate the payload before touching flash so a bad command cannot
     * destroy a previously working record on its way past erase. */
    struct radio_config candidate;
    if (!radio_config_parse2(sector_image, RADIO_SECTOR_SIZE, &candidate)) return false;
    memset(&radio_flash_op, 0xff, sizeof(radio_flash_op));
    radio_flash_op.offset = RADIO_PROVISION_OFFSET;
    memcpy(radio_flash_op.sector, sector_image, RADIO_SECTOR_SIZE);
    if (flash_safe_execute(radio_program_sector, &radio_flash_op, 1000u) != PICO_OK) {
        memset(&radio_flash_op, 0, sizeof(radio_flash_op));
        return false;
    }
    memset(&radio_flash_op, 0, sizeof(radio_flash_op));
    const uint8_t *readback = (const uint8_t *)(uintptr_t)RADIO_PROVISION_XIP;
    if (memcmp(readback, sector_image, RADIO_SECTOR_SIZE) != 0) return false;
    struct radio_config persisted;
    if (!radio_config_parse2(readback, RADIO_SECTOR_SIZE, &persisted)) return false;
    return strncmp(persisted.ssid, candidate.ssid, sizeof(persisted.ssid)) == 0 &&
           strncmp(persisted.psk, candidate.psk, sizeof(persisted.psk)) == 0;
}

bool radio_provision_flash_read(struct radio_config *out) {
    const uint8_t *readback = (const uint8_t *)(uintptr_t)RADIO_PROVISION_XIP;
    return radio_config_parse2(readback, RADIO_SECTOR_SIZE, out);
}

bool radio_provision_flash_clear(void) {
    memset(&radio_flash_op, 0xff, sizeof(radio_flash_op));
    radio_flash_op.offset = RADIO_PROVISION_OFFSET;
    int rc = flash_safe_execute(radio_erase_sector, &radio_flash_op, 1000u);
    memset(&radio_flash_op, 0, sizeof(radio_flash_op));
    if (rc != PICO_OK) return false;
    const uint8_t *readback = (const uint8_t *)(uintptr_t)RADIO_PROVISION_XIP;
    for (size_t i = 0; i < RADIO_SECTOR_SIZE; i++) {
        if (readback[i] != 0xffu) return false;
    }
    return true;
}
