#ifndef RADIO_PROVISION_FLASH_H
#define RADIO_PROVISION_FLASH_H
#include <stdbool.h>
#include <stdint.h>
#include "radio_config.h"

/* Write a caller-built schema 2 sector image to the dedicated radio sector
 * (0x3FA000), then re-read and parse-verify it. The sector is single-slot:
 * a torn write leaves an unparseable record, and the next successful
 * provisioning overwrites it — acceptable because the record is re-sent
 * over the authenticated BLE channel, not accumulated state.
 * Returns true only when the read-back parses as schema 2 and matches the
 * submitted ssid/psk byte-for-byte. */
bool radio_provision_flash_write_and_verify(const uint8_t sector_image[RADIO_SECTOR_SIZE]);

/* Read the persisted record. Returns true on a valid schema 2 record.
 * Does not wipe `out` on success (callers may keep pointers into flash XIP). */
bool radio_provision_flash_read(struct radio_config *out);

/* Clear the sector (erase). Idempotent; safe on already-erased flash. */
bool radio_provision_flash_clear(void);
#endif
