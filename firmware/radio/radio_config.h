#ifndef RADIO_CONFIG_H
#define RADIO_CONFIG_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The radio record lives in the last free flash sector below the RP2350-E10
 * errata sector (the final 4 KiB of the 4 MiB flash). Below that sit the
 * BTstack flash bank and the controller trust store — see docs/flash-layout.md.
 *
 * The offsets are derived from the SDK constants so the three regions cannot
 * drift onto each other silently. Host unit tests compile this header without
 * the SDK, so the SDK-derived form is only used when the SDK headers exist. */
#if defined(__has_include)
#  if __has_include("hardware/flash.h") && __has_include("pico/btstack_flash_bank.h")
#    include "hardware/flash.h"
#    include "pico/btstack_flash_bank.h"
#    include "pico/platform.h"
#    define RADIO_HAVE_FLASH_LAYOUT 1
#  endif
#endif

#ifdef RADIO_HAVE_FLASH_LAYOUT
#  define RADIO_SECTOR_SIZE FLASH_SECTOR_SIZE
/* Layout (top of the 4 MiB flash, downward): RP2350-E10 errata sector
 * 0x3FF000, BTstack bank 0x3FD000..0x3FEFFF, controller store
 * 0x3FB000..0x3FCFFF, radio record 0x3FA000. Overlap with the controller
 * store is asserted in controller_store_flash.c where both are defined. */
#  define RADIO_PROVISION_OFFSET (PICO_FLASH_BANK_STORAGE_OFFSET - 3u * FLASH_SECTOR_SIZE)
#  define RADIO_PROVISION_XIP (XIP_BASE + RADIO_PROVISION_OFFSET)
#else /* host test build: literals mirror the RP2350 4 MiB layout */
#  define RADIO_SECTOR_SIZE 4096u
#  define RADIO_PROVISION_OFFSET 0x003FA000u
#  define RADIO_PROVISION_XIP 0x103FA000u
#endif

struct radio_config {
    char ssid[33];
    char psk[64];
    const uint8_t *cert, *key;
    size_t cert_len, key_len;
};
/* Schema 1 (PBRAD01): AP/diagnostic record, certificate fields mandatory. */
bool radio_config_parse(const uint8_t *sector, size_t length, struct radio_config *out);
/* Schema 2 (PBRAD02): station-mode record for the WLAN command endpoint.
 * Same layout as schema 1 but cert/key are optional (length 0 permitted)
 * and the PSK lower bound is 8 (WPA2-Personal minimum for third-party
 * routers). Never accepts schema 1 bytes and vice versa. */
bool radio_config_parse2(const uint8_t *sector, size_t length, struct radio_config *out);
/* Build a schema 2 sector image for provisioning. Returns false without
 * touching out on invalid input. */
bool radio_config_build2(const char *ssid, size_t ssid_len, const char *psk,
                         size_t psk_len, uint8_t out[RADIO_SECTOR_SIZE]);
#endif
