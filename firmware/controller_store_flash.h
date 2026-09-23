#ifndef CONTROLLER_STORE_FLASH_H
#define CONTROLLER_STORE_FLASH_H

#include "controller_store.h"

/* Pico 2 W: two 4-KiB sectors immediately before BTstack's flash bank. The
 * SDK places that bank below RP2350's final errata-reserved sector. */
controller_store_status_t controller_store_flash_boot_or_seed(
    controller_store_t *store, const uint8_t recovery_public_key[CONTROLLER_STORE_KEY_LEN]);
controller_store_status_t controller_store_flash_commit(const controller_store_t *store);

#endif
