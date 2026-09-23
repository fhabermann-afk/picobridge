#ifndef PICO_BRIDGE_RECOVERY_ADMIN_PUBLIC_H
#define PICO_BRIDGE_RECOVERY_ADMIN_PUBLIC_H

#include <stdint.h>

/* TEMPLATE ONLY - replace before your first build/flash!
 *
 * This is the public X25519 key of the OFFLINE RECOVERY ADMINISTRATOR. The
 * matching private key must live only in your own password manager / offline
 * vault and is used to recover control of the device if daily controller
 * identities are lost. Anyone who controls the private key matching whatever
 * is burned in HERE can enroll themselves as recovery admin on devices built
 * from this tree, so generate your own keypair first (see docs/PROVISIONING.md)
 * and substitute the public half before flashing your device.
 */
static const uint8_t PICO_BRIDGE_RECOVERY_ADMIN_PUBLIC[32] = {
    0xb4, 0x9a, 0x20, 0xa6, 0x95, 0xf5, 0x28, 0x8f,
    0xb3, 0x74, 0x39, 0xb3, 0x84, 0x4b, 0xc3, 0x12,
    0x3b, 0xdb, 0x7b, 0xa9, 0xb1, 0xc8, 0x10, 0xd9,
    0x1b, 0xcc, 0xd8, 0xa4, 0x9f, 0xf0, 0x3f, 0x76,
};

#endif
