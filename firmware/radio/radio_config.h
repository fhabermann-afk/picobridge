#ifndef RADIO_CONFIG_H
#define RADIO_CONFIG_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define RADIO_SECTOR_SIZE 4096u
#define RADIO_PROVISION_OFFSET 0x003ff000u
#define RADIO_PROVISION_XIP 0x103ff000u
struct radio_config {
    char ssid[33];
    char psk[64];
    const uint8_t *cert, *key;
    size_t cert_len, key_len;
};
bool radio_config_parse(const uint8_t *sector, size_t length, struct radio_config *out);
#endif
