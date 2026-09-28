#ifndef PICO_BRIDGE_NET_ENDPOINT_H
#define PICO_BRIDGE_NET_ENDPOINT_H

#include <stdbool.h>
#include <stdint.h>
#include "noise_ik.h"

#define NET_LISTEN_PORT_   44901u /* "PB"ridge; static, no mDNS needed  */
#define NET_FRAME_MAX_     2048u  /* largest encrypted bridge frame     */
#define NET_CONNECT_TIMEOUT_MS_ 20000u
#define NET_RETRY_MAX_MS_       30000u

/* Network command endpoint (Wi-Fi STA + raw-API lwIP TCP).
 *
 * Transport-only by design: the bytes that arrive on the TCP socket are
 * exactly the frames the BLE characteristic accepts — CMD_NOISE(5) handshake
 * (80-byte initiator message in, 53-byte response out) followed by
 * CMD_ENCRYPTED(6) packets and their encrypted receipts. All authentication,
 * replay protection and receipts live in noise_ik.c; this file adds framing
 * only (4-byte big-endian length prefix per message).
 *
 * The Noise state is global to the device: a successful handshake on ANY
 * transport replaces the current session (and a failed handshake attempt
 * resets it, which is a bounded DoS — never an auth bypass).
 *
 * Requires the schema 2 radio record (set-radio); without a valid record the
 * endpoint stays completely passive: no radio, no listener. */
bool net_endpoint_start(void);
void net_endpoint_poll(uint32_t now_ms);
bool net_endpoint_wifi_up(void);

/* Diagnostic for BLE NET_STATUS: 0=no record, 1=retry wait,
 * 2=connecting (no ipv4 yet), 3=ready (listener armed). */
uint8_t net_endpoint_state(void);

/* Raw cyw43 link status (CYW43_LINK_*): 0 down, 1 join, 2 noip, 3 up,
 * -1 fail, -2 nonet, -3 badauth. Signed! */
int8_t net_endpoint_link(void);

/* Raw driver join_state bits (diagnostics): bit0 active, 9 auth,
 * 10 link, 11 keyed (0x0e01 = STA connected); kind nibble 2 fail,
 * 3 nonet, 4 badauth. */
uint16_t net_endpoint_raw(void);

/* DHCP client state per cyw43 dhcp.c: 0=never started, 1=netif down, 2=discovering, 3=discovered(bound). */
uint8_t net_endpoint_dhcp(void);

#endif
