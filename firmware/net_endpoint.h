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

#endif
