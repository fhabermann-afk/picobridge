#ifndef PICO_BRIDGE_NOISE_IK_H
#define PICO_BRIDGE_NOISE_IK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "controller_store.h"

/* Noise_IK_25519_ChaChaPoly_SHA256 wire sizes. */
#define NOISE_IK_KEY_LEN 32u
#define NOISE_IK_TAG_LEN 16u
#define NOISE_IK_INIT_MESSAGE_LEN 80u     /* e || EncryptAndHash(s) */
#define NOISE_IK_RESPONSE_LEN 53u         /* e || EncryptAndHash("PBIK1") */
#define NOISE_IK_TRANSPORT_NONCE_LEN 8u   /* little-endian uint64 */
#define NOISE_IK_TRANSPORT_OVERHEAD (NOISE_IK_TRANSPORT_NONCE_LEN + NOISE_IK_TAG_LEN)
#define NOISE_IK_TRANSPORT_ACK_LEN 6u /* "PBOK1" plus bridge_status_t */
#define NOISE_IK_TRANSPORT_RESPONSE_LEN (NOISE_IK_TRANSPORT_OVERHEAD + NOISE_IK_TRANSPORT_ACK_LEN)
#define NOISE_IK_MAX_PLAINTEXT 1038u      /* largest bridge-core command frame */

/* Initialise permanent device identity and active controller trust store. */
int noise_ik_init(const controller_store_t *controllers);

/* Slot/role of the currently authenticated controller; invalid until the
 * current Noise IK handshake finishes successfully. */
size_t noise_authenticated_slot(void);
controller_role_t noise_authenticated_role(void);

/* Consume the 80-byte IK initiator message and produce the 53-byte authenticated response. */
int noise_ik_handshake_respond(const uint8_t *initiator_message, size_t initiator_len,
                               uint8_t *response_out, size_t response_cap, size_t *response_len);

/* Verify/decrypt nonce64 || ciphertext || tag. Rejects stale, skipped and unauthenticated frames. */
int noise_decrypt_packet(const uint8_t *packet, size_t packet_len,
                         uint8_t *plaintext_out, size_t plaintext_cap, size_t *plaintext_len);

/* Encrypt an authenticated device receipt and the corresponding bridge command status. */
int noise_encrypt_transport_ack(uint8_t command_status,
                                uint8_t *packet_out, size_t packet_cap, size_t *packet_len);

bool noise_is_ready(void);

#endif
