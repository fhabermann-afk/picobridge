/* Mutually authenticated Noise IK responder for the Pico bridge.
 *
 * The private device key and authorized host public key are generated offline
 * by tools/noise_ik_provision.py. They are deliberately not derived from a
 * public serial number.
 */
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "pico/rand.h"
#include "pico/time.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/sha256.h"
#include "mbedtls/md.h"
#include "mbedtls/bignum.h"
#include "noise_ik.h"
#include "noise_ik_keys.h"

#define IK_NONCE_LEN 12u
#define IK_TRANSCRIPT_MAX (32u + NOISE_IK_INIT_MESSAGE_LEN)
#define IK_ACK_LEN 5u
static const uint8_t ik_protocol_name[] = "Noise_IK_25519_ChaChaPoly_SHA256";
static const uint8_t ik_ack[IK_ACK_LEN] = {'P', 'B', 'I', 'K', '1'};

typedef struct {
    uint8_t device_static_priv[NOISE_IK_KEY_LEN];
    uint8_t device_static_pub[NOISE_IK_KEY_LEN];
    const controller_store_t *controllers;  /* owned by bridge_main for device lifetime */
    size_t authenticated_slot;
    controller_role_t authenticated_role;
    uint8_t key[NOISE_IK_KEY_LEN];             /* handshake CipherState */
    uint8_t receive_key[NOISE_IK_KEY_LEN];     /* initiator -> responder */
    uint8_t send_key[NOISE_IK_KEY_LEN];        /* responder -> initiator */
    uint8_t ck[NOISE_IK_KEY_LEN];
    uint8_t h[NOISE_IK_KEY_LEN];
    uint64_t nonce_counter;                    /* handshake CipherState */
    uint64_t receive_nonce;
    uint64_t send_nonce;
    bool ready;
} noise_ik_ctx_t;

static noise_ik_ctx_t nctx;

/* mbedtls_ms_time replacement (avoids platform_util.c #error). */
mbedtls_ms_time_t mbedtls_ms_time(void) {
    return (mbedtls_ms_time_t)to_ms_since_boot(get_absolute_time());
}

static int rng_callback(void *ctx, unsigned char *buf, size_t len) {
    (void)ctx;
    while (len) {
        uint32_t value = get_rand_32();
        size_t take = len < sizeof(value) ? len : sizeof(value);
        memcpy(buf, &value, take);
        buf += take;
        len -= take;
    }
    return 0;
}

static int ik_sha256(const uint8_t *data, size_t len, uint8_t out[NOISE_IK_KEY_LEN]) {
    return mbedtls_sha256(data, len, out, 0);
}

static int mix_hash(const uint8_t *data, size_t len) {
    uint8_t transcript[IK_TRANSCRIPT_MAX];
    if (len > NOISE_IK_INIT_MESSAGE_LEN) return -1;
    memcpy(transcript, nctx.h, NOISE_IK_KEY_LEN);
    memcpy(transcript + NOISE_IK_KEY_LEN, data, len);
    return ik_sha256(transcript, NOISE_IK_KEY_LEN + len, nctx.h);
}

/* Noise MixKey: HKDF(ck, input, 2); setting a cipher key resets its nonce. */
static int mix_key(const uint8_t *data, size_t len) {
    uint8_t tmp[2 * NOISE_IK_KEY_LEN];
    int ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                           nctx.ck, NOISE_IK_KEY_LEN, data, len,
                           NULL, 0, tmp, sizeof(tmp));
    if (ret == 0) {
        memcpy(nctx.ck, tmp, NOISE_IK_KEY_LEN);
        memcpy(nctx.key, tmp + NOISE_IK_KEY_LEN, NOISE_IK_KEY_LEN);
        nctx.nonce_counter = 0;
    }
    memset(tmp, 0, sizeof(tmp));
    return ret;
}

static void noise_nonce(uint64_t counter, uint8_t nonce[IK_NONCE_LEN]) {
    memset(nonce, 0, IK_NONCE_LEN);
    for (unsigned i = 0; i < 8; ++i) {
        nonce[4 + i] = (uint8_t)(counter >> (8u * i));
    }
}

static int x25519_dh(const uint8_t priv_in[NOISE_IK_KEY_LEN],
                     const uint8_t pub[NOISE_IK_KEY_LEN],
                     uint8_t shared[NOISE_IK_KEY_LEN]) {
    int ret;
    uint8_t priv[NOISE_IK_KEY_LEN];
    mbedtls_ecp_group grp;
    mbedtls_ecp_point peer;
    mbedtls_mpi scalar;
    mbedtls_mpi result;

    memcpy(priv, priv_in, sizeof(priv));
    /* RFC 7748 clamping is required for the mbedTLS Curve25519 path. */
    priv[0] &= 0xf8u;
    priv[31] &= 0x7fu;
    priv[31] |= 0x40u;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&peer);
    mbedtls_mpi_init(&scalar);
    mbedtls_mpi_init(&result);
    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (ret == 0) ret = mbedtls_ecp_point_read_binary(&grp, &peer, pub, NOISE_IK_KEY_LEN);
    if (ret == 0) ret = mbedtls_mpi_read_binary_le(&scalar, priv, NOISE_IK_KEY_LEN);
    if (ret == 0) ret = mbedtls_ecdh_compute_shared(&grp, &result, &peer, &scalar, rng_callback, NULL);
    if (ret == 0) ret = mbedtls_mpi_write_binary_le(&result, shared, NOISE_IK_KEY_LEN);
    mbedtls_mpi_free(&result);
    mbedtls_mpi_free(&scalar);
    mbedtls_ecp_point_free(&peer);
    mbedtls_ecp_group_free(&grp);
    memset(priv, 0, sizeof(priv));
    return ret;
}

static int x25519_keypair(uint8_t priv[NOISE_IK_KEY_LEN], uint8_t pub[NOISE_IK_KEY_LEN]) {
    int ret;
    uint8_t pub_bin[33];
    size_t out_len = 0;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point point;
    mbedtls_mpi scalar;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&point);
    mbedtls_mpi_init(&scalar);
    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (ret == 0) ret = mbedtls_ecdh_gen_public(&grp, &scalar, &point, rng_callback, NULL);
    if (ret == 0) ret = mbedtls_mpi_write_binary_le(&scalar, priv, NOISE_IK_KEY_LEN);
    if (ret == 0) ret = mbedtls_ecp_point_write_binary(&grp, &point, 0, &out_len, pub_bin, sizeof(pub_bin));
    if (ret == 0 && out_len == NOISE_IK_KEY_LEN) memcpy(pub, pub_bin, NOISE_IK_KEY_LEN);
    else if (ret == 0) ret = -1;
    mbedtls_mpi_free(&scalar);
    mbedtls_ecp_point_free(&point);
    mbedtls_ecp_group_free(&grp);
    memset(pub_bin, 0, sizeof(pub_bin));
    return ret;
}

static bool ct_equal(const uint8_t *left, const uint8_t *right, size_t len) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) diff |= left[i] ^ right[i];
    return diff == 0;
}

static int cipher_encrypt_and_hash(const uint8_t *plaintext, size_t plaintext_len,
                                   uint8_t *out, size_t *out_len) {
    uint8_t nonce[IK_NONCE_LEN];
    mbedtls_chachapoly_context cipher;
    if (nctx.nonce_counter == UINT64_MAX) return -1;
    noise_nonce(nctx.nonce_counter, nonce);
    mbedtls_chachapoly_init(&cipher);
    int ret = mbedtls_chachapoly_setkey(&cipher, nctx.key);
    if (ret == 0) {
        ret = mbedtls_chachapoly_encrypt_and_tag(&cipher, plaintext_len, nonce,
                                                  nctx.h, NOISE_IK_KEY_LEN,
                                                  plaintext, out, out + plaintext_len);
    }
    mbedtls_chachapoly_free(&cipher);
    if (ret == 0) {
        *out_len = plaintext_len + NOISE_IK_TAG_LEN;
        ++nctx.nonce_counter;
        ret = mix_hash(out, *out_len);
    }
    memset(nonce, 0, sizeof(nonce));
    return ret;
}

static int cipher_decrypt_and_hash(const uint8_t *encrypted, size_t encrypted_len,
                                   uint8_t *out, size_t *out_len) {
    uint8_t nonce[IK_NONCE_LEN];
    mbedtls_chachapoly_context cipher;
    if (encrypted_len < NOISE_IK_TAG_LEN || nctx.nonce_counter == UINT64_MAX) return -1;
    noise_nonce(nctx.nonce_counter, nonce);
    mbedtls_chachapoly_init(&cipher);
    int ret = mbedtls_chachapoly_setkey(&cipher, nctx.key);
    size_t ciphertext_len = encrypted_len - NOISE_IK_TAG_LEN;
    if (ret == 0) {
        ret = mbedtls_chachapoly_auth_decrypt(&cipher, ciphertext_len, nonce,
                                              nctx.h, NOISE_IK_KEY_LEN,
                                              encrypted + ciphertext_len, encrypted, out);
    }
    mbedtls_chachapoly_free(&cipher);
    if (ret == 0) {
        *out_len = ciphertext_len;
        ++nctx.nonce_counter;
        ret = mix_hash(encrypted, encrypted_len);
    }
    memset(nonce, 0, sizeof(nonce));
    return ret;
}

static int split_transport(void) {
    uint8_t tmp[2 * NOISE_IK_KEY_LEN];
    static const uint8_t empty_input = 0;
    int ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                           nctx.ck, NOISE_IK_KEY_LEN, &empty_input, 0, NULL, 0,
                           tmp, sizeof(tmp));
    if (ret == 0) {
        /* Noise Split order: initiator gets k1 for send and k2 for receive. */
        memcpy(nctx.receive_key, tmp, NOISE_IK_KEY_LEN);
        memcpy(nctx.send_key, tmp + NOISE_IK_KEY_LEN, NOISE_IK_KEY_LEN);
        nctx.receive_nonce = 0;
        nctx.send_nonce = 0;
        memset(nctx.key, 0, sizeof(nctx.key));
    }
    memset(tmp, 0, sizeof(tmp));
    return ret;
}

static int reset_handshake_state(void) {
    nctx.ready = false;
    nctx.authenticated_slot = CONTROLLER_STORE_SLOT_COUNT;
    nctx.authenticated_role = CONTROLLER_ROLE_NONE;
    nctx.nonce_counter = 0;
    nctx.receive_nonce = 0;
    nctx.send_nonce = 0;
    memset(nctx.key, 0, sizeof(nctx.key));
    memset(nctx.receive_key, 0, sizeof(nctx.receive_key));
    memset(nctx.send_key, 0, sizeof(nctx.send_key));
    if (ik_sha256(ik_protocol_name, sizeof(ik_protocol_name) - 1, nctx.h) != 0) return -1;
    memcpy(nctx.ck, nctx.h, NOISE_IK_KEY_LEN);
    return mix_hash(nctx.device_static_pub, NOISE_IK_KEY_LEN);  /* IK pre-message: <- s */
}

int noise_ik_init(const controller_store_t *controllers) {
    static const uint8_t basepoint[NOISE_IK_KEY_LEN] = {9};
    if (!controllers) return -1;
    memset(&nctx, 0, sizeof(nctx));
    nctx.controllers = controllers;
    memcpy(nctx.device_static_priv, PICO_BRIDGE_DEVICE_STATIC_PRIVATE, NOISE_IK_KEY_LEN);
    if (x25519_dh(nctx.device_static_priv, basepoint, nctx.device_static_pub) != 0) return -1;
    return reset_handshake_state();
}

int noise_ik_handshake_respond(const uint8_t *initiator_message, size_t initiator_len,
                               uint8_t *response_out, size_t response_cap, size_t *response_len) {
    uint8_t initiator_static[NOISE_IK_KEY_LEN];
    uint8_t responder_eph_priv[NOISE_IK_KEY_LEN];
    uint8_t responder_eph_pub[NOISE_IK_KEY_LEN];
    uint8_t shared[NOISE_IK_KEY_LEN];
    size_t plaintext_len = 0;
    size_t ack_len = 0;
    int ret = -1;

    if (!initiator_message || !response_out || !response_len ||
        initiator_len != NOISE_IK_INIT_MESSAGE_LEN || response_cap < NOISE_IK_RESPONSE_LEN) return -1;
    if (reset_handshake_state() != 0) goto done;

    const uint8_t *initiator_eph = initiator_message;
    const uint8_t *encrypted_static = initiator_message + NOISE_IK_KEY_LEN;
    if (mix_hash(initiator_eph, NOISE_IK_KEY_LEN) != 0) goto done;  /* -> e */
    if (x25519_dh(nctx.device_static_priv, initiator_eph, shared) != 0 ||
        mix_key(shared, sizeof(shared)) != 0) goto done;             /* es */
    if (cipher_decrypt_and_hash(encrypted_static, NOISE_IK_KEY_LEN + NOISE_IK_TAG_LEN,
                                initiator_static, &plaintext_len) != 0 ||
        plaintext_len != NOISE_IK_KEY_LEN || !nctx.controllers) goto done;
    size_t matched_slot = CONTROLLER_STORE_SLOT_COUNT;
    controller_role_t matched_role = CONTROLLER_ROLE_NONE;
    for (size_t i = 0; i < CONTROLLER_STORE_SLOT_COUNT; ++i) {
        const controller_slot_t *slot = &nctx.controllers->slots[i];
        bool match = slot->role != CONTROLLER_ROLE_NONE &&
                     ct_equal(initiator_static, slot->public_key, NOISE_IK_KEY_LEN);
        if (match && matched_slot == CONTROLLER_STORE_SLOT_COUNT) {
            matched_slot = i;
            matched_role = (controller_role_t)slot->role;
        }
    }
    if (matched_slot == CONTROLLER_STORE_SLOT_COUNT) goto done;
    if (x25519_dh(nctx.device_static_priv, initiator_static, shared) != 0 ||
        mix_key(shared, sizeof(shared)) != 0) goto done;             /* ss */

    if (x25519_keypair(responder_eph_priv, responder_eph_pub) != 0 ||
        mix_hash(responder_eph_pub, NOISE_IK_KEY_LEN) != 0 ||
        x25519_dh(responder_eph_priv, initiator_eph, shared) != 0 ||
        mix_key(shared, sizeof(shared)) != 0 ||                      /* ee */
        x25519_dh(responder_eph_priv, initiator_static, shared) != 0 ||
        mix_key(shared, sizeof(shared)) != 0) goto done;             /* se */

    memcpy(response_out, responder_eph_pub, NOISE_IK_KEY_LEN);
    if (cipher_encrypt_and_hash(ik_ack, sizeof(ik_ack), response_out + NOISE_IK_KEY_LEN, &ack_len) != 0 ||
        ack_len != NOISE_IK_RESPONSE_LEN - NOISE_IK_KEY_LEN) goto done;
    *response_len = NOISE_IK_RESPONSE_LEN;
    if (split_transport() != 0) goto done;
    nctx.authenticated_slot = matched_slot;
    nctx.authenticated_role = matched_role;
    nctx.ready = true;
    ret = 0;

done:
    if (ret != 0) {
        *response_len = 0;
        (void)reset_handshake_state();
    }
    memset(initiator_static, 0, sizeof(initiator_static));
    memset(responder_eph_priv, 0, sizeof(responder_eph_priv));
    memset(shared, 0, sizeof(shared));
    return ret;
}

int noise_decrypt_packet(const uint8_t *packet, size_t packet_len,
                         uint8_t *plaintext_out, size_t plaintext_cap, size_t *plaintext_len) {
    uint8_t nonce[IK_NONCE_LEN];
    uint64_t supplied_nonce = 0;
    mbedtls_chachapoly_context cipher;
    if (!nctx.ready || !packet || !plaintext_out || !plaintext_len ||
        packet_len < NOISE_IK_TRANSPORT_OVERHEAD || nctx.receive_nonce == UINT64_MAX) return -1;
    size_t encrypted_len = packet_len - NOISE_IK_TRANSPORT_NONCE_LEN;
    size_t ciphertext_len = encrypted_len - NOISE_IK_TAG_LEN;
    if (ciphertext_len > plaintext_cap || ciphertext_len > NOISE_IK_MAX_PLAINTEXT) return -1;
    for (unsigned i = 0; i < NOISE_IK_TRANSPORT_NONCE_LEN; ++i) {
        supplied_nonce |= (uint64_t)packet[i] << (8u * i);
    }
    if (supplied_nonce != nctx.receive_nonce) return -1;
    noise_nonce(nctx.receive_nonce, nonce);
    mbedtls_chachapoly_init(&cipher);
    int ret = mbedtls_chachapoly_setkey(&cipher, nctx.receive_key);
    if (ret == 0) {
        ret = mbedtls_chachapoly_auth_decrypt(&cipher, ciphertext_len, nonce,
                                              NULL, 0, packet + NOISE_IK_TRANSPORT_NONCE_LEN + ciphertext_len,
                                              packet + NOISE_IK_TRANSPORT_NONCE_LEN, plaintext_out);
    }
    mbedtls_chachapoly_free(&cipher);
    memset(nonce, 0, sizeof(nonce));
    if (ret == 0) {
        *plaintext_len = ciphertext_len;
        ++nctx.receive_nonce;
    }
    return ret;
}

int noise_encrypt_transport_ack(uint8_t command_status,
                                uint8_t *packet_out, size_t packet_cap, size_t *packet_len) {
    uint8_t receipt[NOISE_IK_TRANSPORT_ACK_LEN] = {'P', 'B', 'O', 'K', '1', command_status};
    uint8_t nonce[IK_NONCE_LEN];
    mbedtls_chachapoly_context cipher;
    if (!nctx.ready || !packet_out || !packet_len ||
        packet_cap < NOISE_IK_TRANSPORT_RESPONSE_LEN || nctx.send_nonce == UINT64_MAX) return -1;
    for (unsigned i = 0; i < NOISE_IK_TRANSPORT_NONCE_LEN; ++i) {
        packet_out[i] = (uint8_t)(nctx.send_nonce >> (8u * i));
    }
    noise_nonce(nctx.send_nonce, nonce);
    mbedtls_chachapoly_init(&cipher);
    int ret = mbedtls_chachapoly_setkey(&cipher, nctx.send_key);
    if (ret == 0) {
        ret = mbedtls_chachapoly_encrypt_and_tag(&cipher, sizeof(receipt), nonce,
                                                  NULL, 0, receipt,
                                                  packet_out + NOISE_IK_TRANSPORT_NONCE_LEN,
                                                  packet_out + NOISE_IK_TRANSPORT_NONCE_LEN + sizeof(receipt));
    }
    mbedtls_chachapoly_free(&cipher);
    memset(nonce, 0, sizeof(nonce));
    if (ret == 0) {
        *packet_len = NOISE_IK_TRANSPORT_RESPONSE_LEN;
        ++nctx.send_nonce;
    }
    return ret;
}

bool noise_is_ready(void) {
    return nctx.ready;
}

size_t noise_authenticated_slot(void) {
    return nctx.ready ? nctx.authenticated_slot : CONTROLLER_STORE_SLOT_COUNT;
}

controller_role_t noise_authenticated_role(void) {
    return nctx.ready ? nctx.authenticated_role : CONTROLLER_ROLE_NONE;
}
