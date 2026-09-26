#include "radio_config.h"
#include <string.h>
static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | (uint16_t)p[1]<<8); }

static bool parse_common(const uint8_t *s, size_t n, struct radio_config *out,
                         const char magic[8], uint16_t schema,
                         size_t psk_min, bool certs_mandatory) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!s || n != RADIO_SECTOR_SIZE) return false;
    if (memcmp(s,magic,8) || le16(s+8)!=schema) return false;
    size_t a=le16(s+16), b=le16(s+18), c=le16(s+20), d=le16(s+22);
    if (a<1 || a>32 || b<psk_min || b>63) return false;
    if (certs_mandatory) {
        if (c<1 || c>2048 || d<1 || d>1024) return false;
    } else {
        /* Optional certificate fields must both be present or both absent. */
        if (c>2048 || d>1024 || ((c==0) != (d==0))) return false;
    }
    if (24+a+b+c+d>n) return false;
    size_t total=le16(s+10);
    if (total!=24+a+b+c+d || total>n) return false;
    for (size_t i=24;i<24+a+b;i++) if (s[i]<32 || s[i]>126) return false;
    for (size_t i=total;i<n;i++) if (s[i]!=255) return false;
    uint32_t crc=UINT32_MAX;
    for (size_t i=16;i<total;i++) {
        crc ^= s[i];
        for (unsigned j=0;j<8;j++) crc=(crc>>1)^((0u-(crc&1u))&0xedb88320u);
    }
    uint32_t stored=(uint32_t)s[12]|(uint32_t)s[13]<<8|(uint32_t)s[14]<<16|(uint32_t)s[15]<<24;
    if ((crc^UINT32_MAX)!=stored) return false;
    memcpy(out->ssid,s+24,a); memcpy(out->psk,s+24+a,b);
    out->cert=s+24+a+b; out->key=out->cert+c;
    out->cert_len=c; out->key_len=d;
    return true;
}

bool radio_config_parse(const uint8_t *s, size_t n, struct radio_config *out) {
    return parse_common(s, n, out, "PBRAD01\0", 1, 20, true);
}

bool radio_config_parse2(const uint8_t *s, size_t n, struct radio_config *out) {
    return parse_common(s, n, out, "PBRAD02\0", 2, 8, false);
}

bool radio_config_build2(const char *ssid, size_t ssid_len, const char *psk,
                         size_t psk_len, uint8_t out[RADIO_SECTOR_SIZE]) {
    if (!ssid || !psk || !out) return false;
    if (ssid_len < 1 || ssid_len > 32) return false;
    if (psk_len < 8 || psk_len > 63) return false;
    for (size_t i = 0; i < ssid_len; i++) if ((unsigned char)ssid[i] < 32 || (unsigned char)ssid[i] > 126) return false;
    for (size_t i = 0; i < psk_len; i++) if ((unsigned char)psk[i] < 32 || (unsigned char)psk[i] > 126) return false;
    memset(out, 0xff, RADIO_SECTOR_SIZE);
    size_t total = 24 + ssid_len + psk_len; /* cert/key lengths are 0 */
    memcpy(out, "PBRAD02\0", 8);
    out[8] = 2; out[9] = 0;                                    /* schema */
    out[10] = (uint8_t)total; out[11] = (uint8_t)(total >> 8);
    out[16] = (uint8_t)ssid_len; out[17] = (uint8_t)(ssid_len >> 8);
    out[18] = (uint8_t)psk_len;  out[19] = (uint8_t)(psk_len >> 8);
    out[20] = 0; out[21] = 0; out[22] = 0; out[23] = 0;         /* no cert/key */
    /* CRC covers s[16..total-1]: the four LE16 lengths then ssid+psk — the
     * exact byte stream the parser hashes. */
    uint32_t crc = UINT32_MAX;
    const uint8_t lens[8] = { out[16], out[17], out[18], out[19], 0, 0, 0, 0 };
    for (size_t i = 0; i < 8; i++) {
        crc ^= lens[i];
        for (unsigned j = 0; j < 8; j++) crc = (crc >> 1) ^ ((0u - (crc & 1u)) & 0xedb88320u);
    }
    for (size_t i = 0; i < ssid_len; i++) {
        crc ^= (uint8_t)ssid[i];
        for (unsigned j = 0; j < 8; j++) crc = (crc >> 1) ^ ((0u - (crc & 1u)) & 0xedb88320u);
    }
    for (size_t i = 0; i < psk_len; i++) {
        crc ^= (uint8_t)psk[i];
        for (unsigned j = 0; j < 8; j++) crc = (crc >> 1) ^ ((0u - (crc & 1u)) & 0xedb88320u);
    }
    crc ^= UINT32_MAX;
    out[12] = (uint8_t)crc; out[13] = (uint8_t)(crc >> 8);
    out[14] = (uint8_t)(crc >> 16); out[15] = (uint8_t)(crc >> 24);
    memcpy(out + 24, ssid, ssid_len);
    memcpy(out + 24 + ssid_len, psk, psk_len);
    return true;
}
