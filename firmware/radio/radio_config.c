#include "radio_config.h"
#include <string.h>
static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | (uint16_t)p[1]<<8); }
bool radio_config_parse(const uint8_t *s, size_t n, struct radio_config *out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!s || n != RADIO_SECTOR_SIZE) return false;
    if (memcmp(s,"PBRAD01\0",8) || le16(s+8)!=1) return false;
    size_t a=le16(s+16), b=le16(s+18), c=le16(s+20), d=le16(s+22);
    if (a<1 || a>32 || b<20 || b>63 || c<1 || c>2048 || d<1 || d>1024 || 24+a+b+c+d>n) return false;
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
