/* Original bounded DHCP wire reader; RFC 2131/2132, no demo helper code. */
#include "dhcp_wire.h"
#include <string.h>
bool radio_dhcp_parse(const uint8_t *p,size_t n,struct radio_dhcp_request *out) {
    if(!out) return false;
    memset(out,0,sizeof(*out));
    if(!p || n<240 || n>RADIO_DHCP_MAX) return false;
    static const uint8_t zero[4]={0};
    if(p[0]!=1 || p[1]!=1 || p[2]!=6 || p[3]!=0 ||
       memcmp(p+24,zero,4) || memcmp(p+236,"\x63\x82\x53\x63",4) ||
       (p[28]&1u) || !(p[28]|p[29]|p[30]|p[31]|p[32]|p[33])) return false;
    struct radio_dhcp_request r={0};
    bool ended=false;
    memcpy(r.mac,p+28,6); memcpy(r.xid,p+4,4); memcpy(r.ciaddr,p+12,4);
    size_t i=240;
    while(i<n) {
        unsigned opt=p[i++]; if(!opt) continue; if(opt==255) { ended=true; break; }
        if(i==n) return false;
        size_t len=p[i++]; if(len>n-i) return false;
        if(opt==53) { if(len!=1 || r.type) return false; r.type=p[i]; }
        else if(opt==50) {
            if(len!=4 || r.has_requested) return false;
            memcpy(r.requested,p+i,4); r.has_requested=true;
        } else if(opt==54) {
            if(len!=4 || r.has_server) return false;
            memcpy(r.server,p+i,4); r.has_server=true;
        } else if(opt==52) return false; /* no option overload */
        i+=len;
    }
    if(!ended || (r.type!=1 && r.type!=3)) return false;
    *out=r; return true;
}
