#include "http_parser.h"
#include <stdbool.h>
#include <string.h>
static bool eq(const uint8_t *p,size_t n,const char *s) {
    return n==strlen(s) && !memcmp(p,s,n);
}
static bool ieq(const uint8_t *p,size_t n,const char *s) {
    if (n!=strlen(s)) return false;
    for (size_t i=0;i<n;i++) {
        unsigned c=p[i]; if(c>='A' && c<='Z') c+='a'-'A';
        if(c!=(unsigned char)s[i]) return false;
    }
    return true;
}
static bool token(unsigned c) {
    return (c>='a' && c<='z') || (c>='A' && c<='Z') ||
           (c>='0' && c<='9') || (c && strchr("!#$%&'*+-.^_`|~",(int)c));
}
enum radio_http_result radio_http_parse(const uint8_t *p,size_t n) {
    if (n>RADIO_HTTP_MAX) return HTTP_LARGE;
    if (!p) return n ? HTTP_BAD : HTTP_MORE;
    size_t end=0;
    for (size_t i=0;i<n;i++) {
        if (p[i]=='\r') { if(i+1<n && p[i+1]!='\n') return HTTP_BAD; }
        else if (p[i]=='\n') { if(!i || p[i-1]!='\r') return HTTP_BAD; }
        else if (p[i]<32 || p[i]>126) return HTTP_BAD;
        if(i>=3 && !memcmp(p+i-3,"\r\n\r\n",4) && !end) end=i+1;
    }
    if (!end) return n==RADIO_HTTP_MAX ? HTTP_LARGE : HTTP_MORE;
    if(end!=n) return HTTP_BAD; /* no body or pipelining */
    size_t line=0;
    while(line+1<n && !(p[line]=='\r' && p[line+1]=='\n')) line++;
    size_t m=0; while(m<line && token(p[m])) m++;
    if(!m || m>=line || p[m]!=' ') return HTTP_BAD;
    size_t path=m+1, pathend=path;
    while(pathend<line && p[pathend]!=' ') pathend++;
    if(pathend==path || p[path]!='/' || pathend>=line ||
       !eq(p+pathend+1,line-pathend-1,"HTTP/1.1")) return HTTP_BAD;
    bool host=false, cl=false;
    size_t pos=line+2;
    while(pos<n-2) {
        size_t stop=pos; while(stop+1<n && p[stop]!='\r') stop++;
        if(stop==pos) return HTTP_BAD;
        size_t colon=pos;
        while(colon<stop && token(p[colon])) colon++;
        if(colon==pos || colon>=stop || p[colon]!=':') return HTTP_BAD;
        size_t value=colon+1, vend=stop;
        while(value<vend && p[value]==' ') value++;
        while(vend>value && p[vend-1]==' ') vend--;
        if(ieq(p+pos,colon-pos,"host")) {
            if(host || !(eq(p+value,vend-value,"192.168.4.1") ||
                         eq(p+value,vend-value,"192.168.4.1:443"))) return HTTP_BAD;
            host=true;
        } else if(ieq(p+pos,colon-pos,"content-length")) {
            if(cl || !eq(p+value,vend-value,"0")) return HTTP_BAD;
            cl=true;
        } else if(ieq(p+pos,colon-pos,"transfer-encoding") ||
                  ieq(p+pos,colon-pos,"expect") || ieq(p+pos,colon-pos,"upgrade")) return HTTP_BAD;
        pos=stop+2;
    }
    if(!host) return HTTP_BAD;
    if(!eq(p,m,"GET")) return HTTP_METHOD;
    if(eq(p+path,pathend-path,"/")) return HTTP_ROOT;
    if(eq(p+path,pathend-path,"/health")) return HTTP_HEALTH;
    return HTTP_NOT_FOUND;
}
