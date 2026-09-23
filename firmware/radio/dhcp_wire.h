#ifndef RADIO_DHCP_WIRE_H
#define RADIO_DHCP_WIRE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define RADIO_DHCP_MAX 576u
struct radio_dhcp_request { uint8_t type, mac[6], xid[4], requested[4], server[4], ciaddr[4]; bool has_requested,has_server; };
bool radio_dhcp_parse(const uint8_t *p,size_t n,struct radio_dhcp_request *out);
#endif
