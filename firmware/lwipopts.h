#ifndef _LWIPOPTS_H
#define _LWIPOPTS_H

/* Minimal NO_SYS raw-API lwIP for the PicoBridge network endpoint.
 * Single netif (CYW43 STA), single TCP listener, one active session.
 * No BSD sockets, no netconn, no DNS — the controller connects by IP. */

#define NO_SYS                          1
#define LWIP_TIMERS                     1
#define LWIP_SOCKET                     0
#define LWIP_NETCONN                    0

#define LWIP_IPV4                       1
#define LWIP_IPV6                       0
#define LWIP_DHCP                       1
#define LWIP_DNS                        0
#define LWIP_ICMP                       1   /* pingability = diagnostics */
#define LWIP_RAW                        0
#define LWIP_UDP                        1   /* required by DHCP */
#define LWIP_TCP                        1
#define LWIP_ARP                        1

#define LWIP_NETIF_HOSTNAME             1
#define LWIP_NETIF_STATUS_CALLBACK      0
#define LWIP_SINGLE_NETIF               1

#define LWIP_STATS                      0
#define LWIP_PROVIDE_ERRNO              0
#define LWIP_ASSERT_CORE_CHECKS         0

/* Memory: small static pools, no heap growth surprises on 520 KiB SRAM. */
#define MEM_ALIGNMENT                   4
#define MEM_SIZE                        (8 * 1024)
#define MEMP_NUM_PBUF                   16
#define PBUF_POOL_SIZE                  16
#define MEMP_NUM_TCP_PCB                2
#define MEMP_NUM_TCP_PCB_LISTEN         1
#define MEMP_NUM_TCP_SEG                32
#define MEMP_NUM_SYS_TIMEOUT            8
#define TCP_SND_BUF                     (4 * 1024)
#define TCP_SND_QUEUELEN                8
#define TCP_WND                         (4 * 1024)
#define TCP_MSS                         1460
#define TCP_LISTEN_BACKLOG              1

#endif
