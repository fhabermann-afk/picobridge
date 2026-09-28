/* Network command endpoint: Wi-Fi STA + raw-API lwIP TCP carrying the exact
 * BLE command frames behind 4-byte big-endian length prefixes.
 *
 * Trust model: the socket is unauthenticated bytes. command_process_frame()
 * answers handshake frames and encrypted frames only; every action still
 * requires the Noise IK handshake and yields an encrypted receipt. A fresh
 * handshake from any transport takes over the single global Noise session —
 * deliberate, but it means a nearby attacker with an unauthenticated socket
 * can only reset sessions (bounded DoS), never forge or decrypt commands.
 *
 * Fail-closed: without a valid schema 2 radio record the radio is never
 * powered and nothing listens. */

#include "net_endpoint.h"

#ifdef BRIDGE_ENABLE_NET

#include <string.h>

#include "lwip/init.h"
#include "lwip/ip4_addr.h"
#include "lwip/netif.h"
#include "lwip/tcp.h"
#include "lwip/dhcp.h"
#include "pico/cyw43_arch.h"
#include "pico/time.h"

#include "radio_provision_flash.h"
#include "cyw43.h"
#include "cyw43_internal.h"

/* Provided by bridge_main.c (transport-agnostic command core). */
void command_process_frame(const uint8_t *data, uint16_t len,
                           uint8_t *resp, uint16_t resp_cap,
                           uint16_t *resp_len);

typedef enum {
    NET_STATE_NO_RECORD,   /* fail closed: radio untouched, nothing listens */
    NET_STATE_RETRY_WAIT,  /* backoff before the next association attempt */
    NET_STATE_CONNECTING,  /* async connect issued; waiting link + IPv4 */
    NET_STATE_READY,       /* listener armed */
} net_state_t;

static net_state_t net_state = NET_STATE_NO_RECORD;
static uint32_t net_retry_at_ms;
static uint32_t net_retry_delay_ms = 3000u;
static bool net_listener_ok;

/* Session state. All mutations happen either in lwIP callbacks (which run
 * under the async_context lock during async_context_poll) or inside the
 * explicitly locked window of net_endpoint_poll(). */
static struct tcp_pcb *net_listener;
static struct tcp_pcb *net_session_pcb;
static uint8_t net_rx[NET_FRAME_MAX_];
static uint32_t net_rx_len;
static uint8_t net_pending_tx[1u + NOISE_IK_RESPONSE_LEN];
static uint32_t net_pending_tx_len;

static void net_reset_frame(void) {
    net_rx_len = 0;
    net_pending_tx_len = 0;
}

static void net_session_close(struct tcp_pcb *pcb) {
    if (!pcb) return;
    if (pcb == net_session_pcb) net_session_pcb = NULL;
    tcp_arg(pcb, NULL);
    tcp_recv(pcb, NULL);
    tcp_err(pcb, NULL);
    tcp_sent(pcb, NULL);
    tcp_abort(pcb);
    net_reset_frame();
}

static err_t net_sent_cb(void *arg, struct tcp_pcb *pcb, uint16_t len) {
    (void)arg; (void)len;
    if (pcb != net_session_pcb) return ERR_OK;
    if (net_pending_tx_len == 0) return ERR_OK;
    uint32_t space = tcp_sndbuf(pcb);
    if (space == 0) return ERR_OK;
    uint16_t n = net_pending_tx_len < space ? (uint16_t)net_pending_tx_len : (uint16_t)space;
    if (tcp_write(pcb, net_pending_tx, n, TCP_WRITE_FLAG_COPY) != ERR_OK) return ERR_OK;
    tcp_output(pcb);
    if (n >= net_pending_tx_len) {
        net_pending_tx_len = 0;
    } else {
        memmove(net_pending_tx, net_pending_tx + n, net_pending_tx_len - n);
        net_pending_tx_len -= n;
    }
    return ERR_OK;
}

static void net_process_frame(struct tcp_pcb *pcb) {
    uint8_t resp[1u + NOISE_IK_RESPONSE_LEN];
    uint16_t resp_len = 0;
    command_process_frame(net_rx, (uint16_t)net_rx_len, resp, sizeof(resp), &resp_len);
    net_rx_len = 0;
    if (resp_len == 0) return;
    if (net_pending_tx_len != 0) {
        /* Previous receipt never drained: peer outran the socket. Kill the
         * session rather than interleave receipts. */
        net_session_close(pcb);
        return;
    }
    memcpy(net_pending_tx, resp, resp_len);
    net_pending_tx_len = resp_len;
    (void)net_sent_cb(NULL, pcb, 0);
}

static err_t net_recv_cb(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    (void)arg;
    if (pcb != net_session_pcb) {
        if (p) tcp_recved(pcb, p->tot_len);
        return ERR_OK;
    }
    if (err != ERR_OK || p == NULL) {  /* remote closed */
        net_session_close(pcb);
        return ERR_OK;
    }
    bool overflow = false;
    for (struct pbuf *q = p; q != NULL && !overflow; q = q->next) {
        const uint8_t *data = (const uint8_t *)q->payload;
        for (uint16_t i = 0; i < q->len; i++) {
            if (net_rx_len < 4u) {
                net_rx[net_rx_len++] = data[i];
                if (net_rx_len == 4u) {
                    uint32_t flen = ((uint32_t)net_rx[0] << 24) | ((uint32_t)net_rx[1] << 16) |
                                    ((uint32_t)net_rx[2] << 8) | net_rx[3];
                    if (flen == 0u || flen > NET_FRAME_MAX_) overflow = true;
                }
            } else {
                net_rx[net_rx_len++] = data[i];
                uint32_t flen = ((uint32_t)net_rx[0] << 24) | ((uint32_t)net_rx[1] << 16) |
                                ((uint32_t)net_rx[2] << 8) | net_rx[3];
                if (net_rx_len == 4u + flen) net_process_frame(pcb);
                if (net_session_pcb == NULL) { overflow = true; break; }
            }
        }
    }
    uint16_t total = p->tot_len;
    pbuf_free(p);
    tcp_recved(pcb, total);
    if (overflow) net_session_close(pcb);
    return ERR_OK;
}

static void net_err_cb(void *arg, err_t err) {
    (void)arg; (void)err;
    /* lwIP already freed the pcb here; net_recv_cb detached via tcp_arg. */
    net_session_pcb = NULL;
    net_reset_frame();
}

static err_t net_accept_cb(void *arg, struct tcp_pcb *newpcb, err_t err) {
    (void)arg;
    if (err != ERR_OK || !newpcb) return ERR_VAL;
    if (net_session_pcb || net_pending_tx_len != 0) {
        /* One session at a time: a scanner cannot lock out the owner. */
        tcp_abort(newpcb);
        return ERR_ABRT;
    }
    net_session_pcb = newpcb;
    net_reset_frame();
    tcp_arg(newpcb, NULL);
    tcp_recv(newpcb, net_recv_cb);
    tcp_err(newpcb, net_err_cb);
    tcp_sent(newpcb, net_sent_cb);
    tcp_nagle_disable(newpcb);
    return ERR_OK;
}

/* Must be called with the async_context lock held. */
static bool net_start_listener_locked(void) {
    if (net_listener) return true;
    struct tcp_pcb *lpcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (!lpcb) return false;
    if (tcp_bind(lpcb, IP_ANY_TYPE, NET_LISTEN_PORT_) != ERR_OK) {
        tcp_close(lpcb);
        return false;
    }
    net_listener = tcp_listen(lpcb);
    if (!net_listener) {
        tcp_close(lpcb);
        return false;
    }
    tcp_accept(net_listener, net_accept_cb);
    return true;
}

bool net_endpoint_start(void) {
    struct radio_config cfg;
    if (!radio_provision_flash_read(&cfg)) {
        net_state = NET_STATE_NO_RECORD;  /* fail closed, no radio */
        return false;
    }
    memset(&cfg, 0, sizeof(cfg));
    net_state = NET_STATE_RETRY_WAIT;
    net_retry_at_ms = 0;
    net_retry_delay_ms = 3000u;
    return true;
}

bool net_endpoint_wifi_up(void) {
    return net_state == NET_STATE_READY && net_listener_ok;
}

uint8_t net_endpoint_state(void) { return (uint8_t)net_state; }

int8_t net_endpoint_link(void) {
    if (net_state == NET_STATE_NO_RECORD) return 0;
    return (int8_t)cyw43_wifi_link_status(&cyw43_state, CYW43_ITF_STA);
}

uint16_t net_endpoint_raw(void) {
    return (uint16_t)cyw43_state.wifi_join_state;
}

uint8_t net_endpoint_dhcp(void) {
    struct netif *n = netif_find("w0");
    const struct dhcp *d;
    if (!n) return 0;
    d = netif_dhcp_data(n);
    if (!d) return 0;                    /* dhcp_start never ran */
    if (!netif_is_up(n)) return 1;       /* netif down */
    return d->state == 10 ? 3 : (uint8_t)d->state;  /* 10 = BOUND */
}

void net_endpoint_poll(uint32_t now_ms) {
    if (net_state == NET_STATE_NO_RECORD) return;

    /* IMPORTANT: cyw43_arch_* functions take the async_context lock
     * themselves; never call them while holding it (non-recursive lock).
     * The locked section below only touches our lwIP objects, exactly the
     * same objects the tcp callbacks manipulate under the same lock. */
    bool have_ip = false;
    async_context_t *ctx = cyw43_arch_async_context();
    async_context_acquire_lock_blocking(ctx);
    struct netif *n = netif_find("w0");
    if (n) have_ip = netif_is_up(n) && !ip4_addr_isany_val(*netif_ip4_addr(n));
    async_context_release_lock(ctx);

    switch (net_state) {
        case NET_STATE_NO_RECORD:
            return;
        case NET_STATE_RETRY_WAIT:
            if ((int32_t)(now_ms - net_retry_at_ms) < 0) return;
            if (have_ip) {  /* driver reconnected under us */
                net_state = NET_STATE_CONNECTING;
                net_retry_at_ms = now_ms + NET_CONNECT_TIMEOUT_MS_;
                break;
            }
            {
                struct radio_config cfg;
                if (!radio_provision_flash_read(&cfg)) {
                    net_state = NET_STATE_NO_RECORD;  /* radio cleared */
                    return;
                }
                /* cyw43_arch_init does NOT enable STA mode (SDK examples do
                 * it explicitly); the join needs w0 up with lwIP/DHCP wired:
                 * exactly what this call performs. Idempotent per retry. */
                cyw43_arch_enable_sta_mode();
                int r = cyw43_arch_wifi_connect_async(cfg.ssid, cfg.psk,
                                                      CYW43_AUTH_WPA2_AES_PSK);
                memset(&cfg, 0, sizeof(cfg));
                if (r != PICO_OK) {
                    net_retry_at_ms = now_ms + net_retry_delay_ms;
                    if (net_retry_delay_ms < NET_RETRY_MAX_MS_) {
                        net_retry_delay_ms *= 2;
                        if (net_retry_delay_ms > NET_RETRY_MAX_MS_) net_retry_delay_ms = NET_RETRY_MAX_MS_;
                    }
                    return;
                }
            }
            net_retry_at_ms = now_ms + NET_CONNECT_TIMEOUT_MS_;
            net_state = NET_STATE_CONNECTING;
            return;
        case NET_STATE_CONNECTING:
            if (have_ip) {
                async_context_acquire_lock_blocking(ctx);
                net_listener_ok = net_start_listener_locked();
                async_context_release_lock(ctx);
                if (net_listener_ok) {
                    net_retry_delay_ms = 3000u;
                    net_state = NET_STATE_READY;
                    return;
                }
            }
            /* Timeout only while NOT associated: JOIN (link 1) means the
             * 4-way/DHCP phase is still in flight — killing it there caused
             * a flap loop that threw away leases seconds before they came. */
            if ((int32_t)(now_ms - net_retry_at_ms) >= 0 &&
                cyw43_wifi_link_status(&cyw43_state, CYW43_ITF_STA) < CYW43_LINK_JOIN) {
                cyw43_arch_disable_sta_mode();  /* drop association, retry fresh */
                cyw43_arch_enable_sta_mode();
                net_state = NET_STATE_RETRY_WAIT;
                net_retry_at_ms = now_ms + net_retry_delay_ms;
                if (net_retry_delay_ms < NET_RETRY_MAX_MS_) {
                    net_retry_delay_ms *= 2;
                    if (net_retry_delay_ms > NET_RETRY_MAX_MS_) net_retry_delay_ms = NET_RETRY_MAX_MS_;
                }
            }
            return;
        case NET_STATE_READY:
            if (!have_ip) {
                /* Association or lease lost: kill the session; the listener
                 * pcb bound to ANY survives interface flaps in lwIP. */
                async_context_acquire_lock_blocking(ctx);
                net_session_close(net_session_pcb);
                async_context_release_lock(ctx);
                net_state = NET_STATE_CONNECTING;
                net_retry_at_ms = now_ms + NET_CONNECT_TIMEOUT_MS_;
            }
            return;
    }
}

#endif /* BRIDGE_ENABLE_NET */
