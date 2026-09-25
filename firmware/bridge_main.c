/* Bridge firmware: USB HID keyboard + BLE GATT command service.
 *
 * Integrates the tested bridge_core state machine with:
 * - USB HID keyboard output (boot protocol, using usb_descriptors.c)
 * - BLE GATT service with a writable characteristic for receiving
 *   stage/confirm/cancel/tick commands from a paired host.
 *
 * BLE is a command channel only — it does NOT act as a BLE keyboard.
 * USB HID is the single output path. */
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "pico/stdlib.h"
#include "pico/unique_id.h"
#include "pico/cyw43_arch.h"
#include "pico/time.h"
#include "pico/btstack_cyw43.h"
#include "pico/async_context_poll.h"
#include "hardware/watchdog.h"
#include "tusb.h"
#include "btstack_run_loop.h"
#include "btstack_event.h"
#include "hci.h"
#include "l2cap.h"
#include "ble/att_server.h"
#include "ble/att_db_util.h"
#include "gap.h"
#include "ble/sm.h"
#include "ble/gatt_client.h"
#include "bridge_core.h"
#include "controller_store_flash.h"
#include "noise_ik.h"
#include "noise_ik_keys.h"
#include "recovery_admin_public.h"

/* ---- USB identity (from usb_descriptors.c) ---- */
extern void bridge_usb_set_identity(const char *serial, bool radio_ok);

/* ---- BLE command protocol ---- */
#define BLE_CMD_STAGE    1u
#define BLE_CMD_CONFIRM  2u
#define BLE_CMD_CANCEL   3u
#define BLE_CMD_TICK     4u
#define BLE_CMD_NOISE    5u  /* authenticated Noise IK handshake */
#define BLE_CMD_ENCRYPTED 6u /* nonce64 || ciphertext || tag */
#define BLE_CMD_CONTROLLER_ADD 7u    /* role(1) || X25519 public key(32) */
#define BLE_CMD_CONTROLLER_REVOKE 8u /* target slot(1) */

#define BRIDGE_TTL_MS     BRIDGE_MAX_TTL_MS

#define BLE_CMD_MAX_LEN 20u
/* Accommodate a maximal bridge command plus encrypted transport framing. */
#define BLE_CMD_BUF_MAX (NOISE_IK_MAX_PLAINTEXT + 64u)

/* ---- BLE reassembly state ---- */
static uint8_t ble_cmd_buf[BLE_CMD_BUF_MAX];
static uint16_t ble_cmd_pos;
static bool ble_cmd_active;
static uint16_t cmd_char_handle;
static uint8_t cmd_char_read_data[BLE_CMD_BUF_MAX];
static uint16_t cmd_char_read_len;
static bool cmd_char_read_valid;

/* ---- Global state ---- */
static bridge_core_t core;
static controller_store_t controllers;
static uint32_t usb_now_ms;
static uint32_t ble_now_ms;
static bool cyw43_ok;

/* ---- USB HID keyboard ---- */
static uint8_t hid_leds;
static bool hid_idle_dirty;

uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id,
                               hid_report_type_t report_type,
                               uint8_t *buffer, uint16_t reqlen) {
    if (instance != 0 || report_id != 0) return 0;
    if (report_type == HID_REPORT_TYPE_INPUT) {
        uint16_t n = reqlen < 8 ? reqlen : 8;
        memset(buffer, 0, n);
        return n;
    }
    if (report_type == HID_REPORT_TYPE_OUTPUT && reqlen) {
        buffer[0] = hid_leds;
        return 1;
    }
    return 0;
}

void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id,
                           hid_report_type_t report_type,
                           uint8_t const *buffer, uint16_t size) {
    if (instance == 0 && report_id == 0 &&
        report_type == HID_REPORT_TYPE_OUTPUT && size == 1) {
        hid_leds = buffer[0] & 0x1f;
        hid_idle_dirty = true;
    }
}

void tud_hid_set_protocol_cb(uint8_t instance, uint8_t protocol) {
    (void)instance; (void)protocol;
    hid_idle_dirty = true;
}

bool tud_hid_set_idle_cb(uint8_t instance, uint8_t rate) {
    (void)instance; (void)rate;
    hid_idle_dirty = true;
    return true;
}

void tud_mount_cb(void) { hid_idle_dirty = true; }
void tud_umount_cb(void) { hid_idle_dirty = true; hid_leds = 0; }
void tud_suspend_cb(bool remote_wakeup_en) { (void)remote_wakeup_en; hid_idle_dirty = true; }
void tud_resume_cb(void) { hid_idle_dirty = true; }

/* ---- USB HID output: drain bridge_core_next → keyboard report ---- */
static void usb_hid_drain(void) {
    bridge_stroke_t stroke;
    while (tud_hid_ready()) {
        bridge_status_t st = bridge_core_next(&core, usb_now_ms, &stroke);
        if (st != BRIDGE_OK) break;
        if (stroke.usage != 0) {
            /* tud_hid_keyboard_report() takes modifier separately and a
             * six-byte keycode array.  Wait for the press IN transfer to
             * complete before queuing the all-zero release: TinyUSB rejects
             * a second report while the endpoint remains busy. */
            uint8_t keys[6] = {stroke.usage, 0, 0, 0, 0, 0};
            uint8_t released[6] = {0, 0, 0, 0, 0, 0};
            if (!tud_hid_keyboard_report(0, stroke.modifier, keys)) break;

            uint32_t deadline = usb_now_ms + 100;
            while (!tud_hid_ready() && usb_now_ms < deadline) {
                tud_task();
                watchdog_update();
                usb_now_ms = to_ms_since_boot(get_absolute_time());
            }
            if (!tud_hid_ready()) break;
            if (!tud_hid_keyboard_report(0, 0, released)) break;
        }
    }
}

/* ---- BLE command handler: decode packet → bridge_core API ---- */
/* Packet format:
 *   Stage:    cmd(1) | owner(4) | id(4) | layout(1) | mode(1) | flags(1) | utf8_len(2) | data(N)
 *   Confirm:  cmd(1) | owner(4) | id(4)
 *   Cancel:   cmd(1) | owner(4) | id(4)
 *   Tick:     cmd(1) | now_ms(4)
 */
static bridge_status_t ble_handle_stage(const uint8_t *p, uint16_t len) {
    if (len < 14) return BRIDGE_ERR_ARGUMENT;
    uint32_t owner = (uint32_t)(p[1] | p[2]<<8 | p[3]<<16 | p[4]<<24);
    uint32_t id = (uint32_t)(p[5] | p[6]<<8 | p[7]<<16 | p[8]<<24);
    bridge_layout_t layout = p[9] == 2 ? BRIDGE_LAYOUT_DE : BRIDGE_LAYOUT_US;
    bridge_mode_t mode = p[10] == 2 ? BRIDGE_MODE_TEXT : BRIDGE_MODE_PASSWORD;
    uint8_t flags = p[11];
    uint16_t ulen = (uint16_t)(p[12] | p[13]<<8);
    if (len < (uint16_t)(14 + ulen)) return BRIDGE_ERR_ARGUMENT;
    return bridge_core_stage(&core, owner, id, layout, mode, flags,
                             p + 14, ulen, ble_now_ms, BRIDGE_TTL_MS);
}

static bridge_status_t ble_handle_confirm(const uint8_t *p, uint16_t len) {
    if (len < 9) return BRIDGE_ERR_ARGUMENT;
    uint32_t owner = (uint32_t)(p[1] | p[2]<<8 | p[3]<<16 | p[4]<<24);
    uint32_t id = (uint32_t)(p[5] | p[6]<<8 | p[7]<<16 | p[8]<<24);
    return bridge_core_confirm(&core, owner, id, ble_now_ms);
}

static bridge_status_t ble_handle_cancel(const uint8_t *p, uint16_t len) {
    if (len < 9) return BRIDGE_ERR_ARGUMENT;
    uint32_t owner = (uint32_t)(p[1] | p[2]<<8 | p[3]<<16 | p[4]<<24);
    uint32_t id = (uint32_t)(p[5] | p[6]<<8 | p[7]<<16 | p[8]<<24);
    return bridge_core_cancel(&core, owner, id);
}

static bridge_status_t ble_handle_tick(const uint8_t *p, uint16_t len) {
    if (len < 5) return BRIDGE_ERR_ARGUMENT;
    uint32_t tick_now = (uint32_t)(p[1] | p[2]<<8 | p[3]<<16 | p[4]<<24);
    return bridge_core_tick(&core, tick_now);
}

static void ble_handle_noise(const uint8_t *p, uint16_t len) {
    size_t response_len = 0;
    cmd_char_read_valid = false;
    cmd_char_read_len = 0;
    if (len != (uint16_t)(1u + NOISE_IK_INIT_MESSAGE_LEN)) return;
    if (noise_ik_handshake_respond(p + 1, NOISE_IK_INIT_MESSAGE_LEN,
                                   cmd_char_read_data, sizeof(cmd_char_read_data),
                                   &response_len) == 0 &&
        response_len == NOISE_IK_RESPONSE_LEN) {
        cmd_char_read_len = (uint16_t)response_len;
        cmd_char_read_valid = true;
    }
}

static bridge_status_t ble_handle_controller_add(const uint8_t *p, uint16_t len) {
    if (len != 34u || !controller_store_is_admin(&controllers, noise_authenticated_slot())) return BRIDGE_ERR_OWNER;
    controller_role_t role = (controller_role_t)p[1];
    if (role != CONTROLLER_ROLE_OPERATOR && role != CONTROLLER_ROLE_ADMIN) return BRIDGE_ERR_ARGUMENT;
    controller_store_t candidate = controllers;
    controller_store_status_t status = controller_store_add(&candidate, noise_authenticated_slot(), p + 2, role, NULL);
    if (status != CONTROLLER_STORE_OK) return status == CONTROLLER_STORE_ERR_FULL ? BRIDGE_ERR_LIMIT : BRIDGE_ERR_ARGUMENT;
    if (controller_store_flash_commit(&candidate) != CONTROLLER_STORE_OK) return BRIDGE_ERR_STATE;
    controllers = candidate;
    return BRIDGE_OK;
}

static bridge_status_t ble_handle_controller_revoke(const uint8_t *p, uint16_t len) {
    if (len != 2u || !controller_store_is_admin(&controllers, noise_authenticated_slot())) return BRIDGE_ERR_OWNER;
    size_t target_slot = p[1];
    /* A controller cannot revoke its active session; it must use another admin.
     * This avoids a post-revocation authenticated command window. */
    if (target_slot == noise_authenticated_slot()) return BRIDGE_ERR_POLICY;
    controller_store_t candidate = controllers;
    controller_store_status_t status = controller_store_revoke(&candidate, noise_authenticated_slot(), target_slot);
    if (status == CONTROLLER_STORE_ERR_IMMUTABLE) return BRIDGE_ERR_POLICY;
    if (status != CONTROLLER_STORE_OK) return BRIDGE_ERR_ARGUMENT;
    if (controller_store_flash_commit(&candidate) != CONTROLLER_STORE_OK) return BRIDGE_ERR_STATE;
    controllers = candidate;
    return BRIDGE_OK;
}

static bridge_status_t ble_handle_authenticated_command(const uint8_t *data, uint16_t len) {
    if (len == 0) return BRIDGE_ERR_ARGUMENT;
    switch (data[0]) {
        case BLE_CMD_STAGE:   return ble_handle_stage(data, len);
        case BLE_CMD_CONFIRM: return ble_handle_confirm(data, len);
        case BLE_CMD_CANCEL:  return ble_handle_cancel(data, len);
        case BLE_CMD_TICK:    return ble_handle_tick(data, len);
        case BLE_CMD_CONTROLLER_ADD: return ble_handle_controller_add(data, len);
        case BLE_CMD_CONTROLLER_REVOKE: return ble_handle_controller_revoke(data, len);
        default: return BRIDGE_ERR_ARGUMENT;
    }
}

static void ble_handle_command(const uint8_t *data, uint16_t len) {
    if (len == 0) return;
    switch (data[0]) {
        case BLE_CMD_NOISE:
            ble_handle_noise(data, len);
            return;
        case BLE_CMD_ENCRYPTED: {
            uint8_t plaintext[NOISE_IK_MAX_PLAINTEXT];
            size_t plaintext_len = 0;
            size_t receipt_len = 0;
            cmd_char_read_valid = false;
            cmd_char_read_len = 0;
            if (len <= 1u || noise_decrypt_packet(data + 1, len - 1u,
                                                   plaintext, sizeof(plaintext),
                                                   &plaintext_len) != 0) return;
            bridge_status_t command_status = ble_handle_authenticated_command(
                plaintext, (uint16_t)plaintext_len);
            cmd_char_read_data[0] = BLE_CMD_ENCRYPTED;
            if (noise_encrypt_transport_ack((uint8_t)command_status,
                                            cmd_char_read_data + 1,
                                            sizeof(cmd_char_read_data) - 1u,
                                            &receipt_len) != 0) return;
            cmd_char_read_len = (uint16_t)(1u + receipt_len);
            cmd_char_read_valid = true;
            return;
        }
        /* Never pass plaintext command frames from the unauthenticated BLE link. */
        case BLE_CMD_STAGE:
        case BLE_CMD_CONFIRM:
        case BLE_CMD_CANCEL:
        case BLE_CMD_TICK:
        default:
            return;
    }
}

/* Fragment protocol for BLE write-without-response (MTU = 20 bytes):
 *   Bit 0 of fragment byte = MORE (set if more fragments follow)
 *   Bits 1-7 = sequence number (0 for first fragment)
 *
 * First fragment contains: cmd(1) | owner(4) | id(4) | layout(1) | mode(1) | flags(1) | utf8_len(2) | data(N)
 * Continuation fragments: raw data bytes
 * Last fragment: ends the reassembled packet */
#define BLE_FRAG_MORE   0x01u

/* Read callback: returns the authenticated Noise response after a successful handshake. */
static uint16_t read_callback(hci_con_handle_t con_handle,
                              uint16_t attribute_handle,
                              uint16_t offset,
                              uint8_t *buffer, uint16_t buffer_size) {
    (void)con_handle;
    if (attribute_handle == cmd_char_handle && cmd_char_read_valid) {
        /* BTstack first queries the complete dynamic value size with buffer == NULL. */
        if (buffer == NULL) return cmd_char_read_len;
        if (offset >= cmd_char_read_len) return 0;
        uint16_t remain = cmd_char_read_len - offset;
        uint16_t n = buffer_size < remain ? buffer_size : remain;
        memcpy(buffer, cmd_char_read_data + offset, n);
        return n;
    }
    return 0;
}

static int cmd_write_callback(hci_con_handle_t con_handle,
                              uint16_t attribute_handle,
                              uint16_t transaction_mode,
                              uint16_t offset,
                              uint8_t *buffer, uint16_t buffer_size) {
    (void)con_handle; (void)attribute_handle; (void)transaction_mode;
    (void)offset;

    if (buffer_size < 1) return 0;

    uint8_t frag_hdr = buffer[0];
    bool more = (frag_hdr & BLE_FRAG_MORE) != 0;
    uint8_t seq = frag_hdr >> 1;
    uint16_t data_len = buffer_size - 1;  /* subtract fragment header byte */
    uint8_t *data = buffer + 1;

    /* Start of new command? */
    if (seq == 0) {
        /* First fragment — reset reassembly */
        if (data_len < 1) goto err;  /* need at least cmd byte */
        ble_cmd_active = true;
        ble_cmd_pos = 0;
        /* Copy fragment header for internal tracking — skip it */
    } else if (!ble_cmd_active) {
        /* Continuation or end of a packet without a start — discard */
        return 0;
    }

    /* Accumulate data into reassembly buffer */
    if ((uint32_t)(ble_cmd_pos + data_len) > BLE_CMD_BUF_MAX) goto err;
    memcpy(ble_cmd_buf + ble_cmd_pos, data, data_len);
    ble_cmd_pos += (uint16_t)data_len;

    if (!more) {
        /* End of packet — process the complete command */
        ble_handle_command(ble_cmd_buf, ble_cmd_pos);
        ble_cmd_active = false;
        ble_cmd_pos = 0;
    }

    return 0;

err:
    ble_cmd_active = false;
    ble_cmd_pos = 0;
    return 0;
}

/* ---- BLE setup ---- */
static void ble_event_handler(uint8_t packet_type, uint16_t event, uint8_t *data, uint16_t size);

static void ble_setup(void) {
    if (!cyw43_ok) return;

    /* Initialize BTstack via the Pico SDK cyw43 bridge */
    btstack_cyw43_init(cyw43_arch_async_context());

    /* Load device identity and the already boot-validated controller store. */
    if (noise_ik_init(&controllers) != 0) return;

    /* Initialize L2CAP, Security Manager, ATT Server, GATT Client */
    l2cap_init();
    sm_init();

    /* Build ATT database with a custom command service */
    att_db_util_init();
    /* Command service UUID: 6e400001-b9a9-8132-8f32-0a9e1b8c7d4e */
    static const uint8_t cmd_service_uuid128[] = {
        0x6e, 0x40, 0x00, 0x01, 0xb9, 0xa9, 0x81, 0x32,
        0x8f, 0x32, 0x0a, 0x9e, 0x1b, 0x8c, 0x7d, 0x4e
    };
    att_db_util_add_service_uuid128(cmd_service_uuid128);
    /* Command characteristic UUID: 6e400002-b9a9-8132-8f32-0a9e1b8c7d4e */
    static const uint8_t cmd_char_uuid128[] = {
        0x6e, 0x40, 0x00, 0x02, 0xb9, 0xa9, 0x81, 0x32,
        0x8f, 0x32, 0x0a, 0x9e, 0x1b, 0x8c, 0x7d, 0x4e
    };
    static uint8_t cmd_char_data[BLE_CMD_BUF_MAX];
    cmd_char_handle = att_db_util_add_characteristic_uuid128(
        cmd_char_uuid128,
        ATT_PROPERTY_WRITE_WITHOUT_RESPONSE | ATT_PROPERTY_READ | ATT_PROPERTY_DYNAMIC,
        ATT_SECURITY_NONE,
        ATT_SECURITY_NONE,
        cmd_char_data, BLE_CMD_BUF_MAX);

    /* Initialize ATT server with the built database */
    att_server_init(att_db_util_get_address(), read_callback, cmd_write_callback);

    /* Set up advertising */
    gatt_client_init();
    uint8_t adv_data[31];
    int pos = 0;
    /* Flags: general discoverable, BR/EDR not supported */
    adv_data[pos++] = 0x02; adv_data[pos++] = 0x01; adv_data[pos++] = 0x06;
    /* Complete local name */
    const char *name = "PicoBridge";
    int name_len = (int)strlen(name);
    adv_data[pos++] = (uint8_t)(name_len + 1);
    adv_data[pos++] = 0x09;  /* Complete Local Name */
    for (int i = 0; i < name_len && pos < (int)sizeof(adv_data); i++) {
        adv_data[pos++] = (uint8_t)name[i];
    }
    gap_advertisements_set_data(pos, adv_data);
    /* BTstack's default advertising interval is 0x0800 (1.28 s) — far too
     * slow for interactive use: the central's page scan can wait several
     * intervals before seeing us, making every connect take 6-25 s.
     * 40 ms keeps discovery/page latency low at negligible power cost for
     * a USB-powered device. */
    bd_addr_t any_addr = {0};
    /* adv_type 0x00 = ADV_TYPE_CONNECTABLE_UNDIRECTED (constant absent in
     * this BTstack revision's headers) — same as BTstack's own default. */
    gap_advertisements_set_params(0x0040, 0x0040, 0x00,
                                  0, any_addr, 0x07, 0x00);
    gap_advertisements_enable(1);

    /* Watch for disconnections so advertising can be re-armed below */
    static btstack_packet_callback_registration_t ble_event_reg;
    ble_event_reg.callback = ble_event_handler;
    hci_add_event_handler(&ble_event_reg);

    /* Power on BLE */
    hci_power_control(HCI_POWER_ON);
}

/* BTstack's CYW43 advertiser does not reliably restart advertising after a
 * central disconnects, and even where enable(1) works it can lag ~20 s.
 * Set a flag in the HCI callback (no timers there) and let the main loop
 * force-restart via disable+enable — that deterministically re-arms the
 * advertiser within one loop pass. gap_advertisements_enable is idempotent,
 * so skipping the restart while still connected is safe. */
static volatile bool readvertise_needed = false;
static uint32_t readvertise_disable_ms = 0;

static void ble_event_handler(uint8_t packet_type, uint16_t event, uint8_t *data, uint16_t size) {
    (void)packet_type; (void)data; (void)size;
    if (event == HCI_EVENT_DISCONNECTION_COMPLETE) {
        readvertise_needed = true;
    }
}

/* Called from the main loop: force advertising back on ~100ms after a
 * disconnect. BlueZ page attempts last several seconds, so being visible
 * again fast is what cuts the next connect from ~20s to ~1-2s. */
static void ble_readvertise_poll(uint32_t now_ms) {
    if (!readvertise_needed) return;
    if (readvertise_disable_ms == 0) {
        gap_advertisements_enable(0);
        readvertise_disable_ms = now_ms + 100;
        return;
    }
    if ((int32_t)(now_ms - readvertise_disable_ms) < 0) return;
    gap_advertisements_enable(1);
    readvertise_disable_ms = 0;
    readvertise_needed = false;
}

/* The first multi-controller boot seeds the immutable recovery admin, then
 * imports the existing single-controller identity as a normal admin so a
 * firmware upgrade never locks out CachyOS. Later boots never auto-add keys. */
static bool controller_setup(void) {
    if (controller_store_flash_boot_or_seed(&controllers, PICO_BRIDGE_RECOVERY_ADMIN_PUBLIC) != CONTROLLER_STORE_OK) {
        return false;
    }
    bool empty_daily_slots = true;
    for (size_t i = 1; i < CONTROLLER_STORE_SLOT_COUNT; ++i) {
        if (controllers.slots[i].role != CONTROLLER_ROLE_NONE) empty_daily_slots = false;
    }
    if (controllers.generation == 1u && empty_daily_slots) {
        if (controller_store_add(&controllers, 0u, PICO_BRIDGE_AUTHORIZED_INITIATOR_PUBLIC,
                                 CONTROLLER_ROLE_ADMIN, NULL) != CONTROLLER_STORE_OK ||
            controller_store_flash_commit(&controllers) != CONTROLLER_STORE_OK) {
            return false;
        }
    }
    return true;
}

/* ---- Main ---- */
int main(void) {
    char serial[2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1];
    pico_get_unique_board_id_string(serial, sizeof(serial));

    /* Initialize cyw43 (status LED + BLE transport) */
    int cyw_result = cyw43_arch_init();
    cyw43_ok = (cyw_result == 0);
    bridge_usb_set_identity(serial, cyw43_ok);

    /* Initialize bridge core */
    bridge_core_init(&core);
    if (!controller_setup()) return 1;

    /* Initialize USB */
    tusb_rhport_init_t tusb_init_cfg = {
        .role = TUSB_ROLE_DEVICE,
        .speed = TUSB_SPEED_FULL
    };
    if (!tusb_init(0, &tusb_init_cfg)) return 1;
    hid_idle_dirty = true;

    /* Initialize BLE */
    if (cyw43_ok) {
        ble_setup();
    }

    /* Watchdog: 30s timeout (BLE needs time to initialize) */
    watchdog_enable(30000, true);

    uint32_t last_led_ms = 0;
    bool led_on = false;
    uint32_t last_usb_drain_ms = 0;

    while (true) {
        /* USB task — TinyUSB polling */
        tud_task();

        usb_now_ms = to_ms_since_boot(get_absolute_time());
        ble_now_ms = usb_now_ms;

        /* Drain USB HID output every 5ms */
        if ((uint32_t)(usb_now_ms - last_usb_drain_ms) >= 5) {
            usb_hid_drain();
            last_usb_drain_ms = usb_now_ms;
        }

        /* Process bridge TTL expiry */
        bridge_core_tick(&core, usb_now_ms);

        /* BLE run loop — pumps BTstack via async context */
        if (cyw43_ok) {
            async_context_poll(cyw43_arch_async_context());
            ble_readvertise_poll(usb_now_ms);
        }

        /* LED indicator */
        if (cyw43_ok && (uint32_t)(usb_now_ms - last_led_ms) >= 500) {
            led_on = !led_on;
            cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, led_on);
            last_led_ms = usb_now_ms;
        }

        watchdog_update();
        tight_loop_contents();
    }
}
