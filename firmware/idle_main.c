/* Safe hardware bring-up image. All keyboard reports are zero; no command input. */
#include <string.h>
#include "pico/stdlib.h"
#include "pico/unique_id.h"
#include "pico/cyw43_arch.h"
#include "hardware/watchdog.h"
#include "tusb.h"

void bridge_usb_set_identity(const char *serial, bool radio_ok);
static uint8_t leds;
static uint8_t idle_rate;
static bool report_sent;
static uint32_t last_report_ms;

uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id,
                             hid_report_type_t report_type, uint8_t *buffer,
                             uint16_t reqlen) {
    if (instance != 0 || report_id != 0) return 0;
    if (report_type == HID_REPORT_TYPE_INPUT) {
        uint16_t n = reqlen < 8 ? reqlen : 8;
        memset(buffer, 0, n);
        return n;
    }
    if (report_type == HID_REPORT_TYPE_OUTPUT && reqlen) {
        buffer[0] = leds;
        return 1;
    }
    return 0;
}
void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id,
                          hid_report_type_t report_type, const uint8_t *buffer,
                          uint16_t size) {
    if (instance == 0 && report_id == 0 && report_type == HID_REPORT_TYPE_OUTPUT && size == 1)
        leds = buffer[0] & 0x1f;
}
void tud_hid_set_protocol_cb(uint8_t instance, uint8_t protocol) {
    (void)instance; (void)protocol;
    report_sent = false;
}
bool tud_hid_set_idle_cb(uint8_t instance, uint8_t rate) {
    if (instance != 0) return false;
    idle_rate = rate;
    report_sent = false;
    return true;
}
void tud_mount_cb(void) { report_sent = false; }
void tud_umount_cb(void) { report_sent = false; leds = 0; idle_rate = 0; }
void tud_suspend_cb(bool remote_wakeup_en) { (void)remote_wakeup_en; report_sent = false; }
void tud_resume_cb(void) { report_sent = false; }

int main(void) {
    char serial[2*PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1];
    pico_get_unique_board_id_string(serial, sizeof(serial));
    bool radio_ok = cyw43_arch_init() == 0;
    bridge_usb_set_identity(serial, radio_ok);
    tusb_rhport_init_t init = {.role = TUSB_ROLE_DEVICE, .speed = TUSB_SPEED_FULL};
    if (!tusb_init(0, &init)) return 1;
    watchdog_enable(8000, true);
    uint32_t last_led_ms = 0;
    bool led_on = false;
    while (true) {
        tud_task();
        uint32_t now = to_ms_since_boot(get_absolute_time());
        if (tud_hid_ready() && (!report_sent ||
            (idle_rate && (uint32_t)(now - last_report_ms) >= 4u * idle_rate))) {
            const uint8_t keys[6] = {0};
            if (tud_hid_keyboard_report(0, 0, keys)) {
                report_sent = true;
                last_report_ms = now;
            }
        }
        if (radio_ok && (uint32_t)(now - last_led_ms) >= 500) {
            led_on = !led_on;
            cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, led_on);
            last_led_ms = now;
        }
        watchdog_update();
        tight_loop_contents();
    }
}
