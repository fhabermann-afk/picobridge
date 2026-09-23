#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

static char serial_string[33] = "UNSET";
static const char *product_string = "PicoBridge idle / CYW43 FAIL";

void bridge_usb_set_identity(const char *serial, bool radio_ok) {
    size_t n = 0;
    if (serial) {
        while (n < sizeof(serial_string) - 1 && serial[n]) {
            serial_string[n] = serial[n];
            n++;
        }
    }
    serial_string[n] = 0;
    product_string = radio_ok ? "PicoBridge idle / CYW43 OK" : "PicoBridge idle / CYW43 FAIL";
}

const uint16_t *tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
    static uint16_t buffer[64];
    if (index == 0) {
        buffer[0] = 0x0304;
        buffer[1] = 0x0409;
        return buffer;
    }
    if (langid != 0x0409) return NULL;
    const char *s;
    switch (index) {
        case 1: s = "Local PicoBridge prototype"; break;
        case 2: s = product_string; break;
        case 3: s = serial_string; break;
        default: return NULL;
    }
    size_t n = 0;
    while (n < 63 && s[n]) {
        buffer[n + 1] = (uint8_t)s[n];
        n++;
    }
    buffer[0] = (uint16_t)(0x0300 | (2*n + 2));
    return buffer;
}

/* Development-only VID/PID from TinyUSB's test namespace, not a registered product. */
static const uint8_t device[] = {
    18, 1, 0x00, 0x02, 0, 0, 0, 64,
    0xfe, 0xca, 0x10, 0x40, 0x01, 0x00, 1, 2, 3, 1
};
static const uint8_t keyboard_report[] = {
    0x05,0x01, 0x09,0x06, 0xa1,0x01,
    0x05,0x07, 0x19,0xe0, 0x29,0xe7, 0x15,0x00, 0x25,0x01,
    0x75,0x01, 0x95,0x08, 0x81,0x02,
    0x95,0x01, 0x75,0x08, 0x81,0x01,
    0x95,0x05, 0x75,0x01, 0x05,0x08, 0x19,0x01, 0x29,0x05, 0x91,0x02,
    0x95,0x01, 0x75,0x03, 0x91,0x01,
    0x95,0x06, 0x75,0x08, 0x15,0x00, 0x25,0x65,
    0x05,0x07, 0x19,0x00, 0x29,0x65, 0x81,0x00, 0xc0
};
static const uint8_t configuration[] = {
    9,2,34,0,1,1,0,0x80,250,
    9,4,0,0,1,3,1,1,0,
    9,0x21,0x11,0x01,0,1,0x22,sizeof(keyboard_report),0,
    7,5,0x81,3,8,0,10
};
const uint8_t *tud_descriptor_device_cb(void) { return device; }
const uint8_t *tud_descriptor_configuration_cb(uint8_t index) {
    return index == 0 ? configuration : NULL;
}
const uint8_t *tud_hid_descriptor_report_cb(uint8_t instance) {
    return instance == 0 ? keyboard_report : NULL;
}
