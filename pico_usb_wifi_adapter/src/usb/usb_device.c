// usb_device.c - TinyUSB vendor bulk transport for Pico W USB WiFi Adapter
//
// RX: poll & drain tud_vendor_read() into pwusb_transport_rx_write()
// TX: pop framed messages from g_txq and stream out via tud_vendor_write()
//     with bounded batching so USB gets a bit more throughput without starving
//     the rest of the single-core main loop.

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "msg_queue.h"
#include "pwusb_debug.h"
#include "pwusb_transport.h"
#include "tusb.h"

// Expose TX queue to main/transport producer
extern msg_queue_t g_txq;

// ---------- USB descriptors ----------
#define USB_VID 0xCAFE
#define USB_PID 0x4001
#define USB_BCD 0x0100

enum {
    ITF_NUM_VENDOR = 0,
    ITF_NUM_TOTAL
};

#define EPNUM_VENDOR_OUT 0x01
#define EPNUM_VENDOR_IN  0x81

// ---------- Tunables ----------
#ifndef USB_RX_CHUNK
#define USB_RX_CHUNK 2048
#endif

#ifndef USB_TX_MAX_MSG
#define USB_TX_MAX_MSG 2048
#endif

#ifndef USB_TX_SPIN_LIMIT
#define USB_TX_SPIN_LIMIT 32
#endif

// Bounded TX work per call.
// Keep this moderate so USB gets more done per loop, but Wi-Fi polling still
// gets CPU time on single-core firmware.
#ifndef USB_TX_BUDGET_BYTES
#define USB_TX_BUDGET_BYTES 8192
#endif

#ifndef USB_TX_BUDGET_MSGS
#define USB_TX_BUDGET_MSGS 16
#endif

// ---------- Device descriptor ----------
tusb_desc_device_t const desc_device = {
    .bLength            = sizeof(tusb_desc_device_t),
    .bDescriptorType    = TUSB_DESC_DEVICE,
    .bcdUSB             = 0x0200,
    .bDeviceClass       = 0x00,
    .bDeviceSubClass    = 0x00,
    .bDeviceProtocol    = 0x00,
    .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor           = USB_VID,
    .idProduct          = USB_PID,
    .bcdDevice          = USB_BCD,
    .iManufacturer      = 0x01,
    .iProduct           = 0x02,
    .iSerialNumber      = 0x03,
    .bNumConfigurations = 0x01
};

uint8_t const* tud_descriptor_device_cb(void) {
    return (uint8_t const*)&desc_device;
}

// ---------- Configuration descriptor ----------
#define CONFIG_TOTAL_LEN (TUD_CONFIG_DESC_LEN + TUD_VENDOR_DESC_LEN)

uint8_t const desc_configuration[] = {
    TUD_CONFIG_DESCRIPTOR(1, ITF_NUM_TOTAL, 0, CONFIG_TOTAL_LEN, 0x00, 100),
    TUD_VENDOR_DESCRIPTOR(ITF_NUM_VENDOR, 4, EPNUM_VENDOR_OUT, EPNUM_VENDOR_IN, 64)
};

uint8_t const* tud_descriptor_configuration_cb(uint8_t index) {
    (void)index;
    return desc_configuration;
}

// ---------- String descriptors ----------
char const* string_desc_arr[] = {
    (const char[]){0x09, 0x04},  // 0: English (0x0409)
    "HCMUS",                     // 1: Manufacturer
    "PicoW USB WiFi Adapter",    // 2: Product
    "0001",                      // 3: Serial
    "Vendor Interface",          // 4: Interface string
};

static uint16_t _desc_str[32];

uint16_t const* tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
    (void)langid;

    uint8_t chr_count;

    if (index == 0) {
        memcpy(&_desc_str[1], string_desc_arr[0], 2);
        chr_count = 1;
    } else {
        uint32_t count = (uint32_t)(sizeof(string_desc_arr) / sizeof(string_desc_arr[0]));
        if (index >= count) return NULL;

        const char* str = string_desc_arr[index];
        chr_count = (uint8_t)strlen(str);
        if (chr_count > 31) chr_count = 31;

        for (uint8_t i = 0; i < chr_count; i++) {
            _desc_str[1 + i] = (uint16_t)str[i];
        }
    }

    _desc_str[0] = (TUSB_DESC_STRING << 8) | (2 * chr_count + 2);
    return _desc_str;
}

// ---------- Vendor callbacks ----------
void tud_vendor_rx_cb(uint8_t itf, uint8_t const* buffer, uint16_t bufsize) {
    (void)itf;
    (void)buffer;
    (void)bufsize;
}

// ---------- RX path ----------
void usb_device_poll_rx(void) {
    if (!tud_mounted()) return;

    static uint8_t buf[USB_RX_CHUNK];

    while (tud_vendor_available()) {
        uint32_t n = tud_vendor_read(buf, sizeof(buf));
        if (n == 0) break;
        pwusb_transport_rx_write(buf, (uint16_t)n);
    }
}

// ---------- TX path state ----------
static uint8_t  s_tx_cur[USB_TX_MAX_MSG];
static uint16_t s_tx_cur_len = 0;
static uint16_t s_tx_cur_off = 0;

static void usb_tx_reset_state(void) {
    s_tx_cur_len = 0;
    s_tx_cur_off = 0;
}

void usb_device_try_tx(void) {
    if (!tud_mounted()) {
        usb_tx_reset_state();
        return;
    }

    bool wrote_any = false;
    uint32_t sent_bytes_this_call = 0;
    uint32_t sent_msgs_this_call = 0;
    int spin = 0;

    while (sent_bytes_this_call < USB_TX_BUDGET_BYTES &&
           sent_msgs_this_call < USB_TX_BUDGET_MSGS) {

        if (s_tx_cur_len == 0) {
            uint16_t len = 0;
            if (!mq_pop(&g_txq, s_tx_cur, &len)) {
                break; // queue empty
            }
            if (len == 0) {
                continue;
            }
            if (len > USB_TX_MAX_MSG) {
                PWUSB_WARN("usb_device_try_tx: message too large (%u > %u), drop\n",
                           (unsigned)len, (unsigned)USB_TX_MAX_MSG);
                continue;
            }

            s_tx_cur_len = len;
            s_tx_cur_off = 0;
        }

        while (s_tx_cur_off < s_tx_cur_len) {
            uint32_t avail = tud_vendor_write_available();
            if (avail == 0) {
                if (++spin >= USB_TX_SPIN_LIMIT) {
                    goto done;
                }
                goto done;
            }

            uint32_t remain = (uint32_t)(s_tx_cur_len - s_tx_cur_off);
            uint32_t chunk = remain;
            if (chunk > avail) chunk = avail;

            uint32_t w = tud_vendor_write(s_tx_cur + s_tx_cur_off, chunk);
            if (w == 0) {
                goto done;
            }

            s_tx_cur_off += (uint16_t)w;
            sent_bytes_this_call += w;
            wrote_any = true;

            if (sent_bytes_this_call >= USB_TX_BUDGET_BYTES) {
                goto done;
            }
        }

        if (s_tx_cur_off >= s_tx_cur_len) {
            usb_tx_reset_state();
            sent_msgs_this_call++;
        }
    }

done:
    if (wrote_any) {
        tud_vendor_flush();
    }
}
