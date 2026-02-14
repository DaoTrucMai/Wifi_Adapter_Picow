// usb_device.c - TinyUSB vendor bulk transport for Pico W USB WiFi Adapter
//
// RX: poll & drain tud_vendor_read() into pwusb_transport_rx_write()
// TX: pop framed messages from g_txq and stream out via tud_vendor_write()
//     with safe chunking + reduced busy-wait + sensible flushing.

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
// Size of a chunk used for draining RX FIFO from TinyUSB
#ifndef USB_RX_CHUNK
#define USB_RX_CHUNK 512
#endif

// Max message size that can be popped from msg_queue.
// IMPORTANT: must be >= your largest framed message (e.g. Ethernet frame packet).
// If your project already defines a constant for this, replace the value below.
#ifndef USB_TX_MAX_MSG
#define USB_TX_MAX_MSG 2048
#endif

// Optional: avoid spinning too hard when IN FIFO full
#ifndef USB_TX_SPIN_LIMIT
#define USB_TX_SPIN_LIMIT 8
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
    // Config: bmAttributes=0x00 (bus powered), MaxPower=100 (200 mA units = 2mA)
    TUD_CONFIG_DESCRIPTOR(1, ITF_NUM_TOTAL, 0, CONFIG_TOTAL_LEN, 0x00, 100),

    // Vendor interface with bulk IN/OUT, EP size 64 (FS)
    TUD_VENDOR_DESCRIPTOR(ITF_NUM_VENDOR, 4, EPNUM_VENDOR_OUT, EPNUM_VENDOR_IN, 64)
};

uint8_t const* tud_descriptor_configuration_cb(uint8_t index) {
    (void)index;
    return desc_configuration;
}

// ---------- String descriptors ----------
char const* string_desc_arr[] = {
    (const char[]){0x09, 0x04},  // 0: English (0x0409)
    "MyUniversity",              // 1: Manufacturer
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
// We do polling in usb_device_poll_rx() to drain FIFO reliably.
// Keep callback empty to avoid heavy work in ISR/USB context.
void tud_vendor_rx_cb(uint8_t itf, uint8_t const* buffer, uint16_t bufsize) {
    (void)itf;
    (void)buffer;
    (void)bufsize;
}

// ---------- RX path ----------
void usb_device_poll_rx(void) {
    if (!tud_mounted()) return;

    static uint8_t buf[USB_RX_CHUNK];

    // Drain everything available from TinyUSB vendor RX FIFO
    while (tud_vendor_available()) {
        uint32_t n = tud_vendor_read(buf, sizeof(buf));
        if (n == 0) break;

        // Feed bytes to transport layer (stream reassembly/parser handles framing)
        pwusb_transport_rx_write(buf, (uint16_t)n);
    }
}

// ---------- TX path state (kept local to this file) ----------
static uint8_t  s_tx_cur[USB_TX_MAX_MSG];
static uint16_t s_tx_cur_len = 0;
static uint16_t s_tx_cur_off = 0;

static void usb_tx_reset_state(void) {
    s_tx_cur_len = 0;
    s_tx_cur_off = 0;
}

// ---------- TX function ----------
void usb_device_try_tx(void) {
    if (!tud_mounted()) {
        // If USB got unplugged/unmounted, reset state to avoid "stuck message"
        usb_tx_reset_state();
        return;
    }

    // If no current message in-flight, pop a new one from TX queue
    if (s_tx_cur_len == 0) {
        uint16_t len = 0;
        if (!mq_pop(&g_txq, s_tx_cur, &len)) {
            return; // nothing to send
        }
        if (len == 0) {
            return;
        }
        if (len > USB_TX_MAX_MSG) {
            // Should never happen if queue is configured correctly
            PWUSB_WARN("usb_device_try_tx: message too large (%u > %u), drop\n",
                       (unsigned)len, (unsigned)USB_TX_MAX_MSG);
            return;
        }

        s_tx_cur_len = len;
        s_tx_cur_off = 0;
    }

    bool wrote_any = false;
    int spin = 0;

    // Stream out as much as possible this call, but avoid infinite spinning
    while (s_tx_cur_off < s_tx_cur_len) {
        uint32_t avail = tud_vendor_write_available();
        if (avail == 0) {
            // Avoid burning CPU; give up this round
            if (++spin >= USB_TX_SPIN_LIMIT) break;
            break;
        }

        uint32_t remain = (uint32_t)(s_tx_cur_len - s_tx_cur_off);
        uint32_t chunk  = remain;
        if (chunk > avail) chunk = avail;

        uint32_t w = tud_vendor_write(s_tx_cur + s_tx_cur_off, chunk);
        if (w == 0) {
            // Could not write now; stop and retry later
            break;
        }

        s_tx_cur_off += (uint16_t)w;
        wrote_any = true;
    }

    // Low-latency safe behavior: flush whenever we wrote any bytes this round.
    // This avoids partial-frame stalls when host IN availability is small.
    if (wrote_any)
        tud_vendor_flush();

    // If finished sending the whole message, clear state so next call pops new msg
    if (s_tx_cur_off >= s_tx_cur_len) {
        usb_tx_reset_state();
    }
}
