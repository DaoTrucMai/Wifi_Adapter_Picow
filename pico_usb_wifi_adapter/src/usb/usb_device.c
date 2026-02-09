#include <stdio.h>
#include <string.h>

#include "msg_queue.h"
#include "pwusb_debug.h"
#include "pwusb_transport.h"
#include "tusb.h"

// Expose TX queue to main
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
#define EPNUM_VENDOR_IN 0x81

tusb_desc_device_t const desc_device = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = 0x0200,
    .bDeviceClass = 0x00,
    .bDeviceSubClass = 0x00,
    .bDeviceProtocol = 0x00,
    .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor = USB_VID,
    .idProduct = USB_PID,
    .bcdDevice = USB_BCD,
    .iManufacturer = 0x01,
    .iProduct = 0x02,
    .iSerialNumber = 0x03,
    .bNumConfigurations = 0x01};

uint8_t const* tud_descriptor_device_cb(void) {
    return (uint8_t const*)&desc_device;
}

#define CONFIG_TOTAL_LEN (TUD_CONFIG_DESC_LEN + TUD_VENDOR_DESC_LEN)

uint8_t const desc_configuration[] = {
    // Config
    TUD_CONFIG_DESCRIPTOR(1, ITF_NUM_TOTAL, 0, CONFIG_TOTAL_LEN,
                          0x00, 100),

    // Vendor interface with bulk IN/OUT
    TUD_VENDOR_DESCRIPTOR(ITF_NUM_VENDOR, 4,
                          EPNUM_VENDOR_OUT,
                          EPNUM_VENDOR_IN, 64)};

uint8_t const* tud_descriptor_configuration_cb(uint8_t index) {
    (void)index;
    return desc_configuration;
}

// Strings
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
        if (index >= sizeof(string_desc_arr) / sizeof(string_desc_arr[0])) return NULL;
        const char* str = string_desc_arr[index];
        chr_count = (uint8_t)strlen(str);
        if (chr_count > 31) chr_count = 31;
        for (uint8_t i = 0; i < chr_count; i++) _desc_str[1 + i] = str[i];
    }

    _desc_str[0] = (TUSB_DESC_STRING << 8) | (2 * chr_count + 2);
    return _desc_str;
}

// ---------- Vendor callbacks ----------
// We use polling via tud_vendor_read() in usb_device_poll_rx() to reliably drain
// TinyUSB's internal FIFO. Leaving the callback empty avoids extra work in IRQ context.
void tud_vendor_rx_cb(uint8_t itf, uint8_t const* buffer, uint16_t bufsize) {
    (void)itf;
    (void)buffer;
    (void)bufsize;
}

void usb_device_poll_rx(void) {
#if PWUSB_USB_DEBUG
    static uint32_t big_dbg;
    static uint32_t hdr_dbg;
    static uint32_t chunk_dbg;
#endif

    if (!tud_vendor_mounted()) return;

    uint8_t buf[CFG_TUD_VENDOR_RX_BUFSIZE];
    uint32_t n;
    uint32_t loops = 0;

    // Drain a bounded amount per main-loop iteration to avoid starving other work.
    while (loops++ < 32 && (n = tud_vendor_read(buf, sizeof(buf))) > 0) {
#if PWUSB_USB_DEBUG
        if (chunk_dbg < 40) {
            printf("USB OUT rd chunk len=%lu\n", (unsigned long)n);
            chunk_dbg++;
        }
        if (n >= 256 && big_dbg < 10) {
            printf("USB OUT rd chunk (large) len=%lu\n", (unsigned long)n);
            big_dbg++;
        }
        if (n >= 16 &&
            buf[0] == 0x50 && buf[1] == 0x48 && buf[2] == 0x54 && buf[3] == 0x4d &&
            hdr_dbg < 10) {
            uint16_t plen = (uint16_t)((uint16_t)buf[10] | ((uint16_t)buf[11] << 8));
            printf("USB OUT hdr magic=PHTM type=0x%02x plen=%u total=%u\n",
                   buf[5], plen, (unsigned)(16 + plen));
            hdr_dbg++;
        }
#endif

        pwusb_transport_rx_write(buf, (size_t)n);
    }
}

// Optional: called when IN is available; we will also send from main loop
void usb_device_try_tx(void) {
    if (!tud_vendor_mounted()) return;

    // TinyUSB vendor TX has a finite FIFO (CFG_TUD_VENDOR_TX_BUFSIZE). Messages can be
    // larger than that (e.g. DHCP OFFER ~ 16 + 590 bytes), so we must stream them.
    static uint8_t cur[MQ_MAX_MSG];
    static uint16_t cur_len = 0;
    static uint16_t cur_off = 0;

    while (true) {
        uint32_t avail = tud_vendor_write_available();
        if (!avail) return;

        if (cur_len == 0) {
            if (!mq_pop(&g_txq, cur, &cur_len)) return;
            cur_off = 0;
        }

        uint32_t remaining = (uint32_t)cur_len - (uint32_t)cur_off;
        uint32_t to_write = remaining < avail ? remaining : avail;
        uint32_t wrote = tud_vendor_write(cur + cur_off, (uint16_t)to_write);
        if (!wrote) return;
        cur_off = (uint16_t)(cur_off + (uint16_t)wrote);
        tud_vendor_flush();

        if (cur_off >= cur_len) {
            cur_len = 0;
            cur_off = 0;
        }
    }
}
