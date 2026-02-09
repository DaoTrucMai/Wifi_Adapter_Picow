#include <stdbool.h>
#include <string.h>

#include "msg_queue.h"
#include "pwusb_proto.h"
#include "ringbuf.h"
#include "hardware/sync.h"

static ringbuf_t g_rx_rb;
static uint8_t g_rx_storage[16384];
static uint32_t g_drop_bytes;
static uint32_t g_drop_events;
static uint32_t g_resync_bytes;

void pwusb_transport_init(void) {
    ringbuf_init(&g_rx_rb, g_rx_storage, sizeof(g_rx_storage));
    g_drop_bytes = 0;
    g_drop_events = 0;
    g_resync_bytes = 0;
}

size_t pwusb_transport_rx_write(const uint8_t* data, size_t n) {
    uint32_t irq_state = save_and_disable_interrupts();
    size_t wrote = ringbuf_write(&g_rx_rb, data, n);
    if (wrote != n) {
        g_drop_bytes += (uint32_t)(n - wrote);
        g_drop_events++;
        // Drop buffered data to recover framing quickly.
        g_rx_rb.r = g_rx_rb.w = g_rx_rb.len = 0;
        wrote = ringbuf_write(&g_rx_rb, data, n);
    }
    restore_interrupts(irq_state);
    return wrote;
}

// Try to extract one complete message into out buffer.
// Returns true if a full message was produced.
bool pwusb_transport_try_get_msg(uint8_t* out, uint16_t* out_len) {
    uint32_t irq_state = save_and_disable_interrupts();
    pwusb_hdr_t hdr;
    if (ringbuf_available(&g_rx_rb) < sizeof(hdr)) {
        restore_interrupts(irq_state);
        return false;
    }

    if (!ringbuf_peek(&g_rx_rb, 0, (uint8_t*)&hdr, sizeof(hdr))) {
        restore_interrupts(irq_state);
        return false;
    }

    // resync if magic mismatch
    if (hdr.magic != PWUSB_MAGIC || hdr.version != PWUSB_VERSION || hdr.hdr_len != sizeof(pwusb_hdr_t)) {
        uint8_t junk;
        ringbuf_read(&g_rx_rb, &junk, 1);
        g_resync_bytes++;
        restore_interrupts(irq_state);
        return false;
    }

    uint32_t total = (uint32_t)hdr.hdr_len + (uint32_t)hdr.payload_len;
    if (total > MQ_MAX_MSG) {
        // drop one byte to resync
        uint8_t junk;
        ringbuf_read(&g_rx_rb, &junk, 1);
        g_resync_bytes++;
        restore_interrupts(irq_state);
        return false;
    }

    if (ringbuf_available(&g_rx_rb) < total) {
        restore_interrupts(irq_state);
        return false;
    }

    ringbuf_read(&g_rx_rb, out, total);
    *out_len = (uint16_t)total;
    restore_interrupts(irq_state);
    return true;
}

void pwusb_transport_get_and_clear_stats(uint32_t* drop_bytes,
                                         uint32_t* drop_events,
                                         uint32_t* resync_bytes) {
    if (drop_bytes) *drop_bytes = g_drop_bytes;
    if (drop_events) *drop_events = g_drop_events;
    if (resync_bytes) *resync_bytes = g_resync_bytes;
    g_drop_bytes = 0;
    g_drop_events = 0;
    g_resync_bytes = 0;
}
