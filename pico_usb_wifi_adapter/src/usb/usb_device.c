#include <stdio.h>
#include <string.h>

#include "pico/time.h"

#include "msg_queue.h"
#include "pwusb_debug.h"
#include "pwusb_perf.h"
#include "pwusb_proto.h"
#include "pwusb_transport.h"
#include "usb.h"
#include "usb_config.h"
/* Provides the stable interface used by main() regardless of USB stack. */
#include "usb_backend.h"

// Expose TX queue to main
extern msg_queue_t g_txq;

// ---------- USB benchmark (device -> host) ----------
// Enabled/controlled by host via PWUSB_CMD_BENCH_START/STOP.
static volatile bool g_bench_src_enabled;
static volatile uint16_t g_bench_src_plen;
static uint16_t g_bench_src_seq;

// Host->device benchmark sink mode. When enabled, we fast-drop BENCH_SINK
// messages at the USB ingress to avoid extra copies and ringbuf contention.
static volatile bool g_bench_sink_enabled;

void usb_device_try_tx(void);

void usb_device_bench_set_src(bool enable, uint16_t payload_len) {
    uint16_t max_plen = (uint16_t)(MQ_MAX_MSG - sizeof(pwusb_hdr_t));
    if (payload_len > max_plen)
        payload_len = max_plen;
    g_bench_src_plen = payload_len;
    g_bench_src_enabled = enable;

    // BENCH_START may arrive while the outbound queue is empty. Kick the first
    // IN transfer immediately so device->host benchmarking does not depend on a
    // later main-loop iteration or unrelated traffic to get started.
    if (enable && payload_len && usb_is_configured()) {
        usb_device_try_tx();
    }
}

void usb_device_bench_set_sink(bool enable) {
    g_bench_sink_enabled = enable;
}

/*
 * USB backend API (usb_library_rp2040 implementation)
 *
 * These wrappers let us keep a stable call surface for the rest of the
 * firmware. A TinyUSB backend can provide the same functions in a different
 * compilation unit later.
 */
void usb_device_poll_rx(void);
void usb_backend_init(void) {
    usb_device_init();
}

void usb_backend_poll_rx(void) {
    usb_device_poll_rx();
}

void usb_backend_try_tx(void) {
    usb_device_try_tx();
}

void usb_backend_bench_set_src(bool enable, uint16_t payload_len) {
    usb_device_bench_set_src(enable, payload_len);
}

void usb_backend_bench_set_sink(bool enable) {
    usb_device_bench_set_sink(enable);
}

// ---------- USB device handlers (usb_library_rp2040) ----------
// Prototypes required by usb_config.h.
void control_transfer_handler(uint8_t* buf, volatile struct usb_setup_packet* pkt, uint8_t stage);
void ep1_out_handler(uint8_t* buf, uint16_t len);
void ep2_in_handler(uint8_t* buf, uint16_t len);

// Bulk endpoints used by the kernel driver.
static struct usb_endpoint_configuration* g_ep_out;
static struct usb_endpoint_configuration* g_ep_in;
static bool g_out_active;
static volatile bool g_in_active;
static uint64_t g_in_submit_us;
static bool g_in_tail_valid;
static uint8_t g_in_tail_byte;

enum {
    // Debug-only aid (when PWUSB_USB_DEBUG=1). Don't cancel transfers based on
    // this; host-side backpressure can legitimately keep IN BUSY.
    USB_IN_STALL_TIMEOUT_US = 2000000, // 2s
};

enum {
    /*
     * Normal traffic is latency-sensitive and often bursty. If an IN transfer
     * ends on an exact max-packet boundary (Full-Speed bulk maxpkt=64), some
     * hosts can keep the read URB pending until a short packet/ZLP arrives.
     *
     * Our usb_library backend has ZLP handling, but keeping the normal staging
     * size *not* divisible by 64 avoids that edge case entirely and improves
     * "responsive" feel even if a ZLP is missed.
     */
    // Keep it not divisible by 64 to avoid the "needs ZLP" edge case on FS bulk.
    // 16352 % 64 = 32.
    USB_IN_STAGE_NORMAL_MAX = 16352,
    // In full-duplex bench mode, don't let device->host IN monopolize the
    // Full-Speed bus with giant transfers. A modest burst preserves good IN
    // throughput while giving host->device OUT enough scheduling opportunity.
    USB_IN_STAGE_BENCH_BOTH_MAX = 8192,
    // Normal host->device traffic comes in <= PICO_USB_TX_BUF_SIZE (4096) on
    // the kernel driver side. Keeping this modest helps latency.
    USB_OUT_STAGE_NORMAL = 4096,
};
extern uint8_t g_usb_in_buf[USB_IN_BUF_SIZE];

static void usb_device_sniff_bench_ctrl(const uint8_t* buf, uint16_t len) {
    // Robustly detect BENCH_START/STOP even if the control message is split
    // across multiple EP1 OUT callbacks.
    enum {
        MAGIC0 = 0x50, // 'P'
        MAGIC1 = 0x48, // 'H'
        MAGIC2 = 0x54, // 'T'
        MAGIC3 = 0x4d, // 'M'
    };
    static uint8_t hdr[sizeof(pwusb_hdr_t)];
    static uint8_t hdr_have;
    static uint16_t payload_left;
    static uint8_t bench_msg_type;
    static uint8_t bench_payload[3];
    static uint8_t bench_payload_have;

    const uint8_t* p = buf;
    uint16_t left = len;

    while (left) {
        uint8_t b = *p++;
        left--;

        if (payload_left) {
            if (bench_msg_type == PWUSB_CMD_BENCH_START && bench_payload_have < sizeof(bench_payload)) {
                bench_payload[bench_payload_have++] = b;
            }
            payload_left--;
            if (!payload_left) {
                if (bench_msg_type == PWUSB_CMD_BENCH_START && bench_payload_have >= 3) {
                    uint8_t dir = bench_payload[0];
                    uint16_t plen = (uint16_t)((uint16_t)bench_payload[1] | ((uint16_t)bench_payload[2] << 8));
                    // Treat BENCH_START as authoritative mode selection, not additive.
                    // This avoids leaving the bench source enabled when the host
                    // switches to sink-only (OUT) benchmarking.
                    usb_device_bench_set_src(false, 0);
                    usb_device_bench_set_sink(false);
                    if (dir & 0x01)
                        usb_device_bench_set_src(true, plen);
                    if (dir & 0x02)
                        usb_device_bench_set_sink(true);
                } else if (bench_msg_type == PWUSB_CMD_BENCH_STOP) {
                    usb_device_bench_set_src(false, 0);
                    usb_device_bench_set_sink(false);
                }
                hdr_have = 0;
                bench_msg_type = 0;
                bench_payload_have = 0;
            }
            continue;
        }

        // Match magic progressively (resync-friendly).
        if (hdr_have < 4) {
            if (hdr_have == 0) {
                if (b != MAGIC0)
                    continue;
                hdr[hdr_have++] = b;
                continue;
            }
            if ((hdr_have == 1 && b != MAGIC1) ||
                (hdr_have == 2 && b != MAGIC2) ||
                (hdr_have == 3 && b != MAGIC3)) {
                hdr_have = (b == MAGIC0) ? 1 : 0;
                if (hdr_have)
                    hdr[0] = b;
                continue;
            }
            hdr[hdr_have++] = b;
            continue;
        }

        hdr[hdr_have++] = b;
        if (hdr_have < sizeof(hdr))
            continue;

        // Full header.
        const pwusb_hdr_t* h = (const pwusb_hdr_t*)hdr;
        if (h->magic != PWUSB_MAGIC ||
            h->version != PWUSB_VERSION ||
            h->hdr_len != sizeof(pwusb_hdr_t) ||
            ((uint16_t)h->hdr_len + h->payload_len) > MQ_MAX_MSG) {
            hdr_have = 0;
            continue;
        }

        bench_msg_type = h->msg_type;
        payload_left = h->payload_len;
        bench_payload_have = 0;

        if (!payload_left) {
            // BENCH_STOP has no payload.
            if (bench_msg_type == PWUSB_CMD_BENCH_STOP) {
                usb_device_bench_set_src(false, 0);
                usb_device_bench_set_sink(false);
            }
            hdr_have = 0;
            bench_msg_type = 0;
            bench_payload_have = 0;
        }
    }
}

static void usb_device_handle_out_chunk_bench(const uint8_t* buf, uint16_t n) {
    // Stream parser state for fast dropping BENCH_SINK frames while still
    // forwarding control messages (e.g. BENCH_STOP) into the normal transport.
    enum {
        ST_HDR = 0,
        ST_DROP_PAYLOAD,
        ST_PASS_PAYLOAD,
    };
    static uint8_t hdr[sizeof(pwusb_hdr_t)];
    static uint16_t hdr_have;
    static uint16_t payload_left;
    static uint8_t st;

    const uint8_t* p = buf;
    uint32_t left = n;

    while (left) {
        if (st == ST_DROP_PAYLOAD) {
            if (!payload_left) {
                st = ST_HDR;
                hdr_have = 0;
                continue;
            }
            uint16_t take = payload_left;
            if (take > left) take = (uint16_t)left;
            payload_left = (uint16_t)(payload_left - take);
            p += take;
            left -= take;
            if (!payload_left) {
                st = ST_HDR;
                hdr_have = 0;
            }
            continue;
        }

        if (st == ST_PASS_PAYLOAD) {
            if (!payload_left) {
                st = ST_HDR;
                hdr_have = 0;
                continue;
            }
            uint16_t take = payload_left;
            if (take > left) take = (uint16_t)left;
            pwusb_transport_rx_write(p, (size_t)take);
            payload_left = (uint16_t)(payload_left - take);
            p += take;
            left -= take;
            if (!payload_left) {
                st = ST_HDR;
                hdr_have = 0;
            }
            continue;
        }

        // ST_HDR
        {
            uint16_t need = (uint16_t)(sizeof(hdr) - hdr_have);
            uint16_t take = need;
            if (take > left) take = (uint16_t)left;
            memcpy(hdr + hdr_have, p, take);
            hdr_have = (uint16_t)(hdr_have + take);
            p += take;
            left -= take;

            if (hdr_have < sizeof(hdr))
                continue;

            // Full header received; decide what to do with payload.
            const pwusb_hdr_t* h = (const pwusb_hdr_t*)hdr;
            uint16_t total = (uint16_t)(h->hdr_len + h->payload_len);

            // If header is invalid, fall back to the normal transport by
            // forwarding the bytes we have; transport will resync.
            if (h->magic != PWUSB_MAGIC ||
                h->version != PWUSB_VERSION ||
                h->hdr_len != sizeof(pwusb_hdr_t) ||
                total > MQ_MAX_MSG) {
                pwusb_transport_rx_write(hdr, sizeof(hdr));
                st = ST_PASS_PAYLOAD;
                payload_left = 0;
                hdr_have = 0;
                continue;
            }

            payload_left = h->payload_len;

            if (g_bench_sink_enabled && h->msg_type == PWUSB_DATA_BENCH_SINK) {
                // Drop sink payload entirely (and do not enqueue header).
                if (payload_left) {
                    st = ST_DROP_PAYLOAD;
                } else {
                    st = ST_HDR;
                    hdr_have = 0;
                }
            } else {
                // Forward message into normal transport.
                pwusb_transport_rx_write(hdr, sizeof(hdr));
                if (payload_left) {
                    st = ST_PASS_PAYLOAD;
                } else {
                    st = ST_HDR;
                    hdr_have = 0;
                }
            }

            hdr_have = 0;
        }
    }
}

static bool usb_device_maybe_exit_bench_sink(const uint8_t* buf, uint16_t len) {
    // If the host starts sending normal traffic while bench sink mode is still
    // enabled, we'd otherwise drop everything and "brick" the control plane.
    // Try to find a valid header in the current chunk and disable sink if it
    // is not BENCH_SINK.
    //
    // Keep the scan bounded so it doesn't impact steady-state benchmark rate.
    const uint16_t scan_max = (len < 256) ? len : 256;
    for (uint16_t i = 0; i + sizeof(pwusb_hdr_t) <= scan_max; i++) {
        if (buf[i + 0] != 'P' || buf[i + 1] != 'H' || buf[i + 2] != 'T' || buf[i + 3] != 'M')
            continue;

        pwusb_hdr_t h;
        memcpy(&h, buf + i, sizeof(h));
        uint16_t total = (uint16_t)(h.hdr_len + h.payload_len);
        if (h.magic != PWUSB_MAGIC ||
            h.version != PWUSB_VERSION ||
            h.hdr_len != sizeof(pwusb_hdr_t) ||
            total > MQ_MAX_MSG) {
            continue;
        }

        if (h.msg_type == PWUSB_DATA_BENCH_SINK) {
            // Still bench sink payload; keep dropping.
            return false;
        }

        // Switch back to normal OUT handling and forward whatever we have from
        // the detected header onward (transport can resync further if needed).
        //
        // Important: do not disable the device->host source here. In "both"
        // mode the source and sink are intentionally active together, and a
        // non-BENCH_SINK control message on OUT should only end fast-drop sink
        // mode, not kill the IN benchmark stream.
        usb_device_bench_set_sink(false);
        pwusb_transport_rx_write(buf + i, (size_t)(len - i));
        return true;
    }
    return false;
}

void usb_device_poll_rx(void) {
    if (!usb_is_configured()) {
        g_out_active = false;
        return;
    }

    if (!g_ep_out)
        g_ep_out = usb_get_endpoint_configuration(EP1_OUT_ADDR);

    if (!g_ep_out)
        return;

    // Be tolerant of library-side resets/reinitialization: our g_out_active can
    // get out of sync with the endpoint state. If the endpoint isn't BUSY,
    // re-arm it.
    if (!g_out_active || usb_is_transfer_completed(g_ep_out) || g_ep_out->status != STATUS_BUSY) {
        /*
         * EP1 OUT is configured as a streaming endpoint (data_buffer==NULL),
         * so the handler runs per max-packet chunk. Keep the transfer length
         * unknown so OUT behaves like a continuous stream.
         */
        int32_t xfer_len = -1;
        (void)g_bench_sink_enabled;
        usb_init_transfer(g_ep_out, xfer_len);
        g_out_active = true;
    }
}

// Optional: called when IN is available; we will also send from main loop
void usb_device_try_tx(void) {
    if (!usb_is_configured()) {
        g_in_active = false;
        return;
    }

    if (!g_ep_in)
        g_ep_in = usb_get_endpoint_configuration(EP2_IN_ADDR);

    if (!g_ep_in)
        return;

    if (g_in_active) {
        if (!usb_is_transfer_completed(g_ep_in)) {
            pwusb_perf_usb_in_blocked();
            if (PWUSB_USB_DEBUG) {
                uint64_t now = time_us_64();
                if (g_in_submit_us && (now - g_in_submit_us) > USB_IN_STALL_TIMEOUT_US) {
                    // Debug aid: prolonged BUSY usually means the host isn't
                    // polling IN fast enough (backpressure). Don't cancel
                    // here; dropping bytes will corrupt the stream framing on
                    // the host.
                    printf("USB IN stuck: status=%u len=%lu pos=%lu pos_send=%lu\n",
                           (unsigned)g_ep_in->status,
                           (unsigned long)g_ep_in->length,
                           (unsigned long)g_ep_in->pos,
                           (unsigned long)g_ep_in->pos_send);
                    // Rate-limit prints.
                    g_in_submit_us = now;
                }
            }
            return;
        }
        g_in_active = false;
        g_in_submit_us = 0;
    }

    // Build one transfer into the endpoint buffer. For bench mode, fill as much
    // as possible to reduce Full-Speed bulk scheduling overhead.
    size_t cap = USB_IN_BUF_SIZE;
    size_t target;
    size_t out = 0;
    static uint8_t msg[MQ_MAX_MSG];
    uint16_t msg_len = 0;
    uint16_t maxpkt = 64;

    if (g_ep_in->descriptor && g_ep_in->descriptor->wMaxPacketSize)
        maxpkt = g_ep_in->descriptor->wMaxPacketSize;

    if (g_bench_src_enabled) {
        if (g_bench_sink_enabled)
            target = USB_IN_STAGE_BENCH_BOTH_MAX;
        else
            target = cap;
    } else {
        target = USB_IN_STAGE_NORMAL_MAX;
    }

    // Carry-over tail byte to avoid maxpkt-aligned transfer lengths (see below).
    if (!g_bench_src_enabled && g_in_tail_valid) {
        g_usb_in_buf[out++] = g_in_tail_byte;
        g_in_tail_valid = false;
    }

    while (out < cap) {
        if (mq_pop(&g_txq, msg, &msg_len)) {
            pwusb_perf_txq_pop_ok();
            if (msg_len > cap - out)
                break;
            memcpy(g_usb_in_buf + out, msg, msg_len);
            out += msg_len;
            if (!g_bench_src_enabled && out >= target)
                break;
            continue;
        }

        pwusb_perf_txq_pop_empty();
        if (!g_bench_src_enabled || g_bench_src_plen == 0)
            break;

        uint16_t frame_len = (uint16_t)(sizeof(pwusb_hdr_t) + g_bench_src_plen);
        if (frame_len == 0 || frame_len > MQ_MAX_MSG)
            break;
        if (out + frame_len > cap)
            break;

        pwusb_hdr_t hdr = {
            .magic = PWUSB_MAGIC,
            .version = PWUSB_VERSION,
            .msg_type = PWUSB_DATA_BENCH_SRC,
            .flags = 0,
            .hdr_len = sizeof(pwusb_hdr_t),
            .seq = g_bench_src_seq++,
            .payload_len = g_bench_src_plen,
            .xid = 0,
        };
        memcpy(g_usb_in_buf + out, &hdr, sizeof(hdr));
        memset(g_usb_in_buf + out + sizeof(hdr), 0xA5, g_bench_src_plen);
        out += frame_len;
        if (out >= target)
            break;
    }

    if (out == 0) {
        return;
    }

    /*
     * FS bulk-IN quirk: if a transfer ends exactly on a max-packet boundary,
     * some hosts wait for a short packet/ZLP before completing the read URB.
     * To make the data plane robust, ensure we never submit lengths divisible
     * by maxpkt (without altering the byte stream).
     */
    if (!g_bench_src_enabled && maxpkt && (out % maxpkt) == 0) {
        g_in_tail_byte = g_usb_in_buf[out - 1];
        g_in_tail_valid = true;
        out--;
        if (out == 0) {
            // Only had 1 byte to send; defer until we can combine with more.
            return;
        }
    }

    usb_init_transfer(g_ep_in, (int32_t)out);
    g_in_active = true;
    g_in_submit_us = time_us_64();
    pwusb_perf_usb_in_write(out);
    pwusb_perf_usb_in_flush();
}

void control_transfer_handler(uint8_t* buf, volatile struct usb_setup_packet* pkt, uint8_t stage) {
    (void)buf;
    (void)pkt;
    (void)stage;
}

void ep1_out_handler(uint8_t* buf, uint16_t len) {
    if (PWUSB_USB_DEBUG) {
        static uint32_t out_dbg;
        if (out_dbg < 20) {
            if (len >= sizeof(pwusb_hdr_t)) {
                pwusb_hdr_t h;
                memcpy(&h, buf, sizeof(h));
                if (h.magic == PWUSB_MAGIC && h.version == PWUSB_VERSION && h.hdr_len == sizeof(pwusb_hdr_t)) {
                    printf("USB OUT: type=0x%02x seq=%u plen=%u len=%u\n",
                           (unsigned)h.msg_type, (unsigned)h.seq,
                           (unsigned)h.payload_len, (unsigned)len);
                    out_dbg++;
                } else {
                    printf("USB OUT: len=%u (no header)\n", (unsigned)len);
                    out_dbg++;
                }
            } else {
                printf("USB OUT: len=%u (short)\n", (unsigned)len);
                out_dbg++;
            }
        }
    }

    if (g_bench_sink_enabled) {
        // Bench sink mode: drop everything fast. The host is sending only
        // PWUSB_DATA_BENCH_SINK frames, and parsing in IRQ context is expensive
        // enough to stall the OUT pipe. Use the bounded exit parser here so a
        // later STOP/control message can still pull us back to normal mode.
        if (!usb_device_maybe_exit_bench_sink(buf, len)) {
            (void)buf;
            (void)len;
        }
    } else {
        // Detect BENCH_START/STOP even if split across multiple OUT callbacks.
        usb_device_sniff_bench_ctrl(buf, len);

        // Normal mode: forward bytes to the stream framer.
        pwusb_transport_rx_write(buf, (size_t)len);
    }

    // For bench sink mode, re-arm OUT in IRQ context so the host's 32KB URBs
    // don't stall waiting for the main loop.
    //
    // For normal traffic, re-arming from the main loop avoids any risk of
    // re-entrancy while higher-level parsers are running.
    if (g_bench_sink_enabled && usb_is_configured()) {
        if (!g_ep_out)
            g_ep_out = usb_get_endpoint_configuration(EP1_OUT_ADDR);
        if (g_ep_out) {
            usb_init_transfer(g_ep_out, (int32_t)USB_OUT_BUF_SIZE);
            g_out_active = true;
        }
    }
}

void ep2_in_handler(uint8_t* buf, uint16_t len) {
    if (!len)
        return;
    // Buffered mode: called at end of transfer.
    (void)buf;
    (void)len;

    // Keep bulk IN saturated during benchmarks and under queue backlog by
    // immediately submitting the next transfer when the previous one completes.
    //
    // Exception: when bench source and sink are both active, defer re-submit to
    // the main loop so OUT processing gets a chance to run between IN bursts.
    if ((g_bench_src_enabled && !g_bench_sink_enabled) || !mq_is_empty(&g_txq)) {
        usb_device_try_tx();
    }
}
