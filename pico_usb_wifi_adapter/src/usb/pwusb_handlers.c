#include "pwusb_handlers.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "msg_queue.h"
#include "pwusb_debug.h"
#include "pwusb_perf.h"
#include "pwusb_proto.h"
#include "wifi_mgr.h"
#include "cyw43.h"

// ============================================================
// Helpers
// ============================================================

static bool enqueue_msg(msg_queue_t* txq, uint16_t seq, uint8_t msg_type, const void* payload, uint16_t payload_len) {
    pwusb_hdr_t h;
    h.magic = PWUSB_MAGIC;
    h.version = PWUSB_VERSION;
    h.msg_type = msg_type;
    h.flags = 0;
    h.hdr_len = sizeof(pwusb_hdr_t);
    h.seq = seq;
    h.payload_len = payload_len;
    h.xid = 0;

    if (payload_len > MQ_MAX_MSG - sizeof(pwusb_hdr_t)) {
        return false;
    }

    return mq_push2(txq, &h, (uint16_t)sizeof(h), payload, payload_len);
}

static bool enqueue_empty(msg_queue_t* txq, uint16_t seq, uint8_t msg_type) {
    return enqueue_msg(txq, seq, msg_type, NULL, 0);
}

static bool enqueue_error(msg_queue_t* txq, uint16_t seq, int32_t code) {
    phtm_error_evt_t e;
    memset(&e, 0, sizeof(e));
    e.code = code;
    return enqueue_msg(txq, seq, PWUSB_EVT_ERROR, &e, (uint16_t)sizeof(e));
}

static bool valid_len(uint16_t len, uint16_t need) {
    return len >= need;
}

typedef struct __attribute__((packed)) {
    uint16_t dev_max_payload;
    uint16_t dev_tx_queue_depth;
    uint32_t dev_caps;
    uint8_t mac[6];
    uint8_t reserved[2];
} phtm_hello_rsp_t;

// ============================================================
// Benchmark state
// ============================================================

static volatile bool g_bench_src_running = false;   // device -> host
static volatile bool g_bench_sink_running = false;  // host -> device
static uint16_t g_bench_plen = 0;
static uint32_t g_bench_seq = 0;

// Small scratch buffer for generated benchmark messages.
// total message <= dev_max_total ~= 2048 in your host stats, so keep <= MQ_MAX_MSG.
static uint8_t g_bench_msg[MQ_MAX_MSG];

bool pwusb_bench_is_active(void) {
    return g_bench_src_running || g_bench_sink_running;
}

// Generate PWUSB_DATA_BENCH_SRC messages continuously while source benchmark runs.
void pwusb_bench_poll(msg_queue_t* txq) {
    if (!g_bench_src_running) {
        return;
    }

    uint16_t max_payload = (uint16_t)(MQ_MAX_MSG - sizeof(pwusb_hdr_t));
    uint16_t plen = g_bench_plen;
    if (plen > max_payload) {
        plen = max_payload;
    }

    pwusb_hdr_t* h = (pwusb_hdr_t*)g_bench_msg;
    uint8_t* p = g_bench_msg + sizeof(pwusb_hdr_t);

    // Build one benchmark source message
    h->magic = PWUSB_MAGIC;
    h->version = PWUSB_VERSION;
    h->msg_type = PWUSB_DATA_BENCH_SRC;
    h->flags = 0;
    h->hdr_len = sizeof(pwusb_hdr_t);
    h->seq = (uint16_t)g_bench_seq;
    h->payload_len = plen;
    h->xid = 0;

    // Put a sequence number at the start to make payload deterministic/useful
    if (plen >= 4) {
        uint32_t seq = g_bench_seq++;
        memcpy(p, &seq, sizeof(seq));
        for (uint16_t i = 4; i < plen; i++) {
            p[i] = (uint8_t)(i + seq);
        }
    } else {
        for (uint16_t i = 0; i < plen; i++) {
            p[i] = (uint8_t)(i + g_bench_seq);
        }
        g_bench_seq++;
    }

    // If queue is full, do not block; just try again next loop.
    (void)mq_push(txq, g_bench_msg, (uint16_t)(sizeof(pwusb_hdr_t) + plen));
}

// ============================================================
// Main dispatcher
// ============================================================

void pwusb_handle_one(msg_queue_t* txq, const uint8_t* msg, uint16_t len) {
    if (!valid_len(len, (uint16_t)sizeof(pwusb_hdr_t))) {
        (void)enqueue_error(txq, 0, -1);
        return;
    }

    const pwusb_hdr_t* h = (const pwusb_hdr_t*)msg;
    const uint8_t* payload = msg + sizeof(pwusb_hdr_t);
    uint16_t payload_len = (uint16_t)(len - sizeof(pwusb_hdr_t));

    if (h->magic != PWUSB_MAGIC) {
        (void)enqueue_error(txq, h->seq, -2);
        return;
    }

    if (h->payload_len != payload_len) {
        (void)enqueue_error(txq, h->seq, -3);
        return;
    }

    switch (h->msg_type) {
        // ----------------------------------------------------
        // Control plane
        // ----------------------------------------------------
        case PWUSB_HELLO: {
            phtm_hello_rsp_t rsp = {0};
            rsp.dev_max_payload = MQ_MAX_MSG;
            rsp.dev_tx_queue_depth = MQ_DEPTH;
            rsp.dev_caps = 0;
            cyw43_wifi_get_mac(&cyw43_state, CYW43_ITF_STA, rsp.mac);
            (void)enqueue_msg(txq, h->seq, PWUSB_HELLO_RSP, &rsp, (uint16_t)sizeof(rsp));
            break;
        }

        case PWUSB_CMD_SCAN_START: {
            if (!wifi_mgr_scan_start(txq, h->seq)) {
                (void)enqueue_error(txq, h->seq, -4);
            }
            break;
        }

        case PWUSB_CMD_CONNECT: {
            if (!valid_len(payload_len, 2)) {
                (void)enqueue_error(txq, h->seq, -5);
                break;
            }

            char ssid[33] = {0};
            char pass[65] = {0};
            uint8_t ssid_len;
            uint8_t psk_len;
            uint8_t key_type;
            const uint8_t* ssid_src;
            const uint8_t* psk_src;

            if (payload_len == (uint16_t)sizeof(phtm_connect_req_t)) {
                const phtm_connect_req_t* req = (const phtm_connect_req_t*)payload;
                ssid_len = req->ssid_len;
                psk_len = req->psk_len;
                key_type = req->key_type;
                ssid_src = req->ssid;
                psk_src = req->psk;
            } else if (payload_len >= 3) {
                uint16_t need_new;
                ssid_len = payload[0];
                key_type = payload[1];
                psk_len = payload[2];
                need_new = (uint16_t)(3 + ssid_len + psk_len);
                if (payload_len == need_new) {
                    ssid_src = payload + 3;
                    psk_src = payload + 3 + ssid_len;
                } else {
                    // Legacy format: [ssid_len][psk_len][ssid...][psk...]
                    // used by older host drivers before explicit key_type.
                    uint8_t legacy_psk_len = payload[1];
                    uint16_t need_old = (uint16_t)(2 + ssid_len + legacy_psk_len);
                    if (payload_len != need_old) {
                        (void)enqueue_error(txq, h->seq, -5);
                        break;
                    }
                    psk_len = legacy_psk_len;
                    key_type = (psk_len > 0) ? PWUSB_KEY_PASSPHRASE : PWUSB_KEY_NONE;
                    ssid_src = payload + 2;
                    psk_src = payload + 2 + ssid_len;
                }
            } else {
                // payload_len == 2 legacy header only; no room for SSID payload.
                (void)enqueue_error(txq, h->seq, -5);
                break;
            }

            if (ssid_len == 0 || ssid_len > 32 || psk_len > 64 || key_type > PWUSB_KEY_PMK) {
                (void)enqueue_error(txq, h->seq, -5);
                break;
            }

            memcpy(ssid, ssid_src, ssid_len);
            if (psk_len) {
                memcpy(pass, psk_src, psk_len);
            }

            int rc = wifi_mgr_connect(txq, h->seq,
                                     ssid, ssid_len,
                                     pass, psk_len,
                                     key_type);
            // wifi_mgr_connect sends PWUSB_EVT_CONN_STATE with status, so no need for additional error here
            (void)rc; // Suppress unused variable warning
            break;
        }

        case PWUSB_CMD_DISCONNECT: {
            int rc = wifi_mgr_disconnect(txq, h->seq);
            // wifi_mgr_disconnect sends PWUSB_EVT_CONN_STATE with status, so no need for additional error here
            (void)rc; // Suppress unused variable warning
            break;
        }

        case PWUSB_CMD_GET_STATUS: {
            wifi_mgr_get_status(txq, h->seq);
            break;
        }

        // ----------------------------------------------------
        // Raw USB benchmark control plane
        // ----------------------------------------------------
        case PWUSB_CMD_BENCH_START: {
            if (!valid_len(payload_len, (uint16_t)sizeof(phtm_bench_start_req_t))) {
                (void)enqueue_error(txq, h->seq, -5);
                break;
            }

            const phtm_bench_start_req_t* req = (const phtm_bench_start_req_t*)payload;
            uint16_t plen = req->payload_len;
            uint16_t max_payload = (uint16_t)(MQ_MAX_MSG - sizeof(pwusb_hdr_t));

            if (plen == 0 || plen > max_payload) {
                (void)enqueue_error(txq, h->seq, -6);
                break;
            }

            g_bench_plen = plen;
            g_bench_seq = 0;

            // Define direction exactly as host driver expects:
            // 1 = IN  (device -> host)
            // 2 = OUT (host -> device sink)
            // 3 = BOTH
            switch (req->dir) {
                case 1:
                    g_bench_src_running = true;
                    g_bench_sink_running = false;
                    break;
                case 2:
                    g_bench_src_running = false;
                    g_bench_sink_running = true;
                    break;
                case 3:
                    g_bench_src_running = true;
                    g_bench_sink_running = true;
                    break;
                default:
                    (void)enqueue_error(txq, h->seq, -7);
                    break;
            }

            break;
        }

        case PWUSB_CMD_BENCH_STOP: {
            g_bench_src_running = false;
            g_bench_sink_running = false;
            g_bench_plen = 0;
            break;
        }

        // ----------------------------------------------------
        // Data plane
        // ----------------------------------------------------
        case PWUSB_DATA_BENCH_SINK: {
            // Host -> device benchmark payload.
            // Do not route to Wi-Fi. Just accept it while sink benchmark is active.
            if (g_bench_sink_running) {
                // Intentionally do nothing. Host driver already counts bus-side bytes.
            }
            break;
        }

        case PWUSB_DATA_TX_ETH: {
            // Normal Ethernet TX from host -> Pico Wi-Fi
            if (payload_len == 0) {
                break;
            }
            if (!wifi_mgr_send_ethernet(payload, payload_len)) {
                (void)enqueue_error(txq, h->seq, -9);
            }
            break;
        }

        default:
            (void)enqueue_error(txq, h->seq, -8);
            break;
    }
}
