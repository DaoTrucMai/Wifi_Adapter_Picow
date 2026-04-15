#include "wifi_mgr.h"
#include "pwusb_perf.h"

#include <stdio.h>
#include <string.h>

#include "cyw43.h"
#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"
#include "pwusb_debug.h"
#include "pwusb_proto.h"

static msg_queue_t* g_txq = NULL;
static uint16_t g_scan_seq = 0;
static bool g_scan_in_progress = false;
static bool g_scan_done_sent = false;
static absolute_time_t g_scan_deadline = {0};
static bool g_connected = false;
static uint8_t g_ssid_len = 0;
static uint8_t g_ssid[32] = {0};
static uint8_t g_psk_len = 0;
static uint8_t g_psk[64] = {0};
static uint8_t g_key_type = PWUSB_KEY_NONE;
static bool g_conn_in_progress = false;
static bool g_conn_done_sent = false;
static uint16_t g_conn_seq = 0;
static absolute_time_t g_conn_deadline = {0};
static uint8_t g_conn_bssid[6] = {0};
static uint8_t g_conn_channel = 0;
static int8_t g_conn_rssi = 0;

#define SCAN_DONE_TIMEOUT_MS 6000
#define CONNECT_TIMEOUT_MS 15000
#define WIFI_SCAN_MAX_RESULTS 32

// Debug override: hardcode credentials for bring-up
#define DEBUG_WIFI_CREDENTIALS 0
#define DEBUG_WIFI_SSID "YOUR_SSID"
#define DEBUG_WIFI_PSK "YOUR_PASSWORD"

static bool parse_dhcp4(const uint8_t* frame, uint16_t len,
                        uint16_t* sport, uint16_t* dport,
                        uint8_t sip[4], uint8_t dip[4]) {
    uint16_t et;
    uint8_t ihl;
    uint16_t udp_off;

    if (!frame || len < 14 + 20 + 8) return false;

    et = (uint16_t)((uint16_t)frame[12] << 8 | frame[13]);
    if (et != 0x0800) return false;

    if ((frame[14] >> 4) != 4) return false;
    ihl = (uint8_t)((frame[14] & 0x0f) * 4);
    if (ihl < 20) return false;
    if (len < (uint16_t)(14 + ihl + 8)) return false;
    if (frame[23] != 17) return false;  // UDP

    memcpy(sip, frame + 26, 4);
    memcpy(dip, frame + 30, 4);

    udp_off = (uint16_t)(14 + ihl);
    *sport = (uint16_t)((uint16_t)frame[udp_off + 0] << 8 | frame[udp_off + 1]);
    *dport = (uint16_t)((uint16_t)frame[udp_off + 2] << 8 | frame[udp_off + 3]);
    if (!((*sport == 68 && *dport == 67) || (*sport == 67 && *dport == 68)))
        return false;

    return true;
}

// helper: build and enqueue a message
static void enqueue_msg(uint8_t type, uint16_t seq, const void* payload, uint16_t plen) {
    uint8_t buf[16 + MQ_MAX_MSG];
    if (plen > (MQ_MAX_MSG - sizeof(pwusb_hdr_t))) return;
    if (!g_txq) return;

    pwusb_hdr_t hdr = {
        .magic = PWUSB_MAGIC,
        .version = PWUSB_VERSION,
        .msg_type = type,
        .flags = 0,
        .hdr_len = sizeof(pwusb_hdr_t),
        .seq = seq,
        .payload_len = plen,
        .xid = 0};

    memcpy(buf, &hdr, sizeof(hdr));
    if (plen && payload) memcpy(buf + sizeof(hdr), payload, plen);

    mq_push(g_txq, buf, (uint16_t)(sizeof(hdr) + plen));
}

// Ensure critical messages (e.g., SCAN_DONE) are enqueued even if the queue is full.
static void enqueue_msg_force(uint8_t type, uint16_t seq, const void* payload, uint16_t plen) {
    uint8_t buf[16 + MQ_MAX_MSG];
    int tries = MQ_DEPTH;

    if (plen > (MQ_MAX_MSG - sizeof(pwusb_hdr_t))) return;
    if (!g_txq) return;

    pwusb_hdr_t hdr = {
        .magic = PWUSB_MAGIC,
        .version = PWUSB_VERSION,
        .msg_type = type,
        .flags = 0,
        .hdr_len = sizeof(pwusb_hdr_t),
        .seq = seq,
        .payload_len = plen,
        .xid = 0};

    memcpy(buf, &hdr, sizeof(hdr));
    if (plen && payload) memcpy(buf + sizeof(hdr), payload, plen);

    while (tries-- > 0) {
        if (mq_push(g_txq, buf, (uint16_t)(sizeof(hdr) + plen)))
            return;
        if (!mq_drop(g_txq))
            return;
    }
}

typedef struct __attribute__((packed)) {
    uint8_t bssid[6];
    uint8_t channel;
    int8_t rssi_dbm;
    uint16_t security_flags;
    uint8_t ssid_len;
    // ssid bytes follow
} scan_result_hdr_t;

typedef struct {
    bool used;
    uint8_t bssid[6];
    uint8_t channel;
    int8_t rssi;
    uint16_t security;
    uint8_t ssid_len;
    uint8_t ssid[32];
} wifi_scan_entry_t;

static wifi_scan_entry_t g_scan_cache[WIFI_SCAN_MAX_RESULTS];
static uint8_t g_scan_cache_count = 0;

static void reset_scan_state_only(void) {
    g_scan_seq = 0;
    g_scan_in_progress = false;
    g_scan_done_sent = false;
    g_scan_deadline = (absolute_time_t){0};
}

static void reset_scan_cache(void) {
    g_scan_cache_count = 0;
    memset(g_scan_cache, 0, sizeof(g_scan_cache));
}

static void reset_connect_state(void) {
    g_connected = false;
    g_ssid_len = 0;
    memset(g_ssid, 0, sizeof(g_ssid));
    g_psk_len = 0;
    memset(g_psk, 0, sizeof(g_psk));
    g_key_type = PWUSB_KEY_NONE;

    g_conn_in_progress = false;
    g_conn_done_sent = false;
    g_conn_seq = 0;
    g_conn_deadline = (absolute_time_t){0};

    memset(g_conn_bssid, 0, sizeof(g_conn_bssid));
    g_conn_channel = 0;
    g_conn_rssi = 0;
}

static void update_conn_meta_from_scan_cache(void) {
    int best = -1;
    uint8_t i;

    if (g_ssid_len == 0)
        return;

    for (i = 0; i < g_scan_cache_count; i++) {
        if (!g_scan_cache[i].used)
            continue;
        if (g_scan_cache[i].ssid_len != g_ssid_len)
            continue;
        if (memcmp(g_scan_cache[i].ssid, g_ssid, g_ssid_len) != 0)
            continue;
        if (best < 0 || g_scan_cache[i].rssi > g_scan_cache[best].rssi)
            best = i;
    }

    if (best >= 0) {
        memcpy(g_conn_bssid, g_scan_cache[best].bssid, sizeof(g_conn_bssid));
        g_conn_channel = g_scan_cache[best].channel;
        g_conn_rssi = g_scan_cache[best].rssi;
    }
}

static uint16_t lookup_security_for_ssid(void) {
    int best = -1;
    uint8_t i;

    if (g_ssid_len == 0)
        return 0;

    for (i = 0; i < g_scan_cache_count; i++) {
        if (!g_scan_cache[i].used)
            continue;
        if (g_scan_cache[i].ssid_len != g_ssid_len)
            continue;
        if (memcmp(g_scan_cache[i].ssid, g_ssid, g_ssid_len) != 0)
            continue;
        if (best < 0 || g_scan_cache[i].rssi > g_scan_cache[best].rssi)
            best = i;
    }

    if (best >= 0)
        return g_scan_cache[best].security;

    return 0;
}

static uint32_t auth_mode_from_security(uint16_t security, uint8_t psk_len) {
    uint8_t auth_mode = (uint8_t)(security & 0xff);

    if (psk_len == 0)
        return CYW43_AUTH_OPEN;

    if ((auth_mode & 0x04) && (auth_mode & 0x02))
        return CYW43_AUTH_WPA2_MIXED_PSK;
    if (auth_mode & 0x04)
        return CYW43_AUTH_WPA2_AES_PSK;
    if (auth_mode & 0x02)
        return CYW43_AUTH_WPA_TKIP_PSK;

    return CYW43_AUTH_WPA2_MIXED_PSK;
}

static void fill_status(phtm_status_rsp_t* st) {
    memset(st, 0, sizeof(*st));
    st->connected = g_connected ? 1 : 0;
    st->ssid_len = g_ssid_len;
    memcpy(st->ssid, g_ssid, g_ssid_len);
    memcpy(st->bssid, g_conn_bssid, sizeof(st->bssid));
    st->channel = g_conn_channel;
    st->rssi = g_conn_rssi;
    st->reserved = 0;
}

static void mask_psk(char* out, size_t out_len, const uint8_t* psk, uint8_t psk_len) {
    size_t i;
    size_t head = (psk_len < 2) ? psk_len : 4;
    size_t tail = (psk_len < 4) ? 0 : 4;
    size_t mid = (psk_len > (head + tail)) ? (psk_len - head - tail) : 0;

    if (out_len == 0)
        return;

    memset(out, 0, out_len);
    if (psk_len == 0)
        return;

    for (i = 0; i < head && i + 1 < out_len; i++)
        out[i] = (char)psk[i];
    for (i = 0; i < mid && (head + i) + 1 < out_len; i++)
        out[head + i] = '*';
    for (i = 0; i < tail && (head + mid + i) + 1 < out_len; i++)
        out[head + mid + i] = (char)psk[psk_len - tail + i];
}

static int scan_cb(void* env, const cyw43_ev_scan_result_t* res) {
    (void)env;
    if (!res) {
        uint32_t st = 0;
        if (!g_scan_done_sent) {
            enqueue_msg_force(PWUSB_EVT_SCAN_DONE, g_scan_seq, &st, sizeof(st));
            g_scan_done_sent = true;
        }
        g_scan_in_progress = false;
        return 0;
    }

    if (g_scan_cache_count < WIFI_SCAN_MAX_RESULTS) {
        wifi_scan_entry_t* e = &g_scan_cache[g_scan_cache_count++];
        memset(e, 0, sizeof(*e));
        e->used = true;
        memcpy(e->bssid, res->bssid, 6);
        e->channel = (uint8_t)res->channel;
        e->rssi = (int8_t)res->rssi;
        e->security = (uint16_t)res->auth_mode;
        e->ssid_len = (res->ssid_len > 32) ? 32 : (uint8_t)res->ssid_len;
        memcpy(e->ssid, res->ssid, e->ssid_len);
    }

    // Build variable-length payload
    uint8_t payload[sizeof(scan_result_hdr_t) + 32];
    scan_result_hdr_t rh;
    memcpy(rh.bssid, res->bssid, 6);
    rh.channel = (uint8_t)res->channel;
    rh.rssi_dbm = (int8_t)res->rssi;
    // Expose CYW43 security bitmask to Linux:
    // bit0=privacy, bit1=WPA IE present, bit2=RSN/WPA2 IE present.
    rh.security_flags = (uint16_t)res->auth_mode;
    rh.ssid_len = (res->ssid_len > 32) ? 32 : (uint8_t)res->ssid_len;

    memcpy(payload, &rh, sizeof(rh));
    memcpy(payload + sizeof(rh), res->ssid, rh.ssid_len);

    enqueue_msg(PWUSB_EVT_SCAN_RESULT, g_scan_seq, payload, (uint16_t)(sizeof(rh) + rh.ssid_len));
    return 0;
}

bool wifi_mgr_init(void) {
    uint8_t mac[6] = {0};

    if (cyw43_arch_init()) return false;
    cyw43_arch_enable_sta_mode();

    // Bring-up: disable power saving so the STA won't miss one-shot DHCP replies.
    // You can re-enable `CYW43_DEFAULT_PM` later once RX is proven reliable.
    int pm_ret = cyw43_wifi_pm(&cyw43_state, CYW43_NONE_PM);
    if (pm_ret != 0) {
        printf("WARN: Failed to set PM mode: %d\n", pm_ret);
    }

    cyw43_wifi_get_mac(&cyw43_state, CYW43_ITF_STA, mac);
    printf("CYW43 MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    reset_scan_state_only();
    reset_scan_cache();
    reset_connect_state();

    return true;
}

void wifi_mgr_set_txq(msg_queue_t* txq) {
    g_txq = txq;
}

void wifi_mgr_poll(void) {
    cyw43_arch_poll();

    if (g_scan_in_progress && !g_scan_done_sent) {
        if (time_reached(g_scan_deadline)) {
            uint32_t st = 0;
            enqueue_msg_force(PWUSB_EVT_SCAN_DONE, g_scan_seq, &st, sizeof(st));
            g_scan_done_sent = true;
            g_scan_in_progress = false;
        }
    }

    /*
     * Connection progress is asynchronous.
     *
     * We must NOT block the main loop inside wifi_mgr_connect(), otherwise USB
     * service and other tasks stall and the adapter "feels unresponsive".
     */
    if (g_conn_in_progress && !g_conn_done_sent) {
        phtm_status_rsp_t st;
        int link_st;

        link_st = cyw43_wifi_link_status(&cyw43_state, CYW43_ITF_STA);
        if (link_st == CYW43_LINK_JOIN ||
            link_st == CYW43_LINK_NOIP ||
            link_st == CYW43_LINK_UP) {
            g_connected = true;
            g_conn_in_progress = false;
            g_conn_done_sent = true;

            update_conn_meta_from_scan_cache();

            fill_status(&st);
            st.reserved = 0;
            if (PWUSB_WIFI_DEBUG) {
                printf("CONN_STATE send: seq=%u connected=1 ssid_len=%u st=0\n",
                       (unsigned)g_conn_seq, (unsigned)st.ssid_len);
            }
            enqueue_msg_force(PWUSB_EVT_CONN_STATE, g_conn_seq, &st, sizeof(st));
            return;
        }

        if (link_st < 0) {
            g_connected = false;
            g_conn_in_progress = false;
            g_conn_done_sent = true;
            fill_status(&st);
            st.reserved = (uint16_t)link_st;
            if (PWUSB_WIFI_DEBUG) {
                printf("CONN_STATE send: seq=%u connected=0 ssid_len=%u st=%d\n",
                       (unsigned)g_conn_seq, (unsigned)st.ssid_len, link_st);
            }
            enqueue_msg_force(PWUSB_EVT_CONN_STATE, g_conn_seq, &st, sizeof(st));
            return;
        }

        if (time_reached(g_conn_deadline)) {
            g_connected = false;
            g_conn_in_progress = false;
            g_conn_done_sent = true;
            fill_status(&st);
            st.reserved = (uint16_t)PICO_ERROR_TIMEOUT;
            if (PWUSB_WIFI_DEBUG) {
                printf("CONN_STATE send: seq=%u connected=0 ssid_len=%u st=timeout\n",
                       (unsigned)g_conn_seq, (unsigned)st.ssid_len);
            }
            enqueue_msg_force(PWUSB_EVT_CONN_STATE, g_conn_seq, &st, sizeof(st));
            /* Best-effort: cancel the in-flight attempt. */
            (void)cyw43_wifi_leave(&cyw43_state, CYW43_ITF_STA);
            return;
        }
    }
}

bool wifi_mgr_send_ethernet(const uint8_t* buf, uint16_t len) {
    int ret;
    if (!buf || len == 0) return false;
    if (len > (MQ_MAX_MSG - sizeof(pwusb_hdr_t))) return false;
    if (!g_connected) {
        static uint32_t tx_dbg;
        if (PWUSB_WIFI_DEBUG && tx_dbg < 5) {
            printf("TX_ETH drop: not connected len=%u\n", (unsigned)len);
            tx_dbg++;
        }
        return false;
    }

    ret = cyw43_send_ethernet(&cyw43_state, CYW43_ITF_STA, len, buf, false);
    {
        static uint32_t tx_dbg;
        if (PWUSB_WIFI_DEBUG && tx_dbg < 5) {
            if (ret == 0)
                printf("TX_ETH ok len=%u\n", (unsigned)len);
            else
                printf("TX_ETH send failed ret=%d len=%u\n", ret, (unsigned)len);
            tx_dbg++;
        }
    }

    return ret == 0;
}

bool wifi_mgr_scan_start(msg_queue_t* txq, uint16_t seq) {
    g_txq = txq;
    reset_scan_state_only();
    reset_scan_cache();
    g_scan_seq = seq;
    g_scan_in_progress = true;
    g_scan_done_sent = false;
    g_scan_deadline = make_timeout_time_ms(SCAN_DONE_TIMEOUT_MS);

    cyw43_wifi_scan_options_t opts = {0};
    // active scan is typical; you can tune later
    int err = cyw43_wifi_scan(&cyw43_state, &opts, NULL, scan_cb);
    if (err) {
        uint32_t st = (uint32_t)err;
        enqueue_msg_force(PWUSB_EVT_ERROR, seq, &st, sizeof(st));
        enqueue_msg_force(PWUSB_EVT_SCAN_DONE, seq, &st, sizeof(st));
        g_scan_in_progress = false;
        g_scan_done_sent = true;
        return false;
    }

    // SCAN_DONE is sent from scan_cb when the scan completes.
    return true;
}

bool wifi_mgr_connect(msg_queue_t* txq, uint16_t seq,
                      const char* ssid, uint8_t ssid_len,
                      const char* psk, uint8_t psk_len,
                      uint8_t key_type) {
    phtm_status_rsp_t st;
    int err;
    uint16_t security;
    uint32_t auth_mode;

    g_txq = txq;
    reset_connect_state();
#if DEBUG_WIFI_CREDENTIALS
    g_ssid_len = strlen(DEBUG_WIFI_SSID);
    g_psk_len = strlen(DEBUG_WIFI_PSK);
    memset(g_ssid, 0, sizeof(g_ssid));
    memset(g_psk, 0, sizeof(g_psk));
    memcpy(g_ssid, DEBUG_WIFI_SSID, g_ssid_len);
    memcpy(g_psk, DEBUG_WIFI_PSK, g_psk_len);
    g_key_type = PWUSB_KEY_PASSPHRASE;
#else
    g_ssid_len = (ssid_len > 32) ? 32 : ssid_len;
    memset(g_ssid, 0, sizeof(g_ssid));
    memcpy(g_ssid, ssid, g_ssid_len);

    g_psk_len = (psk_len > 64) ? 64 : psk_len;
    memset(g_psk, 0, sizeof(g_psk));
    if (psk && g_psk_len)
        memcpy(g_psk, psk, g_psk_len);
    g_key_type = (key_type <= PWUSB_KEY_PMK) ? key_type : PWUSB_KEY_NONE;
#endif

    g_conn_seq = seq;

    if (PWUSB_WIFI_DEBUG) {
        char psk_mask[80];
        if (g_key_type == PWUSB_KEY_PMK) {
            // PMK is binary; don't print raw bytes to UART/logs.
            snprintf(psk_mask, sizeof(psk_mask), "<pmk:%u bytes>", (unsigned)g_psk_len);
        } else {
            mask_psk(psk_mask, sizeof(psk_mask), g_psk, g_psk_len);
        }
        printf("CONNECT req: ssid_len=%u psk_len=%u key_type=%u ssid='%s' psk='%s'\n",
               g_ssid_len, g_psk_len, g_key_type, g_ssid, psk_mask);
    }

    g_conn_in_progress = true;
    g_conn_done_sent = false;
    g_conn_deadline = make_timeout_time_ms(CONNECT_TIMEOUT_MS);

    cyw43_ll_set_pmk_mode(&cyw43_state.cyw43_ll, g_key_type == PWUSB_KEY_PMK);
    security = lookup_security_for_ssid();
    auth_mode = auth_mode_from_security(security, g_psk_len);

    /* Cancel any prior connection attempt. */
    (void)cyw43_wifi_leave(&cyw43_state, CYW43_ITF_STA);
    sleep_ms(100);
    g_connected = false;

    if (g_psk_len) {
        err = cyw43_wifi_join(&cyw43_state, g_ssid_len, g_ssid,
                              g_psk_len, g_psk,
                              auth_mode,
                              NULL, CYW43_CHANNEL_NONE);
    } else {
        err = cyw43_wifi_join(&cyw43_state, g_ssid_len, g_ssid,
                              0, NULL,
                              CYW43_AUTH_OPEN,
                              NULL, CYW43_CHANNEL_NONE);
    }

    if (PWUSB_WIFI_DEBUG) {
        printf("CONNECT start: seq=%u rc=%d ssid_len=%u\n",
               (unsigned)seq, err, (unsigned)g_ssid_len);
    }

    if (err) {
        if (PWUSB_WIFI_DEBUG)
            printf("CONNECT start failed rc=%d\n", err);

        g_conn_in_progress = false;
        g_conn_done_sent = true;
        fill_status(&st);
        st.reserved = (uint16_t)err;
        enqueue_msg_force(PWUSB_EVT_CONN_STATE, seq, &st, sizeof(st));
        return false;
    }

    /*
     * Connection completion is reported from wifi_mgr_poll() once the link
     * reaches CYW43_LINK_JOIN (or errors / times out).
     */
    return true;
}

bool wifi_mgr_disconnect(msg_queue_t* txq, uint16_t seq) {
    phtm_status_rsp_t st;
    int err = 0;

    g_txq = txq;
    err = cyw43_wifi_leave(&cyw43_state, CYW43_ITF_STA);
    sleep_ms(100);
    reset_connect_state();

    fill_status(&st);
    st.reserved = (uint16_t)err;
    enqueue_msg_force(PWUSB_EVT_CONN_STATE, seq, &st, sizeof(st));
    return (err == 0);
}

void wifi_mgr_get_status(msg_queue_t* txq, uint16_t seq) {
    phtm_status_rsp_t st;

    g_txq = txq;
    fill_status(&st);
    enqueue_msg_force(PWUSB_EVT_STATUS, seq, &st, sizeof(st));
}

void cyw43_cb_process_ethernet(void* cb_data, int itf, size_t len, const uint8_t* buf) {
    uint8_t msg[16 + MQ_MAX_MSG];
    pwusb_hdr_t hdr;
    static uint32_t rx_dbg;
    static uint32_t dhcp_dbg;
    static uint32_t push_fail_dbg;
    uint16_t sport = 0, dport = 0;
    uint8_t sip[4] = {0}, dip[4] = {0};
    int tries = MQ_DEPTH;

    (void)cb_data;
    (void)itf;

    if (!g_txq || !buf || len == 0) return;
    pwusb_perf_wifi_rx(len);
    if (len > (MQ_MAX_MSG - sizeof(pwusb_hdr_t))) {
        pwusb_perf_wifi_rx_drop_oversize();
        return;
    }

    if (PWUSB_WIFI_DEBUG && rx_dbg < 10) {
        uint16_t et = (uint16_t)(buf[12] << 8 | buf[13]);
        printf("RX_ETH len=%u et=0x%04x dst=%02x:%02x:%02x:%02x:%02x:%02x src=%02x:%02x:%02x:%02x:%02x:%02x\n",
               (unsigned)len, et,
               buf[0], buf[1], buf[2], buf[3], buf[4], buf[5],
               buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]);
        rx_dbg++;
    }

    if (PWUSB_DHCP_DEBUG && parse_dhcp4(buf, (uint16_t)len, &sport, &dport, sip, dip) && dhcp_dbg < 10) {
        printf("RX DHCP4 %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u len=%u\n",
               sip[0], sip[1], sip[2], sip[3], sport,
               dip[0], dip[1], dip[2], dip[3], dport,
               (unsigned)len);
        dhcp_dbg++;
    }

    hdr.magic = PWUSB_MAGIC;
    hdr.version = PWUSB_VERSION;
    hdr.msg_type = PWUSB_DATA_RX_ETH;
    hdr.flags = 0;
    hdr.hdr_len = sizeof(pwusb_hdr_t);
    hdr.seq = 0;
    hdr.payload_len = (uint16_t)len;
    hdr.xid = 0;

    memcpy(msg, &hdr, sizeof(hdr));
    memcpy(msg + sizeof(hdr), buf, len);
    while (tries-- > 0) {
        if (mq_push(g_txq, msg, (uint16_t)(sizeof(hdr) + len)))
            return;
        if (!mq_drop(g_txq))
            break;
    }
    pwusb_perf_wifi_rx_drop_qfull();
    if (PWUSB_WIFI_DEBUG && push_fail_dbg < 5) {
        printf("RX enqueue drop len=%u (queue full)\n", (unsigned)len);
        push_fail_dbg++;
    }
}

void cyw43_cb_tcpip_set_link_up(cyw43_t* self, int itf) {
    static uint32_t link_dbg;
    (void)self;
    (void)itf;
    if (PWUSB_WIFI_DEBUG && link_dbg < 5) {
        printf("TCPIP link up (no lwIP)\n");
        link_dbg++;
    }
}

void cyw43_cb_tcpip_set_link_down(cyw43_t* self, int itf) {
    static uint32_t link_dbg;
    (void)self;
    (void)itf;
    if (PWUSB_WIFI_DEBUG && link_dbg < 5) {
        printf("TCPIP link down (no lwIP)\n");
        link_dbg++;
    }
}
