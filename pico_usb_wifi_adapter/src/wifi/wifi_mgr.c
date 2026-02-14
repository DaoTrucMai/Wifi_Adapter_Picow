#include "wifi_mgr.h"

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

#define SCAN_DONE_TIMEOUT_MS 6000
#define CONNECT_TIMEOUT_MS 15000

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

static void fill_status(phtm_status_rsp_t* st) {
    memset(st, 0, sizeof(*st));
    st->connected = g_connected ? 1 : 0;
    st->ssid_len = g_ssid_len;
    memcpy(st->ssid, g_ssid, g_ssid_len);
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

    // Build variable-length payload
    uint8_t payload[sizeof(scan_result_hdr_t) + 32];
    scan_result_hdr_t rh;
    memcpy(rh.bssid, res->bssid, 6);
    rh.channel = (uint8_t)res->channel;
    rh.rssi_dbm = (int8_t)res->rssi;
    // Expose auth mode so the Linux cfg80211 side can advertise RSN/WPA in scan results.
    // cyw43 scan results store auth_mode as a small code (0=open, 2=WPA-TKIP, 4=WPA2-AES, 6=WPA2 mixed).
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
    return true;
}

void wifi_mgr_set_txq(msg_queue_t* txq) {
    g_txq = txq;
}

void wifi_mgr_poll(void) {
    cyw43_arch_poll();

    if (g_scan_in_progress && !g_scan_done_sent) {
        if (absolute_time_diff_us(get_absolute_time(), g_scan_deadline) <= 0) {
            uint32_t st = 0;
            enqueue_msg_force(PWUSB_EVT_SCAN_DONE, g_scan_seq, &st, sizeof(st));
            g_scan_done_sent = true;
            g_scan_in_progress = false;
        }
    }

    if (g_conn_in_progress && !g_conn_done_sent) {
        phtm_status_rsp_t st;
        g_connected = false;
        fill_status(&st);
        st.reserved = 1;  // timeout
        enqueue_msg_force(PWUSB_EVT_CONN_STATE, g_conn_seq, &st, sizeof(st));
        g_conn_done_sent = true;
        g_conn_in_progress = false;
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

    g_txq = txq;
    g_conn_seq = seq;
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

    if (g_psk_len) {
        err = cyw43_wifi_join(&cyw43_state, g_ssid_len, g_ssid,
                              g_psk_len, g_psk,
                              CYW43_AUTH_WPA2_MIXED_PSK,
                              NULL, CYW43_CHANNEL_NONE);
    } else {
        err = cyw43_wifi_join(&cyw43_state, g_ssid_len, g_ssid,
                              0, NULL,
                              CYW43_AUTH_OPEN,
                              NULL, CYW43_CHANNEL_NONE);
    }

    if (err == 0) {
        while (!time_reached(g_conn_deadline)) {
            int st = cyw43_wifi_link_status(&cyw43_state, CYW43_ITF_STA);
            if (st == CYW43_LINK_JOIN) {
                g_connected = true;
                err = 0;
                break;
            }
            if (st < 0) {
                err = st;
                break;
            }
            cyw43_arch_poll();
            sleep_ms(10);
        }
        if (!g_connected && err == 0 && time_reached(g_conn_deadline))
            err = PICO_ERROR_TIMEOUT;
    }

    if (g_connected) {
        // Register broadcast MAC to ensure BC frames reach us
        // DHCP replies are sent as broadcast (FF:FF:FF:FF:FF:FF) or unicast (always accepted)
        // No need to register multicast groups since DHCP uses broadcast/unicast only
        uint8_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        cyw43_wifi_update_multicast_filter(&cyw43_state, bcast, true);
        if (PWUSB_WIFI_DEBUG)
            printf("multicast filter: allow broadcast (for DHCP OFFER/ACK)\n");
    }

    if (PWUSB_WIFI_DEBUG)
        printf("CONNECT rc=%d\n", err);

    g_conn_in_progress = false;
    g_conn_done_sent = true;
    fill_status(&st);
    st.reserved = (uint16_t)err;
    enqueue_msg_force(PWUSB_EVT_CONN_STATE, seq, &st, sizeof(st));
    return g_connected;
}

bool wifi_mgr_disconnect(msg_queue_t* txq, uint16_t seq) {
    phtm_status_rsp_t st;
    int err = 0;

    g_txq = txq;
    g_conn_in_progress = false;
    g_conn_done_sent = true;
    err = cyw43_wifi_leave(&cyw43_state, CYW43_ITF_STA);
    g_connected = false;

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
    if (len > (MQ_MAX_MSG - sizeof(pwusb_hdr_t))) return;

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
