#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "msg_queue.h"
#include "pwusb_proto.h"
#include "wifi_mgr.h"
#include "cyw43.h"

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

static void build_and_enqueue(msg_queue_t* txq, uint8_t type, uint16_t seq,
                              const void* payload, uint16_t plen) {
    uint8_t buf[16 + MQ_MAX_MSG];
    if (plen > (MQ_MAX_MSG - sizeof(pwusb_hdr_t))) return;

    pwusb_hdr_t hdr = {
        .magic = PWUSB_MAGIC,
        .version = PWUSB_VERSION,
        .msg_type = type,
        .flags = PWUSB_F_IS_RESPONSE,
        .hdr_len = sizeof(pwusb_hdr_t),
        .seq = seq,
        .payload_len = plen,
        .xid = 0};
    memcpy(buf, &hdr, sizeof(hdr));
    if (plen && payload) memcpy(buf + sizeof(hdr), payload, plen);
    mq_push(txq, buf, (uint16_t)(sizeof(hdr) + plen));
}

static void build_and_enqueue_raw(msg_queue_t* txq, uint8_t type, uint16_t seq,
                                  const void* payload, uint16_t plen) {
    uint8_t buf[16 + MQ_MAX_MSG];
    if (plen > (MQ_MAX_MSG - sizeof(pwusb_hdr_t))) return;

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
    mq_push(txq, buf, (uint16_t)(sizeof(hdr) + plen));
}

typedef struct __attribute__((packed)) {
    uint16_t host_max_payload;
    uint16_t host_rx_queue_depth;
    uint32_t host_caps;
} hello_req_t;

typedef struct __attribute__((packed)) {
    uint16_t dev_max_payload;
    uint16_t dev_tx_queue_depth;
    uint32_t dev_caps;
    uint8_t mac[6];
    uint8_t reserved[2];
} hello_rsp_t;

bool pwusb_handle_one(msg_queue_t* txq, const uint8_t* msg, uint16_t msg_len) {
    if (msg_len < sizeof(pwusb_hdr_t)) return false;

    const pwusb_hdr_t* h = (const pwusb_hdr_t*)msg;
    const uint8_t* payload = msg + sizeof(pwusb_hdr_t);

    switch (h->msg_type) {
        case PWUSB_HELLO: {
            hello_rsp_t rsp = {
                .dev_max_payload = MQ_MAX_MSG,
                .dev_tx_queue_depth = MQ_DEPTH,
                .dev_caps = 0,
                .mac = {0},
                .reserved = {0}};
            cyw43_wifi_get_mac(&cyw43_state, CYW43_ITF_STA, rsp.mac);
            build_and_enqueue(txq, PWUSB_HELLO_RSP, h->seq, &rsp, sizeof(rsp));
            return true;
        }

        case PWUSB_CMD_SCAN_START: {
            // start scan; results will be queued as events
            wifi_mgr_scan_start(txq, h->seq);
            return true;
        }

        case PWUSB_CMD_CONNECT: {
            const uint8_t* p = payload;
            uint8_t ssid_len;
            uint8_t psk_len;
            const uint8_t* ssid;
            const uint8_t* psk;
            if (msg_len < sizeof(pwusb_hdr_t) + 1) {
                uint32_t st = 1;
                build_and_enqueue(txq, PWUSB_EVT_ERROR, h->seq, &st, sizeof(st));
                return true;
            }
            ssid_len = p[0];
            psk_len = (msg_len >= sizeof(pwusb_hdr_t) + 2) ? p[1] : 0;
            if (ssid_len == 0 || ssid_len > 32 || psk_len > 64 ||
                msg_len < sizeof(pwusb_hdr_t) + 2 + ssid_len + psk_len) {
                uint32_t st = 2;
                build_and_enqueue(txq, PWUSB_EVT_ERROR, h->seq, &st, sizeof(st));
                return true;
            }
            ssid = p + 2;
            psk = ssid + ssid_len;
            printf("CMD_CONNECT: ssid_len=%u psk_len=%u ssid='%.*s'\n",
                   ssid_len, psk_len, ssid_len, ssid);
            wifi_mgr_connect(txq, h->seq,
                             (const char*)ssid, ssid_len,
                             (const char*)psk, psk_len);
            return true;
        }

        case PWUSB_CMD_DISCONNECT: {
            wifi_mgr_disconnect(txq, h->seq);
            return true;
        }

        case PWUSB_CMD_GET_STATUS: {
            wifi_mgr_get_status(txq, h->seq);
            return true;
        }

        case PWUSB_DATA_TX_ETH: {
            const uint8_t* payload = msg + sizeof(pwusb_hdr_t);
            uint16_t sport = 0, dport = 0;
            uint8_t sip[4] = {0}, dip[4] = {0};
            static uint32_t dhcp_dbg;
            if (h->payload_len > (MQ_MAX_MSG - sizeof(pwusb_hdr_t))) {
                printf("DATA_TX_ETH: len=%u (drop)\n", h->payload_len);
                return true;
            }
            if (parse_dhcp4(payload, h->payload_len, &sport, &dport, sip, dip) && dhcp_dbg < 10) {
                printf("TX DHCP4 %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u len=%u\n",
                       sip[0], sip[1], sip[2], sip[3], sport,
                       dip[0], dip[1], dip[2], dip[3], dport,
                       h->payload_len);
                dhcp_dbg++;
            }
            printf("DATA_TX_ETH rx len=%u\n", h->payload_len);
            if (!wifi_mgr_send_ethernet(payload, h->payload_len)) {
                printf("DATA_TX_ETH: len=%u (send failed)\n", h->payload_len);
            }
            return true;
        }

        default: {
            uint32_t st = 1;  // unknown cmd
            build_and_enqueue(txq, PWUSB_EVT_ERROR, h->seq, &st, sizeof(st));
            return true;
        }
    }
}
