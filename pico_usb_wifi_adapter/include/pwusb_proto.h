#ifndef PWUSB_PROTO_H
#define PWUSB_PROTO_H

#include <stdint.h>

#define PWUSB_MAGIC 0x4D544850u  // 'PHTM' little-endian
#define PWUSB_VERSION 0x01

enum pwusb_msg_type {
    PWUSB_HELLO = 0x01,
    PWUSB_HELLO_RSP = 0x81,

    PWUSB_CMD_SCAN_START = 0x10,
    PWUSB_CMD_SCAN_ABORT = 0x11,
    PWUSB_CMD_CONNECT = 0x12,
    PWUSB_CMD_DISCONNECT = 0x13,
    PWUSB_CMD_GET_STATUS = 0x14,

    PWUSB_EVT_SCAN_RESULT = 0x90,
    PWUSB_EVT_SCAN_DONE = 0x91,
    PWUSB_EVT_CONN_STATE = 0x92,
    PWUSB_EVT_STATUS = 0x93,
    PWUSB_DATA_TX_ETH = 0xA0,
    PWUSB_DATA_RX_ETH = 0xA1,
    PWUSB_EVT_ERROR = 0xFF,
};

enum pwusb_flags {
    PWUSB_F_ACK_REQ = 1 << 0,
    PWUSB_F_IS_RESPONSE = 1 << 1,
};

enum pwusb_key_type {
    PWUSB_KEY_NONE = 0,
    PWUSB_KEY_PASSPHRASE = 1,
    PWUSB_KEY_PMK = 2,
};

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint8_t version;
    uint8_t msg_type;
    uint8_t flags;
    uint8_t hdr_len;  // 16
    uint16_t seq;
    uint16_t payload_len;
    uint32_t xid;
} pwusb_hdr_t;

typedef struct {
    uint8_t ssid_len;
    uint8_t key_type;
    uint8_t psk_len;
    uint8_t ssid[32];
    uint8_t psk[64];
} phtm_connect_req_t;

typedef struct {
    uint8_t connected;
    uint8_t ssid_len;
    uint8_t ssid[32];
    uint8_t bssid[6];
    uint8_t channel;
    int8_t rssi;
    uint16_t reserved;
} phtm_status_rsp_t;
#pragma pack(pop)

#endif
