// SPDX-License-Identifier: GPL-2.0
#include <linux/atomic.h>
#include <linux/debugfs.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/udp.h>
#include <linux/uaccess.h>
#include <linux/usb.h>
#include <linux/workqueue.h>
#include <net/checksum.h>

#include "pico_wifi_cfg80211.h"
#define DRV_NAME "pico_usb_wifi"

static bool pico_debug;
module_param_named(debug, pico_debug, bool, 0644);
MODULE_PARM_DESC(debug, "Enable verbose bring-up logging");

static bool pico_dhcp_force_broadcast;
module_param_named(dhcp_force_broadcast, pico_dhcp_force_broadcast, bool, 0644);
MODULE_PARM_DESC(dhcp_force_broadcast, "Set BOOTP broadcast flag on DHCPDISCOVER (optional)");

// Must match Pico firmware
#define PICO_USB_VID 0xCAFE
#define PICO_USB_PID 0x4001

// PHTM protocol
#define PWU_MAGIC 0x4D544850u  // 'PHTM'
#define PWU_VER 0x01
#define PWU_HDR_LEN 16

// Message types
#define PWUSB_HELLO 0x01
#define PWUSB_HELLO_RSP 0x81
#define PWUSB_CMD_SCAN_START 0x10
#define PWUSB_CMD_CONNECT 0x12
#define PWUSB_CMD_DISCONNECT 0x13
#define PWUSB_CMD_GET_STATUS 0x14
#define PWUSB_EVT_SCAN_RESULT 0x90
#define PWUSB_EVT_SCAN_DONE 0x91
#define PWUSB_EVT_CONN_STATE 0x92
#define PWUSB_EVT_STATUS 0x93
#define PWUSB_DATA_TX_ETH 0xA0
#define PWUSB_DATA_RX_ETH 0xA1
#define PWUSB_EVT_ERROR 0xFF

struct pico_scan_result {
    u8 bssid[6];
    u8 channel;
    s8 rssi;
    u16 security;
    u8 ssid_len;
    char ssid[33];
};

struct __packed phtm_connect_req {
    u8 ssid_len;
    u8 key_type;
    u8 psk_len;
    u8 ssid[32];
    u8 psk[64];
};

struct __packed phtm_status_rsp {
    u8 connected;
    u8 ssid_len;
    u8 ssid[32];
    u8 bssid[6];
    u8 channel;
    s8 rssi;
    u16 reserved;
};

struct __packed pwu_hdr {
    __le32 magic;
    u8 version;
    u8 msg_type;
    u8 flags;
    u8 hdr_len;
    __le16 seq;
    __le16 payload_len;
    __le32 xid;
};

struct __packed phtm_hello_rsp {
    __le16 dev_max_payload;
    __le16 dev_tx_queue_depth;
    __le32 dev_caps;
    u8 mac[6];
    u8 reserved[2];
};

struct pico_dev {
    struct usb_device* udev;
    struct usb_interface* intf;

    u8 ep_in, ep_out;
    u16 ep_in_maxpkt, ep_out_maxpkt;

    // RX
    struct urb* rx_urb;
    u8* rx_buf;
    size_t rx_buf_size;

    // Stream framer buffer
    u8* fr_buf;
    size_t fr_len;
    size_t fr_cap;

    /* TX (async) */
    struct urb* tx_urb;
    u8* tx_buf;
    size_t tx_buf_size;
    atomic_t tx_busy;

    // Hello state
    bool got_hello;

    // SCAN state/results
    spinlock_t scan_lock;
    struct pico_scan_result scan_results[64];
    u8 scan_count;
    bool scan_in_progress;
    bool scan_done;
    u16 last_seq;  // Track sequence number for messages

    // Connect/status state (OPEN only for now)
    bool conn_connected;
    char conn_ssid[33];
    u8 conn_ssid_len;
    u8 conn_bssid[6];
    u8 conn_channel;
    s8 conn_rssi;
    u16 conn_status;

    // debugfs
    struct dentry* dbg_dir;

    // net_device (data plane)
    struct net_device* netdev;
    struct pico_cfg80211* cfg;

    bool disconnected;

    // debug counters
    u32 rx_dbg_count;
    u32 tx_dbg_count;
    u32 tx_eagain_count;
    u32 dhcp_tx_dbg_count;
    u32 dhcp_rx_dbg_count;
    u32 dhcp_tx_complete_dbg_count;
    bool last_tx_is_dhcp;
    u16 last_tx_seq;
    u32 last_tx_total;

    // deferred control path
    struct delayed_work ctrl_work;
    u8 ctrl_cmd;
    char ctrl_ssid[32];
    u8 ctrl_ssid_len;
    char ctrl_psk[64];
    u8 ctrl_psk_len;
    u8 ctrl_key_type;
    bool ctrl_quiesce;
};

static bool pico_parse_dhcp4(const u8* frame, size_t len,
                             __be32* sip, __be32* dip,
                             u16* sport, u16* dport,
                             u8* dhcp_msg_type, u32* dhcp_xid,
                             __be32* dhcp_yiaddr, u16* dhcp_flags) {
    struct ethhdr eh;
    struct iphdr iph;
    struct udphdr udph;
    size_t ihl;
    size_t ip_off = ETH_HLEN;
    size_t udp_off;
    size_t udp_payload_off;
    size_t udp_payload_len;
    const u8* bootp;
    size_t opts_off;

    if (!frame || len < ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr))
        return false;

    memcpy(&eh, frame, sizeof(eh));
    if (eh.h_proto != htons(ETH_P_IP))
        return false;

    memcpy(&iph, frame + ip_off, sizeof(iph));
    if (iph.version != 4)
        return false;
    ihl = (size_t)iph.ihl * 4;
    if (ihl < sizeof(struct iphdr))
        return false;

    udp_off = ip_off + ihl;
    if (len < udp_off + sizeof(struct udphdr))
        return false;
    if (iph.protocol != IPPROTO_UDP)
        return false;

    memcpy(&udph, frame + udp_off, sizeof(udph));
    *sport = ntohs(udph.source);
    *dport = ntohs(udph.dest);
    if (!((*sport == 68 && *dport == 67) || (*sport == 67 && *dport == 68)))
        return false;

    *sip = iph.saddr;
    *dip = iph.daddr;

    if (dhcp_msg_type)
        *dhcp_msg_type = 0;
    if (dhcp_xid)
        *dhcp_xid = 0;
    if (dhcp_yiaddr)
        *dhcp_yiaddr = 0;
    if (dhcp_flags)
        *dhcp_flags = 0;

    udp_payload_off = udp_off + sizeof(struct udphdr);
    if (len < udp_payload_off)
        return true;
    udp_payload_len = len - udp_payload_off;
    if (udp_payload_len < 240)
        return true;

    bootp = frame + udp_payload_off;
    if (dhcp_xid)
        *dhcp_xid = ntohl(*((const __be32*)(bootp + 4)));
    if (dhcp_flags)
        *dhcp_flags = ntohs(*((const __be16*)(bootp + 10)));
    if (dhcp_yiaddr)
        *dhcp_yiaddr = *((const __be32*)(bootp + 16));

    // Options start at BOOTP fixed header (236) + magic cookie (4) = 240
    opts_off = 240;
    if (udp_payload_len > opts_off + 3 && dhcp_msg_type) {
        const u8* opt = bootp + opts_off;
        size_t left = udp_payload_len - opts_off;
        while (left > 0) {
            u8 code = opt[0];
            u8 olen;
            if (code == 0) { // pad
                opt += 1;
                left -= 1;
                continue;
            }
            if (code == 255) // end
                break;
            if (left < 2)
                break;
            olen = opt[1];
            if (left < (size_t)(2 + olen))
                break;
            if (code == 53 && olen >= 1) { // DHCP message type
                *dhcp_msg_type = opt[2];
                break;
            }
            opt += 2 + olen;
            left -= 2 + olen;
        }
    }
    return true;
}

static void pico_dhcp_set_broadcast_flag(u8* frame, size_t len) {
    struct ethhdr eh;
    struct iphdr iph;
    struct udphdr udph;
    size_t ihl;
    size_t ip_off = ETH_HLEN;
    size_t udp_off;
    size_t udp_payload_off;
    u16 sport, dport;
    u16 udp_len;
    __wsum sum;
    __be16 bootp_flags_be;

    if (!frame || len < ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr))
        return;

    memcpy(&eh, frame, sizeof(eh));
    if (eh.h_proto != htons(ETH_P_IP))
        return;

    memcpy(&iph, frame + ip_off, sizeof(iph));
    if (iph.version != 4)
        return;
    ihl = (size_t)iph.ihl * 4;
    if (ihl < sizeof(struct iphdr))
        return;

    udp_off = ip_off + ihl;
    if (len < udp_off + sizeof(struct udphdr))
        return;
    if (iph.protocol != IPPROTO_UDP)
        return;

    memcpy(&udph, frame + udp_off, sizeof(udph));
    sport = ntohs(udph.source);
    dport = ntohs(udph.dest);
    if (!(sport == 68 && dport == 67))
        return;

    udp_payload_off = udp_off + sizeof(struct udphdr);
    if (len < udp_payload_off + 12)
        return;

    /*
     * BOOTP flags field is at offset 10 from start of BOOTP header.
     * Set broadcast bit to encourage servers to broadcast OFFER/ACK.
     *
     * We must also fix the UDP checksum, since we're changing payload bytes.
     */
    memcpy(&bootp_flags_be, frame + udp_payload_off + 10, sizeof(bootp_flags_be));
    bootp_flags_be |= htons(0x8000);
    memcpy(frame + udp_payload_off + 10, &bootp_flags_be, sizeof(bootp_flags_be));

    udp_len = ntohs(udph.len);
    if (!udp_len || len < udp_off + udp_len)
        return;

    udph.check = 0;
    memcpy(frame + udp_off, &udph, sizeof(udph));
    sum = csum_partial(frame + udp_off, udp_len, 0);
    udph.check = csum_tcpudp_magic(iph.saddr, iph.daddr, udp_len, IPPROTO_UDP, sum);
    if (udph.check == 0)
        udph.check = CSUM_MANGLED_0;
    memcpy(frame + udp_off, &udph, sizeof(udph));
}

static void pico_kick_rx(struct pico_dev* pdev);
static int pico_send_hello(struct pico_dev* pdev);
static int pico_send_scan_start(struct pico_dev* pdev);
static int pico_send_connect(struct pico_dev* pdev,
                             const char* ssid, u8 ssid_len,
                             const char* psk, u8 psk_len,
                             u8 key_type);
static int pico_send_disconnect(struct pico_dev* pdev);
static int pico_send_get_status(struct pico_dev* pdev);
static void pico_scan_clear(struct pico_dev* pdev);
static void pico_handle_scan_result(struct pico_dev* pdev, const u8* payload, size_t plen);
static void pico_handle_scan_done(struct pico_dev* pdev);
static void pico_handle_conn_state(struct pico_dev* pdev, const u8* payload, size_t plen);
static void pico_handle_status(struct pico_dev* pdev, const u8* payload, size_t plen);
static void pico_handle_data_rx(struct pico_dev* pdev, const u8* payload, size_t plen);
static void pico_ctrl_work_fn(struct work_struct* work);

enum {
    PICO_CTRL_NONE = 0,
    PICO_CTRL_CONNECT = 1,
    PICO_CTRL_DISCONNECT = 2,
};

struct pico_netdev_priv {
    struct pico_dev* pdev;
};

static void pico_process_stream(struct pico_dev* pdev, const u8* data, size_t n) {
    // append to framer buffer (simple linear buffer for now)
    if (n == 0) return;

    if (pdev->fr_len + n > pdev->fr_cap) {
        // drop on overflow (v0.1)
        pdev->fr_len = 0;
        return;
    }

    memcpy(pdev->fr_buf + pdev->fr_len, data, n);
    pdev->fr_len += n;

    // parse as many framed messages as possible
    while (pdev->fr_len >= PWU_HDR_LEN) {
        struct pwu_hdr h;
        u32 magic;
        u16 plen;
        size_t total;

        memcpy(&h, pdev->fr_buf, sizeof(h));
        magic = le32_to_cpu(h.magic);

        // resync by shifting one byte until magic/version/hdrlen match
        if (magic != PWU_MAGIC || h.version != PWU_VER || h.hdr_len != PWU_HDR_LEN) {
            memmove(pdev->fr_buf, pdev->fr_buf + 1, pdev->fr_len - 1);
            pdev->fr_len -= 1;
            continue;
        }

        plen = le16_to_cpu(h.payload_len);
        total = PWU_HDR_LEN + plen;

        if (total > pdev->fr_cap) {
            // invalid length -> resync
            memmove(pdev->fr_buf, pdev->fr_buf + 1, pdev->fr_len - 1);
            pdev->fr_len -= 1;
            continue;
        }

        if (pdev->fr_len < total) {
            // wait for more
            return;
        }

        // We have one complete message
        if (h.msg_type == PWUSB_HELLO_RSP) {
            struct phtm_hello_rsp rsp;
            dev_info(&pdev->intf->dev, DRV_NAME ": <- HELLO_RSP seq=%u plen=%u\n",
                     le16_to_cpu(h.seq), plen);
            pdev->got_hello = true;
            if (plen >= sizeof(rsp)) {
                memcpy(&rsp, pdev->fr_buf + PWU_HDR_LEN, sizeof(rsp));
                if (pdev->netdev)
                    eth_hw_addr_set(pdev->netdev, rsp.mac);
                dev_info(&pdev->intf->dev, DRV_NAME ": MAC %pM\n", rsp.mac);
            }
            /* Handshake complete, trigger WiFi scan */
            dev_info(&pdev->intf->dev, DRV_NAME ": handshake complete, starting WiFi scan\n");
            pico_send_scan_start(pdev);

        } else if (h.msg_type == PWUSB_EVT_SCAN_RESULT) {
            dev_dbg(&pdev->intf->dev, DRV_NAME ": <- SCAN_RESULT seq=%u plen=%u\n",
                    le16_to_cpu(h.seq), plen);
            pico_handle_scan_result(pdev, pdev->fr_buf + PWU_HDR_LEN, plen);
        } else if (h.msg_type == PWUSB_EVT_SCAN_DONE) {
            dev_info(&pdev->intf->dev, DRV_NAME ": <- SCAN_DONE seq=%u plen=%u\n",
                     le16_to_cpu(h.seq), plen);
            pico_handle_scan_done(pdev);
        } else if (h.msg_type == PWUSB_EVT_CONN_STATE) {
            dev_info(&pdev->intf->dev, DRV_NAME ": <- CONN_STATE seq=%u plen=%u\n",
                     le16_to_cpu(h.seq), plen);
            pico_handle_conn_state(pdev, pdev->fr_buf + PWU_HDR_LEN, plen);
        } else if (h.msg_type == PWUSB_EVT_STATUS) {
            dev_info(&pdev->intf->dev, DRV_NAME ": <- STATUS seq=%u plen=%u\n",
                     le16_to_cpu(h.seq), plen);
            pico_handle_status(pdev, pdev->fr_buf + PWU_HDR_LEN, plen);
        } else if (h.msg_type == PWUSB_DATA_RX_ETH) {
            pico_handle_data_rx(pdev, pdev->fr_buf + PWU_HDR_LEN, plen);
        } else if (h.msg_type == PWUSB_EVT_ERROR) {
            u32 st = 0;
            if (plen >= sizeof(st))
                memcpy(&st, pdev->fr_buf + PWU_HDR_LEN, sizeof(st));
            dev_warn(&pdev->intf->dev, DRV_NAME ": <- ERROR seq=%u st=%u\n",
                     le16_to_cpu(h.seq), le32_to_cpu(st));
        } else {
            dev_info(&pdev->intf->dev, DRV_NAME ": <- msg type=0x%02x seq=%u plen=%u\n",
                     h.msg_type, le16_to_cpu(h.seq), plen);
        }

        // consume this message
        if (pdev->fr_len > total)
            memmove(pdev->fr_buf, pdev->fr_buf + total, pdev->fr_len - total);
        pdev->fr_len -= total;
    }
}

static void pico_rx_complete(struct urb* urb) {
    struct pico_dev* pdev = urb->context;
    int status = urb->status;

    if (!pdev) return;

    if (status == 0) {
        dev_dbg(&pdev->intf->dev, DRV_NAME ": RX urb complete actual_length=%d\n", urb->actual_length);
        if (urb->actual_length > 0)
            pico_process_stream(pdev, pdev->rx_buf, urb->actual_length);
    } else if (status == -EOVERFLOW) {
        dev_dbg(&pdev->intf->dev, DRV_NAME ": RX urb overflow (buffer too small)\n");
    } else {
        if (!pdev->disconnected)
            dev_warn(&pdev->intf->dev, DRV_NAME ": RX urb status=%d\n", status);
    }

    // Resubmit unless device is gone
    if (!pdev->disconnected && status != -ENODEV && status != -ESHUTDOWN)
        pico_kick_rx(pdev);
}

static void pico_kick_rx(struct pico_dev* pdev) {
    int ret;

    usb_fill_bulk_urb(pdev->rx_urb,
                      pdev->udev,
                      usb_rcvbulkpipe(pdev->udev, pdev->ep_in),
                      pdev->rx_buf,
                      pdev->rx_buf_size,
                      pico_rx_complete,
                      pdev);

    ret = usb_submit_urb(pdev->rx_urb, GFP_ATOMIC);
    if (ret)
        dev_warn(&pdev->intf->dev, DRV_NAME ": usb_submit_urb RX failed: %d\n", ret);
    else
        dev_dbg(&pdev->intf->dev, DRV_NAME ": RX urb submitted len=%zu\n", pdev->rx_buf_size);
}

static void pico_tx_complete(struct urb* urb) {
    struct pico_dev* pdev = urb->context;
    int status = urb->status;

    if (!pdev) return;

    if (pico_debug && pdev->last_tx_is_dhcp && pdev->dhcp_tx_complete_dbg_count < 10) {
        dev_info(&pdev->intf->dev,
                 DRV_NAME ": TX DHCP complete status=%d actual=%d seq=%u total=%u\n",
                 status, urb->actual_length, pdev->last_tx_seq, pdev->last_tx_total);
        pdev->dhcp_tx_complete_dbg_count++;
    }

    if (status)
        dev_warn(&pdev->intf->dev, DRV_NAME ": TX urb status=%d\n", status);
    else
        dev_dbg(&pdev->intf->dev, DRV_NAME ": TX complete len=%d\n", urb->actual_length);

    /* Mark TX as free */
    atomic_set(&pdev->tx_busy, 0);
    pdev->last_tx_is_dhcp = false;
    if (pdev->netdev && pdev->conn_connected && netif_carrier_ok(pdev->netdev))
        netif_wake_queue(pdev->netdev);
}

static int pico_tx_submit_gfp(struct pico_dev* pdev, const u8* data, size_t n, gfp_t gfp) {
    int ret;

    if (!pdev || pdev->disconnected)
        return -ENODEV;

    if (n > pdev->tx_buf_size) return -EINVAL;

    /* simple single-URB TX queue: fail if busy */
    if (atomic_xchg(&pdev->tx_busy, 1)) return -EAGAIN;

    memcpy(pdev->tx_buf, data, n);

    usb_fill_bulk_urb(pdev->tx_urb,
                      pdev->udev,
                      usb_sndbulkpipe(pdev->udev, pdev->ep_out),
                      pdev->tx_buf,
                      n,
                      pico_tx_complete,
                      pdev);

    ret = usb_submit_urb(pdev->tx_urb, gfp);
    if (ret) {
        atomic_set(&pdev->tx_busy, 0);
        dev_warn(&pdev->intf->dev, DRV_NAME ": usb_submit_urb TX failed: %d\n", ret);
    } else {
        dev_dbg(&pdev->intf->dev, DRV_NAME ": -> TX submitted len=%zu\n", n);
    }

    return ret;
}

static int pico_tx_submit_skb_gfp(struct pico_dev* pdev, const struct pwu_hdr* h,
                                  const struct sk_buff* skb, gfp_t gfp,
                                  bool dhcp_broadcast) {
    int ret;
    size_t total;

    if (!pdev || !h || !skb || pdev->disconnected)
        return -ENODEV;

    total = PWU_HDR_LEN + skb->len;
    if (total > pdev->tx_buf_size)
        return -EINVAL;

    if (atomic_xchg(&pdev->tx_busy, 1))
        return -EAGAIN;

    memcpy(pdev->tx_buf, h, PWU_HDR_LEN);
    if (skb_copy_bits(skb, 0, pdev->tx_buf + PWU_HDR_LEN, skb->len)) {
        atomic_set(&pdev->tx_busy, 0);
        return -EFAULT;
    }

    if (dhcp_broadcast)
        pico_dhcp_set_broadcast_flag(pdev->tx_buf + PWU_HDR_LEN, skb->len);

    usb_fill_bulk_urb(pdev->tx_urb,
                      pdev->udev,
                      usb_sndbulkpipe(pdev->udev, pdev->ep_out),
                      pdev->tx_buf,
                      total,
                      pico_tx_complete,
                      pdev);

    ret = usb_submit_urb(pdev->tx_urb, gfp);
    if (ret) {
        atomic_set(&pdev->tx_busy, 0);
        dev_warn(&pdev->intf->dev, DRV_NAME ": usb_submit_urb TX failed: %d\n", ret);
    }

    return ret;
}

static int pico_tx_submit(struct pico_dev* pdev, const u8* data, size_t n) {
    return pico_tx_submit_gfp(pdev, data, n, GFP_KERNEL);
}

/* Send a HELLO message (non-blocking via TX URB) */
static int pico_send_hello(struct pico_dev* pdev) {
    u8 msg[PWU_HDR_LEN];
    struct pwu_hdr h;
    int ret;

    memset(&h, 0, sizeof(h));
    h.magic = cpu_to_le32(PWU_MAGIC);
    h.version = PWU_VER;
    h.msg_type = PWUSB_HELLO;
    h.flags = 0;
    h.hdr_len = PWU_HDR_LEN;
    h.seq = cpu_to_le16(1);
    h.payload_len = cpu_to_le16(0);
    h.xid = cpu_to_le32(0);

    memcpy(msg, &h, sizeof(h));

    ret = pico_tx_submit(pdev, msg, sizeof(msg));

    dev_info(&pdev->intf->dev, DRV_NAME ": -> HELLO submit ret=%d\n", ret);
    return ret;
}

/* Send SCAN_START command */
static int pico_send_scan_start(struct pico_dev* pdev) {
    u8 msg[PWU_HDR_LEN];
    struct pwu_hdr h;
    int ret;

    memset(&h, 0, sizeof(h));
    h.magic = cpu_to_le32(PWU_MAGIC);
    h.version = PWU_VER;
    h.msg_type = PWUSB_CMD_SCAN_START;
    h.flags = 0;
    h.hdr_len = PWU_HDR_LEN;
    h.seq = cpu_to_le16(pdev->last_seq++);
    h.payload_len = cpu_to_le16(0);
    h.xid = cpu_to_le32(0);

    memcpy(msg, &h, sizeof(h));

    ret = pico_tx_submit(pdev, msg, sizeof(msg));
    if (ret == 0) {
        dev_info(&pdev->intf->dev, DRV_NAME ": SCAN_START sent (seq=%u)\n",
                 le16_to_cpu(h.seq));
    }

    return ret;
}

/* Send CONNECT command (OPEN only) */
static int pico_send_connect(struct pico_dev* pdev,
                             const char* ssid, u8 ssid_len,
                             const char* psk, u8 psk_len,
                             u8 key_type) {
    u8 msg[PWU_HDR_LEN + 3 + 32 + 64];
    struct pwu_hdr h;
    int ret;
    u8* p;

    if (ssid_len == 0 || ssid_len > 32 || psk_len > 64)
        return -EINVAL;
    if (key_type > PICO_KEY_PMK)
        return -EINVAL;

    memset(&h, 0, sizeof(h));
    h.magic = cpu_to_le32(PWU_MAGIC);
    h.version = PWU_VER;
    h.msg_type = PWUSB_CMD_CONNECT;
    h.flags = 0;
    h.hdr_len = PWU_HDR_LEN;
    h.seq = cpu_to_le16(pdev->last_seq++);
    h.payload_len = cpu_to_le16(3 + ssid_len + psk_len);
    h.xid = cpu_to_le32(0);

    memcpy(msg, &h, sizeof(h));
    p = msg + sizeof(h);
    p[0] = ssid_len;
    p[1] = key_type;
    p[2] = psk_len;
    memcpy(p + 3, ssid, ssid_len);
    if (psk && psk_len)
        memcpy(p + 3 + ssid_len, psk, psk_len);

    ret = pico_tx_submit(pdev, msg, PWU_HDR_LEN + 3 + ssid_len + psk_len);
    if (ret == 0) {
        dev_info(&pdev->intf->dev, DRV_NAME ": CONNECT sent (seq=%u ssid=%.*s psk=%u)\n",
                 le16_to_cpu(h.seq), ssid_len, ssid, psk_len);
    }

    return ret;
}

/* Send DISCONNECT command */
static int pico_send_disconnect(struct pico_dev* pdev) {
    u8 msg[PWU_HDR_LEN];
    struct pwu_hdr h;

    memset(&h, 0, sizeof(h));
    h.magic = cpu_to_le32(PWU_MAGIC);
    h.version = PWU_VER;
    h.msg_type = PWUSB_CMD_DISCONNECT;
    h.flags = 0;
    h.hdr_len = PWU_HDR_LEN;
    h.seq = cpu_to_le16(pdev->last_seq++);
    h.payload_len = cpu_to_le16(0);
    h.xid = cpu_to_le32(0);

    memcpy(msg, &h, sizeof(h));
    return pico_tx_submit(pdev, msg, sizeof(msg));
}

int pico_ctrl_scan_start(struct pico_dev* pdev) {
    unsigned long flags;
    int ret;

    if (!pdev)
        return -ENODEV;

    spin_lock_irqsave(&pdev->scan_lock, flags);
    if (pdev->scan_in_progress) {
        spin_unlock_irqrestore(&pdev->scan_lock, flags);
        return -EBUSY;
    }
    pdev->scan_in_progress = true;
    pdev->scan_done = false;
    pdev->scan_count = 0;
    spin_unlock_irqrestore(&pdev->scan_lock, flags);

    ret = pico_send_scan_start(pdev);
    if (ret) {
        spin_lock_irqsave(&pdev->scan_lock, flags);
        pdev->scan_in_progress = false;
        spin_unlock_irqrestore(&pdev->scan_lock, flags);
        return ret;
    }

    return 0;
}

int pico_ctrl_connect(struct pico_dev* pdev,
                      const u8* ssid, u8 ssid_len,
                      const u8* psk, u8 psk_len,
                      u8 key_type) {
    if (!pdev || !ssid || ssid_len == 0 || ssid_len > sizeof(pdev->ctrl_ssid))
        return -EINVAL;
    if (psk_len > sizeof(pdev->ctrl_psk))
        return -EINVAL;
    if (key_type > PICO_KEY_PMK)
        return -EINVAL;

    pdev->ctrl_ssid_len = ssid_len;
    memcpy(pdev->ctrl_ssid, ssid, ssid_len);
    pdev->ctrl_psk_len = psk_len;
    if (psk_len && psk)
        memcpy(pdev->ctrl_psk, psk, psk_len);
    pdev->ctrl_key_type = key_type;
    pdev->ctrl_cmd = PICO_CTRL_CONNECT;
    schedule_delayed_work(&pdev->ctrl_work, 0);
    return 0;
}

int pico_ctrl_disconnect(struct pico_dev* pdev) {
    if (!pdev)
        return -ENODEV;
    pdev->ctrl_cmd = PICO_CTRL_DISCONNECT;
    schedule_delayed_work(&pdev->ctrl_work, 0);
    return 0;
}

static void pico_ctrl_work_fn(struct work_struct* work) {
    struct pico_dev* pdev = container_of(work, struct pico_dev, ctrl_work.work);
    int ret;

    if (!pdev || pdev->disconnected)
        return;

    switch (pdev->ctrl_cmd) {
        case PICO_CTRL_CONNECT:
            ret = pico_send_connect(pdev,
                                    pdev->ctrl_ssid,
                                    pdev->ctrl_ssid_len,
                                    pdev->ctrl_psk_len ? pdev->ctrl_psk : NULL,
                                    pdev->ctrl_psk_len,
                                    pdev->ctrl_key_type);
            if (ret == -EAGAIN) {
                dev_info(&pdev->intf->dev, DRV_NAME ": CONNECT busy, will retry\n");
                schedule_delayed_work(&pdev->ctrl_work, msecs_to_jiffies(100));
                return;
            }
            if (ret)
                dev_warn(&pdev->intf->dev, DRV_NAME ": CONNECT send failed: %d\n", ret);
            pdev->ctrl_cmd = PICO_CTRL_NONE;
            return;
        case PICO_CTRL_DISCONNECT:
            if (!pdev->ctrl_quiesce && pdev->netdev) {
                netif_stop_queue(pdev->netdev);
                netif_carrier_off(pdev->netdev);
                pdev->ctrl_quiesce = true;
            }
            ret = pico_send_disconnect(pdev);
            if (ret == -EAGAIN) {
                dev_info(&pdev->intf->dev, DRV_NAME ": DISCONNECT busy, will retry\n");
                schedule_delayed_work(&pdev->ctrl_work, msecs_to_jiffies(100));
                return;
            }
            if (ret)
                dev_warn(&pdev->intf->dev, DRV_NAME ": DISCONNECT send failed: %d\n", ret);
            pdev->ctrl_cmd = PICO_CTRL_NONE;
            pdev->ctrl_quiesce = false;
            return;
        default:
            return;
    }
}

/* Send GET_STATUS command */
static int pico_send_get_status(struct pico_dev* pdev) {
    u8 msg[PWU_HDR_LEN];
    struct pwu_hdr h;

    memset(&h, 0, sizeof(h));
    h.magic = cpu_to_le32(PWU_MAGIC);
    h.version = PWU_VER;
    h.msg_type = PWUSB_CMD_GET_STATUS;
    h.flags = 0;
    h.hdr_len = PWU_HDR_LEN;
    h.seq = cpu_to_le16(pdev->last_seq++);
    h.payload_len = cpu_to_le16(0);
    h.xid = cpu_to_le32(0);

    memcpy(msg, &h, sizeof(h));
    return pico_tx_submit(pdev, msg, sizeof(msg));
}

static void pico_scan_clear(struct pico_dev* pdev) {
    unsigned long flags;

    spin_lock_irqsave(&pdev->scan_lock, flags);
    pdev->scan_count = 0;
    pdev->scan_in_progress = false;
    pdev->scan_done = false;
    spin_unlock_irqrestore(&pdev->scan_lock, flags);
}

static void pico_handle_scan_result(struct pico_dev* pdev, const u8* payload, size_t plen) {
    struct pico_scan_result* entry = NULL;
    unsigned long flags;
    __le16 sec_le;
    u8 ssid_len;
    u8 i;
    char ssid_buf[33];
    u8 bssid[6];
    u8 channel;
    s8 rssi;
    u16 security;

    if (plen < 11) {
        dev_dbg(&pdev->intf->dev, DRV_NAME ": SCAN_RESULT too short (%zu)\n", plen);
        return;
    }

    ssid_len = payload[10];
    if (ssid_len > 32)
        ssid_len = 32;

    if (plen < (size_t)(11 + ssid_len)) {
        dev_dbg(&pdev->intf->dev, DRV_NAME ": SCAN_RESULT bad ssid_len=%u plen=%zu\n",
                ssid_len, plen);
        return;
    }

    memcpy(bssid, payload, 6);
    channel = payload[6];
    rssi = (s8)payload[7];
    memcpy(&sec_le, payload + 8, sizeof(sec_le));
    security = le16_to_cpu(sec_le);
    memset(ssid_buf, 0, sizeof(ssid_buf));
    memcpy(ssid_buf, payload + 11, ssid_len);

    spin_lock_irqsave(&pdev->scan_lock, flags);

    for (i = 0; i < pdev->scan_count; i++) {
        if (!memcmp(pdev->scan_results[i].bssid, payload, 6)) {
            entry = &pdev->scan_results[i];
            break;
        }
    }

    if (!entry) {
        if (pdev->scan_count >= ARRAY_SIZE(pdev->scan_results)) {
            spin_unlock_irqrestore(&pdev->scan_lock, flags);
            return;
        }
        entry = &pdev->scan_results[pdev->scan_count++];
        memcpy(entry->bssid, bssid, sizeof(bssid));
    }

    entry->channel = channel;
    entry->rssi = rssi;
    entry->security = security;
    entry->ssid_len = ssid_len;
    memset(entry->ssid, 0, sizeof(entry->ssid));
    memcpy(entry->ssid, ssid_buf, ssid_len);

    spin_unlock_irqrestore(&pdev->scan_lock, flags);

    if (pdev->cfg)
        pico_cfg80211_report_scan_result(pdev->cfg, bssid, channel, rssi, security,
                                         ssid_buf, ssid_len);

    if (pico_debug) {
        dev_info(&pdev->intf->dev,
                 DRV_NAME ": SSID=\"%s\"  RSSI=%d  CH=%u  BSSID=%pM  SEC=0x%04x\n",
                 ssid_buf, rssi, channel, bssid, security);
    }
}

static void pico_handle_scan_done(struct pico_dev* pdev) {
    unsigned long flags;

    spin_lock_irqsave(&pdev->scan_lock, flags);
    pdev->scan_in_progress = false;
    pdev->scan_done = true;
    spin_unlock_irqrestore(&pdev->scan_lock, flags);

    if (pdev->cfg)
        pico_cfg80211_scan_done(pdev->cfg, false);
}

static bool pico_fill_bssid_from_scan(struct pico_dev* pdev) {
    unsigned long flags;
    struct pico_scan_result* best = NULL;
    u8 i;

    if (!pdev || pdev->conn_ssid_len == 0)
        return false;

    spin_lock_irqsave(&pdev->scan_lock, flags);
    for (i = 0; i < pdev->scan_count; i++) {
        struct pico_scan_result* r = &pdev->scan_results[i];
        if (r->ssid_len != pdev->conn_ssid_len)
            continue;
        if (memcmp(r->ssid, pdev->conn_ssid, r->ssid_len) != 0)
            continue;
        if (!best || r->rssi > best->rssi)
            best = r;
    }
    if (best) {
        memcpy(pdev->conn_bssid, best->bssid, sizeof(pdev->conn_bssid));
        pdev->conn_channel = best->channel;
        pdev->conn_rssi = best->rssi;
    }
    spin_unlock_irqrestore(&pdev->scan_lock, flags);

    return best != NULL;
}

static void pico_handle_conn_state(struct pico_dev* pdev, const u8* payload, size_t plen) {
    struct phtm_status_rsp st;
    unsigned long flags;

    if (plen < sizeof(st))
        return;

    memcpy(&st, payload, sizeof(st));

    spin_lock_irqsave(&pdev->scan_lock, flags);
    pdev->conn_connected = st.connected ? true : false;
    pdev->conn_ssid_len = (st.ssid_len > 32) ? 32 : st.ssid_len;
    memset(pdev->conn_ssid, 0, sizeof(pdev->conn_ssid));
    memcpy(pdev->conn_ssid, st.ssid, pdev->conn_ssid_len);
    memcpy(pdev->conn_bssid, st.bssid, sizeof(pdev->conn_bssid));
    pdev->conn_channel = st.channel;
    pdev->conn_rssi = st.rssi;
    pdev->conn_status = le16_to_cpu((__le16)st.reserved);
    spin_unlock_irqrestore(&pdev->scan_lock, flags);

    if (pdev->conn_connected && is_zero_ether_addr(pdev->conn_bssid))
        pico_fill_bssid_from_scan(pdev);

    dev_info(&pdev->intf->dev,
             DRV_NAME ": CONN_STATE connected=%u ssid=\"%s\" bssid=%pM ch=%u rssi=%d st=%u\n",
             pdev->conn_connected ? 1 : 0, pdev->conn_ssid, pdev->conn_bssid,
             pdev->conn_channel, pdev->conn_rssi, pdev->conn_status);

    if (pdev->cfg)
        pico_cfg80211_conn_state(pdev->cfg,
                                 pdev->conn_connected,
                                 pdev->conn_bssid,
                                 pdev->conn_ssid,
                                 pdev->conn_ssid_len,
                                 pdev->conn_status,
                                 pdev->conn_rssi,
                                 pdev->conn_channel);

    if (pdev->netdev) {
        if (pdev->conn_connected) {
            netif_carrier_on(pdev->netdev);
            netif_wake_queue(pdev->netdev);
        } else {
            netif_carrier_off(pdev->netdev);
            netif_stop_queue(pdev->netdev);
        }
    }
}

static void pico_handle_status(struct pico_dev* pdev, const u8* payload, size_t plen) {
    struct phtm_status_rsp st;
    unsigned long flags;

    if (plen < sizeof(st))
        return;

    memcpy(&st, payload, sizeof(st));

    spin_lock_irqsave(&pdev->scan_lock, flags);
    pdev->conn_connected = st.connected ? true : false;
    pdev->conn_ssid_len = (st.ssid_len > 32) ? 32 : st.ssid_len;
    memset(pdev->conn_ssid, 0, sizeof(pdev->conn_ssid));
    memcpy(pdev->conn_ssid, st.ssid, pdev->conn_ssid_len);
    memcpy(pdev->conn_bssid, st.bssid, sizeof(pdev->conn_bssid));
    pdev->conn_channel = st.channel;
    pdev->conn_rssi = st.rssi;
    pdev->conn_status = le16_to_cpu((__le16)st.reserved);
    spin_unlock_irqrestore(&pdev->scan_lock, flags);

    if (pdev->netdev) {
        if (pdev->conn_connected) {
            netif_carrier_on(pdev->netdev);
            netif_wake_queue(pdev->netdev);
        } else {
            netif_carrier_off(pdev->netdev);
            netif_stop_queue(pdev->netdev);
        }
    }
}

static void pico_handle_data_rx(struct pico_dev* pdev, const u8* payload, size_t plen) {
    struct sk_buff* skb;
    __be32 sip = 0, dip = 0;
    u16 sport = 0, dport = 0;
    u8 dhcp_type = 0;
    u32 dhcp_xid = 0;
    __be32 yiaddr = 0;
    u16 flags = 0;
    bool is_dhcp = false;
    int rx_ret;

    if (!pdev || !pdev->netdev || plen == 0)
        return;

    if (pico_debug) {
        is_dhcp = pico_parse_dhcp4(payload, plen, &sip, &dip, &sport, &dport,
                                   &dhcp_type, &dhcp_xid, &yiaddr, &flags);
    }
    if (pico_debug && is_dhcp && pdev->dhcp_rx_dbg_count < 10) {
        dev_info(&pdev->intf->dev,
                 DRV_NAME ": RX DHCP4 t=%u xid=0x%08x yiaddr=%pI4 flags=0x%04x %pI4:%u -> %pI4:%u len=%zu\n",
                 dhcp_type, dhcp_xid, &yiaddr, flags, &sip, sport, &dip, dport, plen);
        pdev->dhcp_rx_dbg_count++;
    }

    if (pico_debug && pdev->rx_dbg_count < 5) {
        dev_info(&pdev->intf->dev, DRV_NAME ": DATA_RX_ETH len=%zu\n", plen);
        print_hex_dump(KERN_INFO, DRV_NAME ": RX ",
                       DUMP_PREFIX_OFFSET, 16, 1,
                       payload, min_t(size_t, plen, 64), false);
        pdev->rx_dbg_count++;
    }

    skb = netdev_alloc_skb(pdev->netdev, plen + NET_IP_ALIGN);
    if (!skb) {
        pdev->netdev->stats.rx_dropped++;
        return;
    }

    skb_reserve(skb, NET_IP_ALIGN);
    memcpy(skb_put(skb, plen), payload, plen);
    skb->ip_summed = CHECKSUM_NONE; /* no offload; data is already on the wire */
    skb->protocol = eth_type_trans(skb, pdev->netdev);
    rx_ret = netif_rx(skb);
    if (is_dhcp && rx_ret != NET_RX_SUCCESS) {
        dev_warn(&pdev->intf->dev, DRV_NAME ": RX DHCP netif_rx ret=%d\n", rx_ret);
    }

    pdev->netdev->stats.rx_packets++;
    pdev->netdev->stats.rx_bytes += plen;
}

static netdev_tx_t pico_ndo_start_xmit(struct sk_buff* skb, struct net_device* ndev) {
    struct pico_netdev_priv* priv = netdev_priv(ndev);
    struct pico_dev* pdev = priv ? priv->pdev : NULL;
    struct pwu_hdr h;
    int ret;
    u8 hdr[96];
    size_t hdr_len;
    __be32 sip = 0, dip = 0;
    u16 sport = 0, dport = 0;
    u8 dhcp_type = 0;
    u32 dhcp_xid = 0;
    __be32 yiaddr = 0;
    u16 flags = 0;
    bool is_dhcp = false;

    if (!pdev || !pdev->udev) {
        ndev->stats.tx_dropped++;
        dev_kfree_skb_any(skb);
        return NETDEV_TX_OK;
    }

    if (!pdev->conn_connected) {
        ndev->stats.tx_dropped++;
        dev_kfree_skb_any(skb);
        return NETDEV_TX_OK;
    }

    /* We don't support checksum offload; compute it in software if needed. */
    if (skb->ip_summed == CHECKSUM_PARTIAL) {
        if (skb_checksum_help(skb)) {
            ndev->stats.tx_dropped++;
            dev_kfree_skb_any(skb);
            return NETDEV_TX_OK;
        }
    }

    if (pico_debug || pico_dhcp_force_broadcast) {
        hdr_len = min_t(size_t, skb->len, sizeof(hdr));
        if (hdr_len >= ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) &&
            !skb_copy_bits(skb, 0, hdr, hdr_len) &&
            pico_parse_dhcp4(hdr, hdr_len, &sip, &dip, &sport, &dport,
                             &dhcp_type, &dhcp_xid, &yiaddr, &flags)) {
            is_dhcp = true;
            // hdr_len may be too small to parse options; we re-parse from full frame below.
        }
    }

    if (pico_debug && pdev->tx_dbg_count < 10) {
        __be16 proto = 0;
        struct ethhdr eh;
        if (skb->len >= ETH_HLEN && !skb_copy_bits(skb, 0, &eh, sizeof(eh)))
            proto = eh.h_proto;
        dev_info(&pdev->intf->dev, DRV_NAME ": TX skb_len=%u proto=0x%04x\n",
                 skb->len, ntohs(proto));
        pdev->tx_dbg_count++;
    }

    if ((PWU_HDR_LEN + skb->len) > pdev->tx_buf_size) {
        ndev->stats.tx_dropped++;
        dev_kfree_skb_any(skb);
        return NETDEV_TX_OK;
    }

    memset(&h, 0, sizeof(h));
    h.magic = cpu_to_le32(PWU_MAGIC);
    h.version = PWU_VER;
    h.msg_type = PWUSB_DATA_TX_ETH;
    h.flags = 0;
    h.hdr_len = PWU_HDR_LEN;
    h.seq = cpu_to_le16(pdev->last_seq++);
    h.payload_len = cpu_to_le16(skb->len);
    h.xid = cpu_to_le32(0);

    if (is_dhcp) {
        pdev->last_tx_is_dhcp = true;
        pdev->last_tx_seq = le16_to_cpu(h.seq);
        pdev->last_tx_total = (u32)(PWU_HDR_LEN + skb->len);
    }

    if (pico_debug && is_dhcp && pdev->dhcp_tx_dbg_count < 10) {
        dev_info(&pdev->intf->dev,
                 DRV_NAME ": TX DHCP4 t=%u xid=0x%08x yiaddr=%pI4 flags=0x%04x %pI4:%u -> %pI4:%u len=%u\n",
                 dhcp_type, dhcp_xid, &yiaddr, flags, &sip, sport, &dip, dport, skb->len);
        pdev->dhcp_tx_dbg_count++;
    }

    ret = pico_tx_submit_skb_gfp(pdev, &h, skb, GFP_ATOMIC,
                                 is_dhcp && pico_dhcp_force_broadcast);

    if (pico_debug && is_dhcp && pdev->dhcp_tx_dbg_count <= 10) {
        dev_info(&pdev->intf->dev, DRV_NAME ": TX DHCP submit ret=%d tx_busy=%d\n",
                 ret, atomic_read(&pdev->tx_busy));
    }

    if (ret == -EAGAIN)
    {
        pdev->tx_eagain_count++;
        netif_stop_queue(ndev);
        return NETDEV_TX_BUSY;
    }
    if (ret) {
        ndev->stats.tx_dropped++;
        dev_kfree_skb_any(skb);
        return NETDEV_TX_OK;
    }

    ndev->stats.tx_packets++;
    ndev->stats.tx_bytes += skb->len;
    dev_kfree_skb_any(skb);
    return NETDEV_TX_OK;
}

static int pico_ndo_open(struct net_device* ndev) {
    struct pico_netdev_priv* priv = netdev_priv(ndev);
    struct pico_dev* pdev = priv ? priv->pdev : NULL;

    if (pdev && pdev->conn_connected) {
        netif_carrier_on(ndev);
        netif_start_queue(ndev);
    } else {
        netif_carrier_off(ndev);
        netif_stop_queue(ndev);
    }
    return 0;
}

static int pico_ndo_stop(struct net_device* ndev) {
    netif_stop_queue(ndev);
    netif_carrier_off(ndev);
    return 0;
}

static const struct net_device_ops pico_netdev_ops = {
    .ndo_open = pico_ndo_open,
    .ndo_stop = pico_ndo_stop,
    .ndo_start_xmit = pico_ndo_start_xmit,
};

static int pico_dbg_scan_results_show(struct seq_file* s, void* unused) {
    struct pico_dev* pdev = s->private;
    struct pico_scan_result* results;
    u8 count;
    unsigned long flags;
    u8 i;

    spin_lock_irqsave(&pdev->scan_lock, flags);
    count = pdev->scan_count;
    results = kcalloc(count ? count : 1, sizeof(*results), GFP_KERNEL);
    if (results)
        memcpy(results, pdev->scan_results, count * sizeof(*results));
    spin_unlock_irqrestore(&pdev->scan_lock, flags);

    if (!results)
        return -ENOMEM;

    for (i = 0; i < count; i++) {
        seq_printf(s, "SSID=\"%s\"  RSSI=%d  CH=%u  BSSID=%pM  SEC=0x%04x\n",
                   results[i].ssid, results[i].rssi, results[i].channel,
                   results[i].bssid, results[i].security);
    }

    kfree(results);
    return 0;
}

static int pico_dbg_scan_results_open(struct inode* inode, struct file* file) {
    return single_open(file, pico_dbg_scan_results_show, inode->i_private);
}

static ssize_t pico_dbg_scan_start_write(struct file* file,
                                         const char __user* buf,
                                         size_t len,
                                         loff_t* ppos) {
    struct pico_dev* pdev = file->private_data;
    int val;
    int ret;

    if (kstrtoint_from_user(buf, len, 0, &val))
        return -EINVAL;
    if (val != 1)
        return -EINVAL;

    ret = pico_ctrl_scan_start(pdev);
    if (ret)
        return ret;

    return len;
}

static ssize_t pico_dbg_scan_done_read(struct file* file,
                                       char __user* buf,
                                       size_t len,
                                       loff_t* ppos) {
    struct pico_dev* pdev = file->private_data;
    char tmp[4];
    int n;
    unsigned long flags;
    bool done;

    spin_lock_irqsave(&pdev->scan_lock, flags);
    done = pdev->scan_done;
    spin_unlock_irqrestore(&pdev->scan_lock, flags);

    n = scnprintf(tmp, sizeof(tmp), "%u\n", done ? 1 : 0);
    return simple_read_from_buffer(buf, len, ppos, tmp, n);
}

static const struct file_operations pico_dbg_scan_results_fops = {
    .owner = THIS_MODULE,
    .open = pico_dbg_scan_results_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static const struct file_operations pico_dbg_scan_start_fops = {
    .owner = THIS_MODULE,
    .write = pico_dbg_scan_start_write,
    .open = simple_open,
};

static const struct file_operations pico_dbg_scan_done_fops = {
    .owner = THIS_MODULE,
    .read = pico_dbg_scan_done_read,
    .open = simple_open,
};

static ssize_t pico_dbg_connect_write(struct file* file,
                                      const char __user* buf,
                                      size_t len,
                                      loff_t* ppos) {
    struct pico_dev* pdev = file->private_data;
    char in[96];
    char ssid[32];
    char psk[64];
    char* sep;
    size_t n = min_t(size_t, len, sizeof(in));
    size_t ssid_len;
    size_t psk_len = 0;

    if (!pdev || n == 0)
        return -EINVAL;

    if (copy_from_user(in, buf, n))
        return -EFAULT;

    while (n > 0 && (in[n - 1] == '\n' || in[n - 1] == '\r'))
        n--;

    if (n == 0)
        return -EINVAL;

    sep = memchr(in, ':', n);
    if (sep) {
        ssid_len = min_t(size_t, sep - in, sizeof(ssid));
        psk_len = min_t(size_t, n - ssid_len - 1, sizeof(psk));
        if (ssid_len == 0)
            return -EINVAL;
        memcpy(ssid, in, ssid_len);
        if (psk_len)
            memcpy(psk, sep + 1, psk_len);
    } else {
        ssid_len = min_t(size_t, n, sizeof(ssid));
        memcpy(ssid, in, ssid_len);
    }

    if (pico_ctrl_connect(pdev, ssid, ssid_len,
                          psk_len ? psk : NULL, psk_len,
                          psk_len ? PICO_KEY_PASSPHRASE : PICO_KEY_NONE))
        return -EINVAL;

    {
        char psk_mask[80];
        size_t i;
        size_t head = (psk_len < 2) ? psk_len : 4;
        size_t tail = (psk_len < 4) ? 0 : 4;
        size_t mid = (psk_len > (head + tail)) ? (psk_len - head - tail) : 0;

        memset(psk_mask, 0, sizeof(psk_mask));
        for (i = 0; i < head && i + 1 < sizeof(psk_mask); i++)
            psk_mask[i] = psk[i];
        for (i = 0; i < mid && (head + i) + 1 < sizeof(psk_mask); i++)
            psk_mask[head + i] = '*';
        for (i = 0; i < tail && (head + mid + i) + 1 < sizeof(psk_mask); i++)
            psk_mask[head + mid + i] = psk[psk_len - tail + i];

        dev_info(&pdev->intf->dev,
                 DRV_NAME ": CONNECT req ssid_len=%zu psk_len=%zu ssid=\"%.*s\" psk=\"%s\"\n",
                 ssid_len, psk_len, (int)ssid_len, ssid, psk_mask);
    }

    return len;
}

static ssize_t pico_dbg_disconnect_write(struct file* file,
                                         const char __user* buf,
                                         size_t len,
                                         loff_t* ppos) {
    struct pico_dev* pdev = file->private_data;
    int val;

    if (kstrtoint_from_user(buf, len, 0, &val))
        return -EINVAL;
    if (val != 1)
        return -EINVAL;

    if (pico_ctrl_disconnect(pdev))
        return -ENODEV;
    return len;
}

static ssize_t pico_dbg_status_read(struct file* file,
                                    char __user* buf,
                                    size_t len,
                                    loff_t* ppos) {
    struct pico_dev* pdev = file->private_data;
    char tmp[128];
    int n;
    unsigned long flags;

    /* Fire-and-forget status request; return cached status */
    pico_send_get_status(pdev);

    spin_lock_irqsave(&pdev->scan_lock, flags);
    n = scnprintf(tmp, sizeof(tmp),
                  "connected=%u ssid=\"%s\" bssid=%pM ch=%u rssi=%d st=%u\n",
                  pdev->conn_connected ? 1 : 0, pdev->conn_ssid, pdev->conn_bssid,
                  pdev->conn_channel, pdev->conn_rssi, pdev->conn_status);
    spin_unlock_irqrestore(&pdev->scan_lock, flags);

    return simple_read_from_buffer(buf, len, ppos, tmp, n);
}

static const struct file_operations pico_dbg_connect_fops = {
    .owner = THIS_MODULE,
    .write = pico_dbg_connect_write,
    .open = simple_open,
};

static const struct file_operations pico_dbg_disconnect_fops = {
    .owner = THIS_MODULE,
    .write = pico_dbg_disconnect_write,
    .open = simple_open,
};

static const struct file_operations pico_dbg_status_fops = {
    .owner = THIS_MODULE,
    .read = pico_dbg_status_read,
    .open = simple_open,
};

static int pico_probe(struct usb_interface* interface,
                      const struct usb_device_id* id) {
    struct usb_device* udev = interface_to_usbdev(interface);
    struct usb_host_interface* iface_desc;
    struct usb_endpoint_descriptor* endpoint;
    struct pico_dev* pdev;
    int i;

    dev_info(&interface->dev, DRV_NAME ": probe() VID=0x%04x PID=0x%04x\n",
             le16_to_cpu(udev->descriptor.idVendor),
             le16_to_cpu(udev->descriptor.idProduct));

    iface_desc = interface->cur_altsetting;

    pdev = kzalloc(sizeof(*pdev), GFP_KERNEL);
    if (!pdev)
        return -ENOMEM;

    pdev->udev = usb_get_dev(udev);
    pdev->intf = interface;

    // find bulk endpoints
    for (i = 0; i < iface_desc->desc.bNumEndpoints; ++i) {
        endpoint = &iface_desc->endpoint[i].desc;

        if (usb_endpoint_is_bulk_in(endpoint) && !pdev->ep_in) {
            pdev->ep_in = endpoint->bEndpointAddress;
            pdev->ep_in_maxpkt = usb_endpoint_maxp(endpoint);
            dev_info(&interface->dev,
                     DRV_NAME ": Found bulk IN ep 0x%02x maxpkt=%u\n",
                     pdev->ep_in, pdev->ep_in_maxpkt);
        }

        if (usb_endpoint_is_bulk_out(endpoint) && !pdev->ep_out) {
            pdev->ep_out = endpoint->bEndpointAddress;
            pdev->ep_out_maxpkt = usb_endpoint_maxp(endpoint);
            dev_info(&interface->dev,
                     DRV_NAME ": Found bulk OUT ep 0x%02x maxpkt=%u\n",
                     pdev->ep_out, pdev->ep_out_maxpkt);
        }
    }

    if (!pdev->ep_in || !pdev->ep_out) {
        dev_err(&interface->dev, DRV_NAME ": Missing bulk endpoints\n");
        usb_put_dev(pdev->udev);
        kfree(pdev);
        return -ENODEV;
    }

    // Allocate RX URB + buffers
    pdev->rx_buf_size = 8192;
    pdev->rx_buf = kmalloc(pdev->rx_buf_size, GFP_KERNEL);
    pdev->rx_urb = usb_alloc_urb(0, GFP_KERNEL);

    pdev->fr_cap = 16348;
    pdev->fr_buf = kmalloc(pdev->fr_cap, GFP_KERNEL);
    pdev->fr_len = 0;

    /* TX resources */
    pdev->tx_buf_size = 4096;
    pdev->tx_buf = kmalloc(pdev->tx_buf_size, GFP_KERNEL);
    pdev->tx_urb = usb_alloc_urb(0, GFP_KERNEL);
    atomic_set(&pdev->tx_busy, 0);
    spin_lock_init(&pdev->scan_lock);
    pico_scan_clear(pdev);

    if (!pdev->rx_buf || !pdev->rx_urb || !pdev->fr_buf || !pdev->tx_buf || !pdev->tx_urb) {
        dev_err(&interface->dev, DRV_NAME ": alloc failed\n");
        if (pdev->rx_urb) usb_free_urb(pdev->rx_urb);
        if (pdev->tx_urb) usb_free_urb(pdev->tx_urb);
        kfree(pdev->rx_buf);
        kfree(pdev->tx_buf);
        kfree(pdev->fr_buf);
        usb_put_dev(pdev->udev);
        kfree(pdev);
        return -ENOMEM;
    }

    usb_set_intfdata(interface, pdev);

    pdev->netdev = alloc_etherdev(sizeof(struct pico_netdev_priv));
    if (!pdev->netdev) {
        dev_err(&interface->dev, DRV_NAME ": netdev alloc failed\n");
        usb_put_dev(pdev->udev);
        kfree(pdev->rx_buf);
        kfree(pdev->tx_buf);
        kfree(pdev->fr_buf);
        usb_free_urb(pdev->rx_urb);
        usb_free_urb(pdev->tx_urb);
        kfree(pdev);
        return -ENOMEM;
    }
    {
        struct pico_netdev_priv* priv = netdev_priv(pdev->netdev);
        priv->pdev = pdev;
    }
    pdev->netdev->netdev_ops = &pico_netdev_ops;
    pdev->netdev->mtu = 1500;
    /* No offloads; we send raw Ethernet over USB. */
    pdev->netdev->features = 0;
    pdev->netdev->hw_features = 0;
    strscpy(pdev->netdev->name, "pico%d", IFNAMSIZ);
    eth_hw_addr_random(pdev->netdev);
    SET_NETDEV_DEV(pdev->netdev, &interface->dev);

    pdev->cfg = pico_cfg80211_init(pdev, pdev->netdev, &interface->dev);
    if (!pdev->cfg) {
        dev_err(&interface->dev, DRV_NAME ": cfg80211 init failed\n");
        free_netdev(pdev->netdev);
        usb_put_dev(pdev->udev);
        kfree(pdev->rx_buf);
        kfree(pdev->tx_buf);
        kfree(pdev->fr_buf);
        usb_free_urb(pdev->rx_urb);
        usb_free_urb(pdev->tx_urb);
        kfree(pdev);
        return -ENODEV;
    }

    if (register_netdev(pdev->netdev)) {
        dev_err(&interface->dev, DRV_NAME ": netdev register failed\n");
        pico_cfg80211_deinit(pdev->cfg);
        pdev->cfg = NULL;
        free_netdev(pdev->netdev);
        usb_put_dev(pdev->udev);
        kfree(pdev->rx_buf);
        kfree(pdev->tx_buf);
        kfree(pdev->fr_buf);
        usb_free_urb(pdev->rx_urb);
        usb_free_urb(pdev->tx_urb);
        kfree(pdev);
        return -ENODEV;
    }

    netif_carrier_off(pdev->netdev);
    netif_stop_queue(pdev->netdev);

    INIT_DELAYED_WORK(&pdev->ctrl_work, pico_ctrl_work_fn);
    pdev->ctrl_cmd = PICO_CTRL_NONE;
    pdev->ctrl_quiesce = false;

    /* Submit RX URB immediately to start receiving device responses */
    pico_kick_rx(pdev);

    /* Send HELLO to initiate handshake with device */
    dev_info(&interface->dev, DRV_NAME ": sending HELLO to initiate handshake\n");
    pico_send_hello(pdev);

    pdev->dbg_dir = debugfs_create_dir(DRV_NAME, NULL);
    if (pdev->dbg_dir) {
        debugfs_create_file("scan_start", 0200, pdev->dbg_dir, pdev,
                            &pico_dbg_scan_start_fops);
        debugfs_create_file("scan_results", 0400, pdev->dbg_dir, pdev,
                            &pico_dbg_scan_results_fops);
        debugfs_create_file("scan_done", 0400, pdev->dbg_dir, pdev,
                            &pico_dbg_scan_done_fops);
        debugfs_create_file("connect", 0200, pdev->dbg_dir, pdev,
                            &pico_dbg_connect_fops);
        debugfs_create_file("disconnect", 0200, pdev->dbg_dir, pdev,
                            &pico_dbg_disconnect_fops);
        debugfs_create_file("status", 0400, pdev->dbg_dir, pdev,
                            &pico_dbg_status_fops);
    } else {
        dev_warn(&interface->dev, DRV_NAME ": debugfs dir create failed\n");
    }

    dev_info(&interface->dev, DRV_NAME ": netdev registered as %s\n",
             pdev->netdev->name);

    dev_info(&interface->dev, DRV_NAME ": probe() success\n");
    return 0;
}

static void pico_disconnect(struct usb_interface* interface) {
    struct pico_dev* pdev = usb_get_intfdata(interface);

    dev_info(&interface->dev, DRV_NAME ": disconnect()\n");

    usb_set_intfdata(interface, NULL);
    if (!pdev) return;

    pdev->disconnected = true;
    cancel_delayed_work_sync(&pdev->ctrl_work);
    pdev->ctrl_cmd = PICO_CTRL_NONE;
    if (pdev->netdev)
        netif_stop_queue(pdev->netdev);
    if (pdev->netdev)
        netif_carrier_off(pdev->netdev);

    // stop RX
    if (pdev->rx_urb)
        usb_kill_urb(pdev->rx_urb);

    if (pdev->rx_urb)
        usb_free_urb(pdev->rx_urb);

    // stop TX
    if (pdev->tx_urb)
        usb_kill_urb(pdev->tx_urb);

    if (pdev->tx_urb)
        usb_free_urb(pdev->tx_urb);

    kfree(pdev->rx_buf);
    kfree(pdev->tx_buf);
    kfree(pdev->fr_buf);
    debugfs_remove_recursive(pdev->dbg_dir);
    if (pdev->netdev) {
        unregister_netdev(pdev->netdev);
        pico_cfg80211_deinit(pdev->cfg);
        pdev->cfg = NULL;
        free_netdev(pdev->netdev);
    }

    usb_put_dev(pdev->udev);
    kfree(pdev);
}

static const struct usb_device_id pico_table[] = {
    {USB_DEVICE(PICO_USB_VID, PICO_USB_PID)},
    {} /* terminating entry */
};
MODULE_DEVICE_TABLE(usb, pico_table);

static struct usb_driver pico_driver = {
    .name = DRV_NAME,
    .probe = pico_probe,
    .disconnect = pico_disconnect,
    .id_table = pico_table,
};

module_usb_driver(pico_driver);

MODULE_AUTHOR("Dao Truc Mai");
MODULE_DESCRIPTION("USB Wi-Fi adapter");
MODULE_LICENSE("GPL");
MODULE_SOFTDEP("pre: cfg80211");
