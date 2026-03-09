// SPDX-License-Identifier: GPL-2.0
#include <linux/atomic.h>
#include <linux/debugfs.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/math64.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/udp.h>
#include <linux/usb.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <net/checksum.h>

#include "pico_wifi_cfg80211.h"
#define DRV_NAME "pico_usb_wifi"

static bool pico_debug;
module_param_named(debug, pico_debug, bool, 0644);
MODULE_PARM_DESC(debug, "Enable verbose bring-up logging");

static bool pico_perf;
module_param_named(perf, pico_perf, bool, 0644);
MODULE_PARM_DESC(perf, "Enable 1 Hz perf summary logging (throughput/drop counters)");

static bool pico_dhcp_force_broadcast;
module_param_named(dhcp_force_broadcast, pico_dhcp_force_broadcast, bool, 0644);
MODULE_PARM_DESC(dhcp_force_broadcast, "Set BOOTP broadcast flag on DHCPDISCOVER (optional)");

// Must match Pico firmware
#define PICO_USB_VID 0xCAFE
#define PICO_USB_PID 0x4001

// PHTM protocol
#define PWU_MAGIC 0x4D544850u // 'PHTM'
#define PWU_VER 0x01
#define PWU_HDR_LEN 16

// Message types
#define PWUSB_HELLO 0x01
#define PWUSB_HELLO_RSP 0x81
#define PWUSB_CMD_SCAN_START 0x10
#define PWUSB_CMD_CONNECT 0x12
#define PWUSB_CMD_DISCONNECT 0x13
#define PWUSB_CMD_GET_STATUS 0x14
#define PWUSB_CMD_BENCH_START 0x20
#define PWUSB_CMD_BENCH_STOP 0x21
#define PWUSB_EVT_SCAN_RESULT 0x90
#define PWUSB_EVT_SCAN_DONE 0x91
#define PWUSB_EVT_CONN_STATE 0x92
#define PWUSB_EVT_STATUS 0x93
#define PWUSB_DATA_TX_ETH 0xA0
#define PWUSB_DATA_RX_ETH 0xA1
#define PWUSB_DATA_BENCH_SINK 0xB0
#define PWUSB_DATA_BENCH_SRC 0xB1
#define PWUSB_EVT_ERROR 0xFF

// USB and framing buffer sizes. Full-speed bulk maxpacket is 64 bytes, so larger
// URBs reduce overhead. The framing buffer must be larger than a single URB
// because USB can split framed messages arbitrarily; we may have partial frame
// data left in the buffer when appending the next URB.
// Increase IN transfer size to improve Full-Speed bulk efficiency. This must be
// paired with sufficient stream-framer buffering for worst-case re-sync.
// RX URB size for device->host bulk IN path. Keep this in sync with what you
// want to test; it does not affect the benchmark OUT URB size.
#define PICO_USB_RX_URB_SIZE 16384
#define PICO_STREAM_FR_CAP 32768 // Must be > RX_URB_SIZE to handle full URB + leftover framing buffer data
#define PICO_USB_RX_URB_COUNT 8

#define PICO_USB_TX_URB_COUNT 16
// Real data-plane TX (host->device) benefits from batching multiple PWUSB frames
// into a single URB on Full-Speed USB. This is the per-URB buffer size.
#define PICO_USB_TX_BUF_SIZE 4096
// Bound how many Ethernet frames we pack into one URB to limit latency spikes
// for interactive traffic (ARP/ICMP/TCP ACKs) while still reducing overhead.
#define PICO_USB_TX_MAX_PKTS_PER_URB 4

// Limit TX software queue depth (in skbs) to bound memory when USB is backpressured.
#define PICO_USB_TX_SKB_Q_LIMIT 256

#define PICO_BENCH_OUT_URB_COUNT 16
#define PICO_BENCH_OUT_URB_SIZE 8192

struct pico_scan_result
{
    u8 bssid[6];
    u8 channel;
    s8 rssi;
    u16 security;
    u8 ssid_len;
    char ssid[33];
};

struct __packed phtm_connect_req
{
    u8 ssid_len;
    u8 key_type;
    u8 psk_len;
    u8 ssid[32];
    u8 psk[64];
};

struct __packed phtm_status_rsp
{
    u8 connected;
    u8 ssid_len;
    u8 ssid[32];
    u8 bssid[6];
    u8 channel;
    s8 rssi;
    u16 reserved;
};

struct __packed pwu_hdr
{
    __le32 magic;
    u8 version;
    u8 msg_type;
    u8 flags;
    u8 hdr_len;
    __le16 seq;
    __le16 payload_len;
    __le32 xid;
};

struct __packed phtm_hello_rsp
{
    __le16 dev_max_payload;
    __le16 dev_tx_queue_depth;
    __le32 dev_caps;
    u8 mac[6];
    u8 reserved[2];
};

struct __packed phtm_bench_start_req
{
    u8 dir; /* bit0: device->host source, bit1: host->device sink */
    __le16 payload_len;
};

struct pico_dev
{
    struct usb_device *udev;
    struct usb_interface *intf;

    u8 ep_in, ep_out;
    u16 ep_in_maxpkt, ep_out_maxpkt;

    // RX
    size_t rx_buf_size;
    struct urb *rx_urbs[PICO_USB_RX_URB_COUNT];
    u8 *rx_bufs[PICO_USB_RX_URB_COUNT];

    // Stream framer buffer
    u8 *fr_buf;
    size_t fr_len;
    size_t fr_cap;

    /* TX (async) */
    spinlock_t tx_lock;
    struct urb *tx_urbs[PICO_USB_TX_URB_COUNT];
    u8 *tx_bufs[PICO_USB_TX_URB_COUNT];
    unsigned long tx_busy_map; /* bit i => tx_urbs[i] in-flight */
    struct sk_buff_head tx_skb_q;
    u32 tx_skb_q_limit;
    struct work_struct tx_work;

    // Hello state
    bool got_hello;

    // SCAN state/results
    spinlock_t scan_lock;
    struct pico_scan_result scan_results[64];
    u8 scan_count;
    bool scan_in_progress;
    bool scan_done;
    u16 last_seq; // Track sequence number for messages

    // Connect/status state (OPEN only for now)
    bool conn_connected;
    char conn_ssid[33];
    u8 conn_ssid_len;
    u8 conn_bssid[6];
    u8 conn_channel;
    s8 conn_rssi;
    u16 conn_status;

    // debugfs
    struct dentry *dbg_dir;

    // net_device (data plane)
    struct net_device *netdev;
    struct pico_cfg80211 *cfg;

    /* RX: NAPI + GRO */
    struct napi_struct napi;
    struct sk_buff_head rx_skb_q;
    u32 rx_skb_q_limit;

    // Device capabilities (from HELLO_RSP)
    u16 dev_max_total;

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

    // perf counters (1 Hz summary when module param 'perf=1')
    struct delayed_work perf_work;
    u64 perf_usb_rx_urbs;
    u64 perf_usb_rx_bytes;
    u64 perf_stream_frames;
    u64 perf_stream_bad;
    u64 perf_data_rx_pkts;
    u64 perf_data_rx_bytes;
    u64 perf_data_rx_netif_drop;
    u64 perf_usb_tx_submits;
    u64 perf_usb_tx_bytes;
    u64 perf_usb_tx_eagain;

    // snapshot for delta printing
    u64 perf_last_usb_rx_bytes;
    u64 perf_last_data_rx_bytes;
    u64 perf_last_data_rx_netif_drop;
    u64 perf_last_usb_tx_bytes;
    u64 perf_last_usb_tx_eagain;

    // deferred control path
    struct delayed_work ctrl_work;
    u8 ctrl_cmd;
    char ctrl_ssid[32];
    u8 ctrl_ssid_len;
    char ctrl_psk[64];
    u8 ctrl_psk_len;
    u8 ctrl_key_type;
    bool ctrl_quiesce;

    // USB benchmark stats
    struct mutex bench_lock; /* protects bench start/stop and resource lifetime */

    bool bench_in_running;
    unsigned long bench_in_start_j;
    u64 bench_in_bytes;
    u64 bench_in_msgs;

    bool bench_out_running;
    unsigned long bench_out_start_j;
    u16 bench_out_payload_len;
    u16 bench_out_eff_payload_len;
    u16 bench_out_seq;
    u64 bench_out_bytes;
    u64 bench_out_urbs_done;
    u64 bench_out_errs;
    struct urb *bench_out_urbs[PICO_BENCH_OUT_URB_COUNT];
    u8 *bench_out_bufs[PICO_BENCH_OUT_URB_COUNT];
    size_t bench_out_len;
};

static int pico_napi_poll(struct napi_struct *napi, int budget)
{
    struct pico_dev *pdev = container_of(napi, struct pico_dev, napi);
    int work_done = 0;

    while (work_done < budget)
    {
        struct sk_buff *skb = skb_dequeue(&pdev->rx_skb_q);

        if (!skb)
            break;

        /* GRO reduces per-packet TCP/IP stack overhead under load. */
        napi_gro_receive(napi, skb);

        work_done++;
    }

    if (work_done < budget)
    {
        napi_complete_done(napi, work_done);
        /* New packets will re-schedule NAPI from the USB RX path. */
    }

    return work_done;
}

static u16 pico_bench_cap_payload(struct pico_dev *pdev, u16 payload_len)
{
    u16 max_plen = payload_len;

    /* Respect device max total message size (header + payload). */
    if (pdev && pdev->dev_max_total)
    {
        u16 dev_max_plen = (pdev->dev_max_total > PWU_HDR_LEN) ? (pdev->dev_max_total - PWU_HDR_LEN) : 0;
        if (dev_max_plen && max_plen > dev_max_plen)
            max_plen = dev_max_plen;
    }

    /* Respect our TX buffer size (we need hdr + payload in a single buffer). */
    if (max_plen > (u16)(PICO_USB_TX_BUF_SIZE - PWU_HDR_LEN))
        max_plen = (u16)(PICO_USB_TX_BUF_SIZE - PWU_HDR_LEN);

    return max_plen;
}

static size_t pico_build_bench_out_buf(struct pico_dev *pdev, u8 *buf, size_t cap, u16 payload_len)
{
    size_t off = 0;
    u16 max_payload = payload_len;
    u16 seq;

    if (!pdev || !buf || cap < PWU_HDR_LEN)
        return 0;

    /* Respect device max total message size (header + payload). */
    if (pdev->dev_max_total)
    {
        u16 max_plen = (pdev->dev_max_total > PWU_HDR_LEN) ? (pdev->dev_max_total - PWU_HDR_LEN) : 0;
        if (max_payload > max_plen)
            max_payload = max_plen;
    }

    if (!max_payload)
        return 0;

    seq = pdev->bench_out_seq;

    while (off + PWU_HDR_LEN + (size_t)max_payload <= cap)
    {
        struct pwu_hdr h = {
            .magic = cpu_to_le32(PWU_MAGIC),
            .version = PWU_VER,
            .msg_type = PWUSB_DATA_BENCH_SINK,
            .flags = 0,
            .hdr_len = PWU_HDR_LEN,
            .seq = cpu_to_le16(seq++),
            .payload_len = cpu_to_le16(max_payload),
            .xid = cpu_to_le32(0),
        };
        memcpy(buf + off, &h, sizeof(h));
        memset(buf + off + PWU_HDR_LEN, 0x5A, max_payload);
        off += PWU_HDR_LEN + (size_t)max_payload;
    }

    pdev->bench_out_seq = seq;
    return off;
}

static void pico_bench_out_complete(struct urb *urb)
{
    struct pico_dev *pdev = urb ? urb->context : NULL;
    int ret;

    if (!pdev || !urb)
        return;

    if (urb->status == 0)
    {
        pdev->bench_out_bytes += (u64)urb->actual_length;
        pdev->bench_out_urbs_done++;
    }
    else if (urb->status != -ENOENT && urb->status != -ESHUTDOWN && urb->status != -ECONNRESET)
    {
        pdev->bench_out_errs++;
    }

    if (!pdev->bench_out_running || pdev->disconnected)
        return;

    usb_fill_bulk_urb(urb, pdev->udev,
                      usb_sndbulkpipe(pdev->udev, pdev->ep_out),
                      urb->transfer_buffer, (int)pdev->bench_out_len,
                      pico_bench_out_complete, pdev);
    ret = usb_submit_urb(urb, GFP_ATOMIC);
    if (ret)
    {
        pdev->bench_out_errs++;
        pdev->bench_out_running = false;
    }
}

static bool pico_parse_dhcp4(const u8 *frame, size_t len,
                             __be32 *sip, __be32 *dip,
                             u16 *sport, u16 *dport,
                             u8 *dhcp_msg_type, u32 *dhcp_xid,
                             __be32 *dhcp_yiaddr, u16 *dhcp_flags)
{
    struct ethhdr eh;
    struct iphdr iph;
    struct udphdr udph;
    size_t ihl;
    size_t ip_off = ETH_HLEN;
    size_t udp_off;
    size_t udp_payload_off;
    size_t udp_payload_len;
    const u8 *bootp;
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
        *dhcp_xid = ntohl(*((const __be32 *)(bootp + 4)));
    if (dhcp_flags)
        *dhcp_flags = ntohs(*((const __be16 *)(bootp + 10)));
    if (dhcp_yiaddr)
        *dhcp_yiaddr = *((const __be32 *)(bootp + 16));

    // Options start at BOOTP fixed header (236) + magic cookie (4) = 240
    opts_off = 240;
    if (udp_payload_len > opts_off + 3 && dhcp_msg_type)
    {
        const u8 *opt = bootp + opts_off;
        size_t left = udp_payload_len - opts_off;
        while (left > 0)
        {
            u8 code = opt[0];
            u8 olen;
            if (code == 0)
            { // pad
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
            if (code == 53 && olen >= 1)
            { // DHCP message type
                *dhcp_msg_type = opt[2];
                break;
            }
            opt += 2 + olen;
            left -= 2 + olen;
        }
    }
    return true;
}

static void pico_dhcp_set_broadcast_flag(u8 *frame, size_t len)
{
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

static void pico_kick_rx(struct pico_dev *pdev);
static int pico_send_hello(struct pico_dev *pdev);
static int pico_send_scan_start(struct pico_dev *pdev);
static int pico_send_connect(struct pico_dev *pdev,
                             const char *ssid, u8 ssid_len,
                             const char *psk, u8 psk_len,
                             u8 key_type);
static int pico_send_disconnect(struct pico_dev *pdev);
static int pico_send_get_status(struct pico_dev *pdev);
static void pico_scan_clear(struct pico_dev *pdev);
static void pico_handle_scan_result(struct pico_dev *pdev, const u8 *payload, size_t plen);
static void pico_handle_scan_done(struct pico_dev *pdev);
static void pico_handle_conn_state(struct pico_dev *pdev, const u8 *payload, size_t plen);
static void pico_handle_status(struct pico_dev *pdev, const u8 *payload, size_t plen);
static void pico_handle_data_rx(struct pico_dev *pdev, const u8 *payload, size_t plen);
static void pico_ctrl_work_fn(struct work_struct *work);
static void pico_perf_work_fn(struct work_struct *work);
static void pico_tx_work_fn(struct work_struct *work);

struct pico_tx_ctx
{
    struct pico_dev *pdev;
    u8 slot;
    bool is_dhcp;
    u16 seq;
    u32 total;
};

static int pico_tx_reserve_slot(struct pico_dev *pdev, u8 *slot_out)
{
    unsigned long flags;
    int i;

    if (!pdev || !slot_out)
        return -EINVAL;

    spin_lock_irqsave(&pdev->tx_lock, flags);
    for (i = 0; i < PICO_USB_TX_URB_COUNT; i++)
    {
        if (!(pdev->tx_busy_map & (1UL << i)))
        {
            pdev->tx_busy_map |= (1UL << i);
            *slot_out = (u8)i;
            if (pdev->tx_urbs[i] && pdev->tx_urbs[i]->context)
            {
                struct pico_tx_ctx *ctx = pdev->tx_urbs[i]->context;
                ctx->is_dhcp = false;
                ctx->seq = 0;
                ctx->total = 0;
            }
            spin_unlock_irqrestore(&pdev->tx_lock, flags);
            return 0;
        }
    }
    spin_unlock_irqrestore(&pdev->tx_lock, flags);
    return -EAGAIN;
}

static void pico_tx_release_slot(struct pico_dev *pdev, u8 slot)
{
    unsigned long flags;
    if (!pdev || slot >= PICO_USB_TX_URB_COUNT)
        return;
    spin_lock_irqsave(&pdev->tx_lock, flags);
    pdev->tx_busy_map &= ~(1UL << slot);
    spin_unlock_irqrestore(&pdev->tx_lock, flags);
}

static void pico_free_rx_resources(struct pico_dev *pdev)
{
    int i;
    if (!pdev)
        return;
    for (i = 0; i < PICO_USB_RX_URB_COUNT; i++)
    {
        if (pdev->rx_urbs[i])
        {
            usb_free_urb(pdev->rx_urbs[i]);
            pdev->rx_urbs[i] = NULL;
        }
        kfree(pdev->rx_bufs[i]);
        pdev->rx_bufs[i] = NULL;
    }
}

static void pico_free_tx_resources(struct pico_dev *pdev)
{
    int i;
    if (!pdev)
        return;
    for (i = 0; i < PICO_USB_TX_URB_COUNT; i++)
    {
        if (pdev->tx_urbs[i])
        {
            kfree(pdev->tx_urbs[i]->context);
            pdev->tx_urbs[i]->context = NULL;
            usb_free_urb(pdev->tx_urbs[i]);
            pdev->tx_urbs[i] = NULL;
        }
        kfree(pdev->tx_bufs[i]);
        pdev->tx_bufs[i] = NULL;
    }
    pdev->tx_busy_map = 0;
}

enum
{
    PICO_CTRL_NONE = 0,
    PICO_CTRL_CONNECT = 1,
    PICO_CTRL_DISCONNECT = 2,
};

struct pico_netdev_priv
{
    struct pico_dev *pdev;
};

static void pico_stream_resync(struct pico_dev *pdev)
{
    size_t i;

    // Find the next possible 'PHTM' header in the accumulated stream.
    for (i = 1; i + 4 <= pdev->fr_len; i++)
    {
        u32 magic;
        memcpy(&magic, pdev->fr_buf + i, sizeof(magic));
        if (le32_to_cpu(magic) == PWU_MAGIC)
        {
            if (i > 0)
            {
                memmove(pdev->fr_buf, pdev->fr_buf + i, pdev->fr_len - i);
                pdev->fr_len -= i;
            }
            return;
        }
    }

    // No magic found: keep last 3 bytes in case 'PHTM' spans URB boundary.
    if (pdev->fr_len > 3)
    {
        memmove(pdev->fr_buf, pdev->fr_buf + (pdev->fr_len - 3), 3);
        pdev->fr_len = 3;
    }
}

static void pico_process_stream(struct pico_dev *pdev, const u8 *data, size_t n)
{
    // append to framer buffer (simple linear buffer for now)
    if (n == 0)
        return;

    if (pdev->fr_len + n > pdev->fr_cap)
    {
        // We've fallen behind (or got a burst). Drop old backlog and keep a tail
        // so we can resync on the next URB without O(n^2) shifting.
        pdev->perf_stream_bad++;
        pico_stream_resync(pdev);
        if (pdev->fr_len + n > pdev->fr_cap)
        {
            // Still too large (should be rare). Drop everything.
            pdev->perf_stream_bad++;
            pdev->fr_len = 0;
            return;
        }
    }

    memcpy(pdev->fr_buf + pdev->fr_len, data, n);
    pdev->fr_len += n;

    // parse as many framed messages as possible
    while (pdev->fr_len >= PWU_HDR_LEN)
    {
        struct pwu_hdr h;
        u32 magic;
        u16 plen;
        size_t total;

        memcpy(&h, pdev->fr_buf, sizeof(h));
        magic = le32_to_cpu(h.magic);

        // resync by shifting one byte until magic/version/hdrlen match
        if (magic != PWU_MAGIC || h.version != PWU_VER || h.hdr_len != PWU_HDR_LEN)
        {
            pdev->perf_stream_bad++;
            pico_stream_resync(pdev);
            continue;
        }

        plen = le16_to_cpu(h.payload_len);
        total = PWU_HDR_LEN + plen;

        if (total > pdev->fr_cap)
        {
            // invalid length -> resync
            pdev->perf_stream_bad++;
            pico_stream_resync(pdev);
            continue;
        }

        if (pdev->fr_len < total)
        {
            // wait for more
            return;
        }

        // We have one complete message
        pdev->perf_stream_frames++;
        if (h.msg_type == PWUSB_HELLO_RSP)
        {
            struct phtm_hello_rsp rsp;
            dev_info(&pdev->intf->dev, DRV_NAME ": <- HELLO_RSP seq=%u plen=%u\n",
                     le16_to_cpu(h.seq), plen);
            pdev->got_hello = true;
            if (plen >= sizeof(rsp))
            {
                memcpy(&rsp, pdev->fr_buf + PWU_HDR_LEN, sizeof(rsp));
                pdev->dev_max_total = le16_to_cpu(rsp.dev_max_payload);
                if (pdev->netdev)
                    eth_hw_addr_set(pdev->netdev, rsp.mac);
                dev_info(&pdev->intf->dev, DRV_NAME ": MAC %pM\n", rsp.mac);
            }
            /* Handshake complete, trigger WiFi scan */
            dev_info(&pdev->intf->dev, DRV_NAME ": handshake complete, starting WiFi scan\n");
            pico_send_scan_start(pdev);
        }
        else if (h.msg_type == PWUSB_EVT_SCAN_RESULT)
        {
            dev_dbg(&pdev->intf->dev, DRV_NAME ": <- SCAN_RESULT seq=%u plen=%u\n",
                    le16_to_cpu(h.seq), plen);
            pico_handle_scan_result(pdev, pdev->fr_buf + PWU_HDR_LEN, plen);
        }
        else if (h.msg_type == PWUSB_EVT_SCAN_DONE)
        {
            dev_info(&pdev->intf->dev, DRV_NAME ": <- SCAN_DONE seq=%u plen=%u\n",
                     le16_to_cpu(h.seq), plen);
            pico_handle_scan_done(pdev);
        }
        else if (h.msg_type == PWUSB_EVT_CONN_STATE)
        {
            dev_info(&pdev->intf->dev, DRV_NAME ": <- CONN_STATE seq=%u plen=%u\n",
                     le16_to_cpu(h.seq), plen);
            pico_handle_conn_state(pdev, pdev->fr_buf + PWU_HDR_LEN, plen);
        }
        else if (h.msg_type == PWUSB_EVT_STATUS)
        {
            dev_info(&pdev->intf->dev, DRV_NAME ": <- STATUS seq=%u plen=%u\n",
                     le16_to_cpu(h.seq), plen);
            pico_handle_status(pdev, pdev->fr_buf + PWU_HDR_LEN, plen);
        }
        else if (h.msg_type == PWUSB_DATA_RX_ETH)
        {
            pico_handle_data_rx(pdev, pdev->fr_buf + PWU_HDR_LEN, plen);
        }
        else if (h.msg_type == PWUSB_DATA_BENCH_SRC)
        {
            if (pdev->bench_in_running)
            {
                pdev->bench_in_bytes += (u64)plen;
                pdev->bench_in_msgs++;
            }
        }
        else if (h.msg_type == PWUSB_EVT_ERROR)
        {
            u32 st = 0;
            if (plen >= sizeof(st))
                memcpy(&st, pdev->fr_buf + PWU_HDR_LEN, sizeof(st));
            dev_warn(&pdev->intf->dev, DRV_NAME ": <- ERROR seq=%u st=%u\n",
                     le16_to_cpu(h.seq), le32_to_cpu(st));
        }
        else
        {
            dev_info(&pdev->intf->dev, DRV_NAME ": <- msg type=0x%02x seq=%u plen=%u\n",
                     h.msg_type, le16_to_cpu(h.seq), plen);
        }

        // consume this message
        if (pdev->fr_len > total)
            memmove(pdev->fr_buf, pdev->fr_buf + total, pdev->fr_len - total);
        pdev->fr_len -= total;
    }
}

static void pico_rx_complete(struct urb *urb)
{
    struct pico_dev *pdev = urb->context;
    int status = urb->status;

    if (!pdev)
        return;

    if (status == 0)
    {
        dev_dbg(&pdev->intf->dev, DRV_NAME ": RX urb complete actual_length=%d\n", urb->actual_length);
        pdev->perf_usb_rx_urbs++;
        if (urb->actual_length > 0)
            pdev->perf_usb_rx_bytes += (u64)urb->actual_length;
        if (urb->actual_length > 0)
            pico_process_stream(pdev, urb->transfer_buffer, urb->actual_length);
    }
    else if (status == -EOVERFLOW)
    {
        dev_dbg(&pdev->intf->dev, DRV_NAME ": RX urb overflow (buffer too small)\n");
    }
    else
    {
        /*
         * On disconnect/unlink, usbcore completes RX URBs with -ECONNRESET/-ENOENT.
         * Don't warn and don't resubmit in those cases; otherwise we can race
         * disconnect() teardown and create noisy/log-spam loops.
         */
        if (!pdev->disconnected &&
            status != -ECONNRESET &&
            status != -ENOENT &&
            status != -ESHUTDOWN &&
            status != -ENODEV)
            dev_warn(&pdev->intf->dev, DRV_NAME ": RX urb status=%d\n", status);
    }

    // Resubmit unless device is gone
    if (!pdev->disconnected && (status == 0 || status == -EOVERFLOW))
    {
        int ret = usb_submit_urb(urb, GFP_ATOMIC);
        if (ret)
            dev_warn(&pdev->intf->dev, DRV_NAME ": usb_submit_urb RX failed: %d\n", ret);
    }
}

static void pico_kick_rx(struct pico_dev *pdev)
{
    int i;
    int ret;

    for (i = 0; i < PICO_USB_RX_URB_COUNT; i++)
    {
        if (!pdev->rx_urbs[i] || !pdev->rx_bufs[i])
            continue;

        usb_fill_bulk_urb(pdev->rx_urbs[i],
                          pdev->udev,
                          usb_rcvbulkpipe(pdev->udev, pdev->ep_in),
                          pdev->rx_bufs[i],
                          pdev->rx_buf_size,
                          pico_rx_complete,
                          pdev);

        ret = usb_submit_urb(pdev->rx_urbs[i], GFP_ATOMIC);
        if (ret)
            dev_warn(&pdev->intf->dev, DRV_NAME ": usb_submit_urb RX[%d] failed: %d\n", i, ret);
        else
            dev_dbg(&pdev->intf->dev, DRV_NAME ": RX urb[%d] submitted len=%zu\n", i, pdev->rx_buf_size);
    }
}

static void pico_tx_complete(struct urb *urb)
{
    struct pico_tx_ctx *ctx = urb ? urb->context : NULL;
    struct pico_dev *pdev = ctx ? ctx->pdev : NULL;
    int status = urb->status;

    if (!pdev)
        return;

    if (pico_debug && ctx->is_dhcp && pdev->dhcp_tx_complete_dbg_count < 10)
    {
        dev_info(&pdev->intf->dev,
                 DRV_NAME ": TX DHCP complete status=%d actual=%d seq=%u total=%u\n",
                 status, urb->actual_length, ctx->seq, ctx->total);
        pdev->dhcp_tx_complete_dbg_count++;
    }

    if (status)
        dev_warn(&pdev->intf->dev, DRV_NAME ": TX urb status=%d\n", status);
    else
        dev_dbg(&pdev->intf->dev, DRV_NAME ": TX complete len=%d\n", urb->actual_length);

    /* Mark slot as free */
    pico_tx_release_slot(pdev, ctx->slot);
    ctx->is_dhcp = false;
    if (!pdev->disconnected)
    {
        // Drain any queued TX skbs now that a slot is free.
        queue_work(system_highpri_wq, &pdev->tx_work);
        if (pdev->netdev && pdev->conn_connected && netif_carrier_ok(pdev->netdev))
            netif_wake_queue(pdev->netdev);
    }
}

static int pico_tx_submit_gfp(struct pico_dev *pdev, const u8 *data, size_t n, gfp_t gfp)
{
    int ret;
    u8 slot;
    struct pico_tx_ctx *ctx;

    if (!pdev || pdev->disconnected)
        return -ENODEV;

    if (n > PICO_USB_TX_BUF_SIZE)
        return -EINVAL;

    ret = pico_tx_reserve_slot(pdev, &slot);
    if (ret)
    {
        pdev->perf_usb_tx_eagain++;
        return -EAGAIN;
    }

    memcpy(pdev->tx_bufs[slot], data, n);
    ctx = (struct pico_tx_ctx *)pdev->tx_urbs[slot]->context;
    if (!ctx)
    {
        // Should not happen; set in probe().
        pico_tx_release_slot(pdev, slot);
        return -EINVAL;
    }

    usb_fill_bulk_urb(pdev->tx_urbs[slot],
                      pdev->udev,
                      usb_sndbulkpipe(pdev->udev, pdev->ep_out),
                      pdev->tx_bufs[slot],
                      n,
                      pico_tx_complete,
                      ctx);

    ret = usb_submit_urb(pdev->tx_urbs[slot], gfp);
    if (ret)
    {
        pico_tx_release_slot(pdev, slot);
        dev_warn(&pdev->intf->dev, DRV_NAME ": usb_submit_urb TX failed: %d\n", ret);
    }
    else
    {
        pdev->perf_usb_tx_submits++;
        pdev->perf_usb_tx_bytes += (u64)n;
        dev_dbg(&pdev->intf->dev, DRV_NAME ": -> TX submitted len=%zu\n", n);
    }

    return ret;
}

static int pico_tx_submit(struct pico_dev *pdev, const u8 *data, size_t n)
{
    return pico_tx_submit_gfp(pdev, data, n, GFP_KERNEL);
}

static void pico_tx_work_fn(struct work_struct *work)
{
    struct pico_dev *pdev = container_of(work, struct pico_dev, tx_work);
    struct net_device *ndev = pdev ? pdev->netdev : NULL;
    int loops = 0;

    if (!pdev || pdev->disconnected || !pdev->udev)
        return;

    // Drain queued skbs into as many in-flight URBs as we have slots for.
    // Limit outer loop to avoid monopolizing CPU.
    while (loops++ < PICO_USB_TX_URB_COUNT)
    {
        struct sk_buff *skb;
        u8 slot;
        int ret;
        u8 *buf;
        size_t off = 0;
        u32 pkts = 0;
        u32 bytes = 0;

        if (skb_queue_empty(&pdev->tx_skb_q))
            break;

        ret = pico_tx_reserve_slot(pdev, &slot);
        if (ret)
            break; // no slot, will be re-kicked on completion

        buf = pdev->tx_bufs[slot];

        while ((skb = skb_dequeue(&pdev->tx_skb_q)) != NULL)
        {
            struct pwu_hdr h;
            size_t total = PWU_HDR_LEN + skb->len;
            bool is_dhcp = false;

            if (off + total > PICO_USB_TX_BUF_SIZE)
            {
                // Doesn't fit; put it back for the next URB.
                skb_queue_head(&pdev->tx_skb_q, skb);
                break;
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

            memcpy(buf + off, &h, sizeof(h));
            skb_copy_bits(skb, 0, buf + off + PWU_HDR_LEN, skb->len);

            // Optional: DHCP broadcast flag tweak can be applied to the copied frame.
            if (pico_dhcp_force_broadcast)
            {
                u8 hdr[96];
                size_t hdr_len = min_t(size_t, skb->len, sizeof(hdr));
                __be32 sip = 0, dip = 0;
                u16 sport = 0, dport = 0;
                u8 dhcp_type = 0;
                u32 dhcp_xid = 0;
                __be32 yiaddr = 0;
                u16 flags = 0;

                if (hdr_len >= ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) &&
                    !skb_copy_bits(skb, 0, hdr, hdr_len) &&
                    pico_parse_dhcp4(hdr, hdr_len, &sip, &dip, &sport, &dport,
                                     &dhcp_type, &dhcp_xid, &yiaddr, &flags))
                {
                    is_dhcp = true;
                }
                if (is_dhcp)
                    pico_dhcp_set_broadcast_flag(buf + off + PWU_HDR_LEN, skb->len);
            }

            off += total;
            pkts++;
            bytes += (u32)skb->len;

            dev_kfree_skb_any(skb);

            // Bound per-URB work: stop if we can't fit even the smallest frame.
            if (PICO_USB_TX_BUF_SIZE - off < PWU_HDR_LEN + 64)
                break;
            if (pkts >= PICO_USB_TX_MAX_PKTS_PER_URB)
                break;
        }

        if (!pkts)
        {
            pico_tx_release_slot(pdev, slot);
            break;
        }

        usb_fill_bulk_urb(pdev->tx_urbs[slot],
                          pdev->udev,
                          usb_sndbulkpipe(pdev->udev, pdev->ep_out),
                          buf,
                          off,
                          pico_tx_complete,
                          pdev->tx_urbs[slot]->context);

        ret = usb_submit_urb(pdev->tx_urbs[slot], GFP_ATOMIC);
        if (ret)
        {
            pico_tx_release_slot(pdev, slot);
            pdev->perf_usb_tx_eagain++;
            if (ndev)
                ndev->stats.tx_dropped += pkts;
            break;
        }

        pdev->perf_usb_tx_submits++;
        pdev->perf_usb_tx_bytes += (u64)off;
        if (ndev)
        {
            ndev->stats.tx_packets += pkts;
            ndev->stats.tx_bytes += bytes;
        }
    }

    if (ndev && netif_queue_stopped(ndev) &&
        skb_queue_len(&pdev->tx_skb_q) < (pdev->tx_skb_q_limit / 2) &&
        pdev->conn_connected && netif_carrier_ok(ndev))
    {
        netif_wake_queue(ndev);
    }
}

static int pico_send_bench_start(struct pico_dev *pdev, u8 dir, u16 payload_len)
{
    u8 msg[PWU_HDR_LEN + sizeof(struct phtm_bench_start_req)];
    struct pwu_hdr h;
    struct phtm_bench_start_req req;

    if (!pdev)
        return -ENODEV;

    req.dir = dir;
    req.payload_len = cpu_to_le16(pico_bench_cap_payload(pdev, payload_len));

    memset(&h, 0, sizeof(h));
    h.magic = cpu_to_le32(PWU_MAGIC);
    h.version = PWU_VER;
    h.msg_type = PWUSB_CMD_BENCH_START;
    h.flags = 0;
    h.hdr_len = PWU_HDR_LEN;
    h.seq = cpu_to_le16(pdev->last_seq++);
    h.payload_len = cpu_to_le16(sizeof(req));
    h.xid = cpu_to_le32(0);

    memcpy(msg, &h, sizeof(h));
    memcpy(msg + PWU_HDR_LEN, &req, sizeof(req));

    return pico_tx_submit(pdev, msg, sizeof(msg));
}

static int pico_send_bench_stop(struct pico_dev *pdev)
{
    u8 msg[PWU_HDR_LEN];
    struct pwu_hdr h;

    if (!pdev)
        return -ENODEV;

    memset(&h, 0, sizeof(h));
    h.magic = cpu_to_le32(PWU_MAGIC);
    h.version = PWU_VER;
    h.msg_type = PWUSB_CMD_BENCH_STOP;
    h.flags = 0;
    h.hdr_len = PWU_HDR_LEN;
    h.seq = cpu_to_le16(pdev->last_seq++);
    h.payload_len = cpu_to_le16(0);
    h.xid = cpu_to_le32(0);

    memcpy(msg, &h, sizeof(h));
    return pico_tx_submit(pdev, msg, sizeof(msg));
}

/* Send a HELLO message (non-blocking via TX URB) */
static int pico_send_hello(struct pico_dev *pdev)
{
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
static int pico_send_scan_start(struct pico_dev *pdev)
{
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
    if (ret == 0)
    {
        dev_info(&pdev->intf->dev, DRV_NAME ": SCAN_START sent (seq=%u)\n",
                 le16_to_cpu(h.seq));
    }

    return ret;
}

/* Send CONNECT command (OPEN only) */
static int pico_send_connect(struct pico_dev *pdev,
                             const char *ssid, u8 ssid_len,
                             const char *psk, u8 psk_len,
                             u8 key_type)
{
    u8 msg[PWU_HDR_LEN + 3 + 32 + 64];
    struct pwu_hdr h;
    int ret;
    u8 *p;

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
    if (ret == 0)
    {
        dev_info(&pdev->intf->dev, DRV_NAME ": CONNECT sent (seq=%u ssid=%.*s psk=%u)\n",
                 le16_to_cpu(h.seq), ssid_len, ssid, psk_len);
    }

    return ret;
}

/* Send DISCONNECT command */
static int pico_send_disconnect(struct pico_dev *pdev)
{
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

int pico_ctrl_scan_start(struct pico_dev *pdev)
{
    unsigned long flags;
    int ret;

    if (!pdev)
        return -ENODEV;

    spin_lock_irqsave(&pdev->scan_lock, flags);
    if (pdev->scan_in_progress)
    {
        spin_unlock_irqrestore(&pdev->scan_lock, flags);
        return -EBUSY;
    }
    pdev->scan_in_progress = true;
    pdev->scan_done = false;
    pdev->scan_count = 0;
    spin_unlock_irqrestore(&pdev->scan_lock, flags);

    ret = pico_send_scan_start(pdev);
    if (ret)
    {
        spin_lock_irqsave(&pdev->scan_lock, flags);
        pdev->scan_in_progress = false;
        spin_unlock_irqrestore(&pdev->scan_lock, flags);
        return ret;
    }

    return 0;
}

int pico_ctrl_connect(struct pico_dev *pdev,
                      const u8 *ssid, u8 ssid_len,
                      const u8 *psk, u8 psk_len,
                      u8 key_type)
{
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

int pico_ctrl_disconnect(struct pico_dev *pdev)
{
    if (!pdev)
        return -ENODEV;
    pdev->ctrl_cmd = PICO_CTRL_DISCONNECT;
    schedule_delayed_work(&pdev->ctrl_work, 0);
    return 0;
}

static void pico_ctrl_work_fn(struct work_struct *work)
{
    struct pico_dev *pdev = container_of(work, struct pico_dev, ctrl_work.work);
    int ret;

    if (!pdev || pdev->disconnected)
        return;

    switch (pdev->ctrl_cmd)
    {
    case PICO_CTRL_CONNECT:
        ret = pico_send_connect(pdev,
                                pdev->ctrl_ssid,
                                pdev->ctrl_ssid_len,
                                pdev->ctrl_psk_len ? pdev->ctrl_psk : NULL,
                                pdev->ctrl_psk_len,
                                pdev->ctrl_key_type);
        if (ret == -EAGAIN)
        {
            dev_info(&pdev->intf->dev, DRV_NAME ": CONNECT busy, will retry\n");
            schedule_delayed_work(&pdev->ctrl_work, msecs_to_jiffies(100));
            return;
        }
        if (ret)
            dev_warn(&pdev->intf->dev, DRV_NAME ": CONNECT send failed: %d\n", ret);
        pdev->ctrl_cmd = PICO_CTRL_NONE;
        return;
    case PICO_CTRL_DISCONNECT:
        if (!pdev->ctrl_quiesce && pdev->netdev)
        {
            netif_stop_queue(pdev->netdev);
            netif_carrier_off(pdev->netdev);
            pdev->ctrl_quiesce = true;
        }
        ret = pico_send_disconnect(pdev);
        if (ret == -EAGAIN)
        {
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

static void pico_perf_work_fn(struct work_struct *work)
{
    struct pico_dev *pdev = container_of(work, struct pico_dev, perf_work.work);
    u64 d_usb_rx_bytes, d_data_rx_bytes, d_netif_drop, d_usb_tx_bytes, d_usb_tx_eagain;

    if (!pdev || pdev->disconnected)
        return;

    if (pico_perf)
    {
        d_usb_rx_bytes = pdev->perf_usb_rx_bytes - pdev->perf_last_usb_rx_bytes;
        d_data_rx_bytes = pdev->perf_data_rx_bytes - pdev->perf_last_data_rx_bytes;
        d_netif_drop = pdev->perf_data_rx_netif_drop - pdev->perf_last_data_rx_netif_drop;
        d_usb_tx_bytes = pdev->perf_usb_tx_bytes - pdev->perf_last_usb_tx_bytes;
        d_usb_tx_eagain = pdev->perf_usb_tx_eagain - pdev->perf_last_usb_tx_eagain;

        pdev->perf_last_usb_rx_bytes = pdev->perf_usb_rx_bytes;
        pdev->perf_last_data_rx_bytes = pdev->perf_data_rx_bytes;
        pdev->perf_last_data_rx_netif_drop = pdev->perf_data_rx_netif_drop;
        pdev->perf_last_usb_tx_bytes = pdev->perf_usb_tx_bytes;
        pdev->perf_last_usb_tx_eagain = pdev->perf_usb_tx_eagain;

        dev_info(&pdev->intf->dev,
                 DRV_NAME ": PERF 1s: usb_rx=%llu B data_rx=%llu B netif_drop=%llu | usb_tx=%llu B tx_eagain=%llu | stream_frames=%llu stream_bad=%llu\n",
                 d_usb_rx_bytes, d_data_rx_bytes, d_netif_drop,
                 d_usb_tx_bytes, d_usb_tx_eagain,
                 pdev->perf_stream_frames, pdev->perf_stream_bad);
    }

    schedule_delayed_work(&pdev->perf_work, HZ);
}

/* Send GET_STATUS command */
static int pico_send_get_status(struct pico_dev *pdev)
{
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

static void pico_scan_clear(struct pico_dev *pdev)
{
    unsigned long flags;

    spin_lock_irqsave(&pdev->scan_lock, flags);
    pdev->scan_count = 0;
    pdev->scan_in_progress = false;
    pdev->scan_done = false;
    spin_unlock_irqrestore(&pdev->scan_lock, flags);
}

static void pico_handle_scan_result(struct pico_dev *pdev, const u8 *payload, size_t plen)
{
    struct pico_scan_result *entry = NULL;
    unsigned long flags;
    __le16 sec_le;
    u8 ssid_len;
    u8 i;
    char ssid_buf[33];
    u8 bssid[6];
    u8 channel;
    s8 rssi;
    u16 security;

    if (plen < 11)
    {
        dev_dbg(&pdev->intf->dev, DRV_NAME ": SCAN_RESULT too short (%zu)\n", plen);
        return;
    }

    ssid_len = payload[10];
    if (ssid_len > 32)
        ssid_len = 32;

    if (plen < (size_t)(11 + ssid_len))
    {
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

    for (i = 0; i < pdev->scan_count; i++)
    {
        if (!memcmp(pdev->scan_results[i].bssid, payload, 6))
        {
            entry = &pdev->scan_results[i];
            break;
        }
    }

    if (!entry)
    {
        if (pdev->scan_count >= ARRAY_SIZE(pdev->scan_results))
        {
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

    if (pico_debug)
    {
        dev_info(&pdev->intf->dev,
                 DRV_NAME ": SSID=\"%s\"  RSSI=%d  CH=%u  BSSID=%pM  SEC=0x%04x\n",
                 ssid_buf, rssi, channel, bssid, security);
    }
}

static void pico_handle_scan_done(struct pico_dev *pdev)
{
    unsigned long flags;

    spin_lock_irqsave(&pdev->scan_lock, flags);
    pdev->scan_in_progress = false;
    pdev->scan_done = true;
    spin_unlock_irqrestore(&pdev->scan_lock, flags);

    if (pdev->cfg)
        pico_cfg80211_scan_done(pdev->cfg, false);
}

static bool pico_fill_bssid_from_scan(struct pico_dev *pdev)
{
    unsigned long flags;
    struct pico_scan_result *best = NULL;
    u8 i;

    if (!pdev || pdev->conn_ssid_len == 0)
        return false;

    spin_lock_irqsave(&pdev->scan_lock, flags);
    for (i = 0; i < pdev->scan_count; i++)
    {
        struct pico_scan_result *r = &pdev->scan_results[i];
        if (r->ssid_len != pdev->conn_ssid_len)
            continue;
        if (memcmp(r->ssid, pdev->conn_ssid, r->ssid_len) != 0)
            continue;
        if (!best || r->rssi > best->rssi)
            best = r;
    }
    if (best)
    {
        memcpy(pdev->conn_bssid, best->bssid, sizeof(pdev->conn_bssid));
        pdev->conn_channel = best->channel;
        pdev->conn_rssi = best->rssi;
    }
    spin_unlock_irqrestore(&pdev->scan_lock, flags);

    return best != NULL;
}

static void pico_handle_conn_state(struct pico_dev *pdev, const u8 *payload, size_t plen)
{
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

    if (pdev->netdev)
    {
        if (pdev->conn_connected)
        {
            netif_carrier_on(pdev->netdev);
            netif_wake_queue(pdev->netdev);
        }
        else
        {
            netif_carrier_off(pdev->netdev);
            netif_stop_queue(pdev->netdev);
        }
    }
}

static void pico_handle_status(struct pico_dev *pdev, const u8 *payload, size_t plen)
{
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

    if (pdev->netdev)
    {
        if (pdev->conn_connected)
        {
            netif_carrier_on(pdev->netdev);
            netif_wake_queue(pdev->netdev);
        }
        else
        {
            netif_carrier_off(pdev->netdev);
            netif_stop_queue(pdev->netdev);
        }
    }
}

static void pico_handle_data_rx(struct pico_dev *pdev, const u8 *payload, size_t plen)
{
    struct sk_buff *skb;
    __be32 sip = 0, dip = 0;
    u16 sport = 0, dport = 0;
    u8 dhcp_type = 0;
    u32 dhcp_xid = 0;
    __be32 yiaddr = 0;
    u16 flags = 0;
    bool is_dhcp = false;

    if (!pdev || !pdev->netdev || plen == 0)
        return;

    pdev->perf_data_rx_pkts++;
    pdev->perf_data_rx_bytes += (u64)plen;

    is_dhcp = pico_parse_dhcp4(payload, plen, &sip, &dip, &sport, &dport,
                               &dhcp_type, &dhcp_xid, &yiaddr, &flags);
    if (pico_debug && is_dhcp && pdev->dhcp_rx_dbg_count < 10)
    {
        dev_info(&pdev->intf->dev,
                 DRV_NAME ": RX DHCP4 t=%u xid=0x%08x yiaddr=%pI4 flags=0x%04x %pI4:%u -> %pI4:%u len=%zu\n",
                 dhcp_type, dhcp_xid, &yiaddr, flags, &sip, sport, &dip, dport, plen);
        pdev->dhcp_rx_dbg_count++;
    }

    if (pico_debug && pdev->rx_dbg_count < 5)
    {
        dev_info(&pdev->intf->dev, DRV_NAME ": DATA_RX_ETH len=%zu\n", plen);
        print_hex_dump(KERN_INFO, DRV_NAME ": RX ",
                       DUMP_PREFIX_OFFSET, 16, 1,
                       payload, min_t(size_t, plen, 64), false);
        pdev->rx_dbg_count++;
    }

    skb = netdev_alloc_skb(pdev->netdev, plen + NET_IP_ALIGN);
    if (!skb)
    {
        pdev->netdev->stats.rx_dropped++;
        return;
    }

    skb_reserve(skb, NET_IP_ALIGN);
    memcpy(skb_put(skb, plen), payload, plen);
    skb->ip_summed = CHECKSUM_NONE; /* no offload; data is already on the wire */
    skb->protocol = eth_type_trans(skb, pdev->netdev);
    if (unlikely(pdev->disconnected || !netif_running(pdev->netdev)))
    {
        pdev->netdev->stats.rx_dropped++;
        dev_kfree_skb_any(skb);
        return;
    }

    if (unlikely(skb_queue_len(&pdev->rx_skb_q) >= pdev->rx_skb_q_limit))
    {
        pdev->netdev->stats.rx_dropped++;
        pdev->perf_data_rx_netif_drop++;
        dev_kfree_skb_any(skb);
        if (is_dhcp)
        {
            dev_warn(&pdev->intf->dev, DRV_NAME ": RX DHCP drop (napi queue full)\n");
        }
        return;
    }

    skb_queue_tail(&pdev->rx_skb_q, skb);
    napi_schedule(&pdev->napi);

    pdev->netdev->stats.rx_packets++;
    pdev->netdev->stats.rx_bytes += plen;
}

static netdev_tx_t pico_ndo_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
    struct pico_netdev_priv *priv = netdev_priv(ndev);
    struct pico_dev *pdev = priv ? priv->pdev : NULL;

    if (!pdev || !pdev->udev)
    {
        ndev->stats.tx_dropped++;
        dev_kfree_skb_any(skb);
        return NETDEV_TX_OK;
    }

    if (!pdev->conn_connected)
    {
        ndev->stats.tx_dropped++;
        dev_kfree_skb_any(skb);
        return NETDEV_TX_OK;
    }

    /* We don't support checksum offload; compute it in software if needed. */
    if (skb->ip_summed == CHECKSUM_PARTIAL)
    {
        if (skb_checksum_help(skb))
        {
            ndev->stats.tx_dropped++;
            dev_kfree_skb_any(skb);
            return NETDEV_TX_OK;
        }
    }

    if (pico_debug && pdev->tx_dbg_count < 10)
    {
        __be16 proto = 0;
        struct ethhdr eh;
        if (skb->len >= ETH_HLEN && !skb_copy_bits(skb, 0, &eh, sizeof(eh)))
            proto = eh.h_proto;
        dev_info(&pdev->intf->dev, DRV_NAME ": TX skb_len=%u proto=0x%04x\n",
                 skb->len, ntohs(proto));
        pdev->tx_dbg_count++;
    }

    // Each PWUSB frame must fit within device max total.
    if ((PWU_HDR_LEN + skb->len) > (pdev->dev_max_total ? pdev->dev_max_total : 2048))
    {
        ndev->stats.tx_dropped++;
        dev_kfree_skb_any(skb);
        return NETDEV_TX_OK;
    }

    if (skb_queue_len(&pdev->tx_skb_q) >= pdev->tx_skb_q_limit)
    {
        pdev->tx_eagain_count++;
        pdev->perf_usb_tx_eagain++;
        netif_stop_queue(ndev);
        return NETDEV_TX_BUSY;
    }

    // Own the skb and submit from worker so we can aggregate multiple frames per URB.
    skb_queue_tail(&pdev->tx_skb_q, skb);
    queue_work(system_highpri_wq, &pdev->tx_work);
    return NETDEV_TX_OK;
}

static int pico_ndo_open(struct net_device *ndev)
{
    struct pico_netdev_priv *priv = netdev_priv(ndev);
    struct pico_dev *pdev = priv ? priv->pdev : NULL;

    if (pdev)
        napi_enable(&pdev->napi);

    if (pdev && pdev->conn_connected)
    {
        netif_carrier_on(ndev);
        netif_start_queue(ndev);
    }
    else
    {
        netif_carrier_off(ndev);
        netif_stop_queue(ndev);
    }
    return 0;
}

static int pico_ndo_stop(struct net_device *ndev)
{
    struct pico_netdev_priv *priv = netdev_priv(ndev);
    struct pico_dev *pdev = priv ? priv->pdev : NULL;

    netif_stop_queue(ndev);
    netif_carrier_off(ndev);

    if (pdev)
    {
        napi_disable(&pdev->napi);
        skb_queue_purge(&pdev->rx_skb_q);
    }

    return 0;
}

static const struct net_device_ops pico_netdev_ops = {
    .ndo_open = pico_ndo_open,
    .ndo_stop = pico_ndo_stop,
    .ndo_start_xmit = pico_ndo_start_xmit,
};

static void pico_bench_out_stop_locked(struct pico_dev *pdev)
{
    int i;

    if (!pdev)
        return;

    pdev->bench_out_running = false;

    for (i = 0; i < PICO_BENCH_OUT_URB_COUNT; i++)
    {
        if (pdev->bench_out_urbs[i])
            usb_kill_urb(pdev->bench_out_urbs[i]);
    }

    for (i = 0; i < PICO_BENCH_OUT_URB_COUNT; i++)
    {
        if (pdev->bench_out_urbs[i])
        {
            usb_free_urb(pdev->bench_out_urbs[i]);
            pdev->bench_out_urbs[i] = NULL;
        }
        kfree(pdev->bench_out_bufs[i]);
        pdev->bench_out_bufs[i] = NULL;
    }

    pdev->bench_out_len = 0;
    pdev->bench_out_payload_len = 0;
    pdev->bench_out_eff_payload_len = 0;
}

static int pico_bench_out_start_locked(struct pico_dev *pdev, u16 payload_len)
{
    int i;
    int ret;
    u16 eff_plen;

    if (!pdev || pdev->disconnected)
        return -ENODEV;

    if (pdev->bench_out_running)
        return -EBUSY;

    eff_plen = pico_bench_cap_payload(pdev, payload_len);
    if (!eff_plen)
        return -EINVAL;

    /* Stop any leftover resources, then allocate fresh. */
    pico_bench_out_stop_locked(pdev);

    pdev->bench_out_payload_len = payload_len;
    pdev->bench_out_eff_payload_len = eff_plen;
    pdev->bench_out_bytes = 0;
    pdev->bench_out_urbs_done = 0;
    pdev->bench_out_errs = 0;
    pdev->bench_out_start_j = jiffies;

    /* Build one 8KB OUT buffer packed with framed BENCH_SINK messages. */
    pdev->bench_out_bufs[0] = kmalloc(PICO_BENCH_OUT_URB_SIZE, GFP_KERNEL);
    if (!pdev->bench_out_bufs[0])
        return -ENOMEM;

    pdev->bench_out_len = pico_build_bench_out_buf(pdev, pdev->bench_out_bufs[0],
                                                   PICO_BENCH_OUT_URB_SIZE, eff_plen);
    if (!pdev->bench_out_len)
    {
        kfree(pdev->bench_out_bufs[0]);
        pdev->bench_out_bufs[0] = NULL;
        return -EINVAL;
    }

    /* Clone the same buffer into each URB to avoid sharing a single buffer among in-flight URBs. */
    for (i = 1; i < PICO_BENCH_OUT_URB_COUNT; i++)
    {
        pdev->bench_out_bufs[i] = kmalloc(PICO_BENCH_OUT_URB_SIZE, GFP_KERNEL);
        if (!pdev->bench_out_bufs[i])
        {
            ret = -ENOMEM;
            goto err;
        }
        memcpy(pdev->bench_out_bufs[i], pdev->bench_out_bufs[0], pdev->bench_out_len);
    }

    for (i = 0; i < PICO_BENCH_OUT_URB_COUNT; i++)
    {
        pdev->bench_out_urbs[i] = usb_alloc_urb(0, GFP_KERNEL);
        if (!pdev->bench_out_urbs[i])
        {
            ret = -ENOMEM;
            goto err;
        }
        usb_fill_bulk_urb(pdev->bench_out_urbs[i], pdev->udev,
                          usb_sndbulkpipe(pdev->udev, pdev->ep_out),
                          pdev->bench_out_bufs[i], (int)pdev->bench_out_len,
                          pico_bench_out_complete, pdev);
    }

    pdev->bench_out_running = true;

    for (i = 0; i < PICO_BENCH_OUT_URB_COUNT; i++)
    {
        ret = usb_submit_urb(pdev->bench_out_urbs[i], GFP_KERNEL);
        if (ret)
        {
            pdev->bench_out_errs++;
            pdev->bench_out_running = false;
            goto err;
        }
    }

    return 0;

err:
    pico_bench_out_stop_locked(pdev);
    return ret;
}

static void pico_bench_reset_locked(struct pico_dev *pdev)
{
    if (!pdev)
        return;
    pdev->bench_in_bytes = 0;
    pdev->bench_in_msgs = 0;
    pdev->bench_in_start_j = jiffies;
    pdev->bench_out_bytes = 0;
    pdev->bench_out_urbs_done = 0;
    pdev->bench_out_errs = 0;
    pdev->bench_out_start_j = jiffies;
}

static int pico_dbg_bench_stats_show(struct seq_file *s, void *unused)
{
    struct pico_dev *pdev = s->private;
    unsigned long now = jiffies;
    u64 in_payload_bytes, in_bus_bytes;
    u64 out_bus_bytes;
    unsigned long in_ms = 0, out_ms = 0;
    u64 in_kbps = 0, out_kbps = 0;
    u32 in_mbps_i = 0, out_mbps_i = 0;
    u32 in_mbps_f = 0, out_mbps_f = 0;
    u16 eff_plen = 0;
    u32 out_msgs_per_urb = 0;

    mutex_lock(&pdev->bench_lock);
    in_payload_bytes = pdev->bench_in_bytes;
    in_bus_bytes = pdev->bench_in_bytes + (u64)PWU_HDR_LEN * pdev->bench_in_msgs;
    out_bus_bytes = pdev->bench_out_bytes;
    if (pdev->bench_in_running)
        in_ms = jiffies_to_msecs(now - pdev->bench_in_start_j);
    if (pdev->bench_out_running)
        out_ms = jiffies_to_msecs(now - pdev->bench_out_start_j);
    eff_plen = pdev->bench_out_eff_payload_len;
    if (pdev->bench_out_len && eff_plen)
    {
        u32 frame_sz = (u32)PWU_HDR_LEN + (u32)eff_plen;
        out_msgs_per_urb = (u32)(pdev->bench_out_len / frame_sz);
    }
    mutex_unlock(&pdev->bench_lock);

    /*
     * Report kbps/mbps derived directly from bytes + elapsed ms.
     * kbps = (bytes * 8) / ms  (since bits/ms == kb/s)
     */
    if (in_ms)
    {
        in_kbps = div_u64(in_bus_bytes * 8ULL, (u64)in_ms);
        in_mbps_i = (u32)(in_kbps / 1000ULL);
        in_mbps_f = (u32)(in_kbps % 1000ULL);
    }
    if (out_ms)
    {
        out_kbps = div_u64(out_bus_bytes * 8ULL, (u64)out_ms);
        out_mbps_i = (u32)(out_kbps / 1000ULL);
        out_mbps_f = (u32)(out_kbps % 1000ULL);
    }

    seq_printf(s, "dev_max_total=%u\n", pdev->dev_max_total);

    seq_printf(s, "in_running=%u in_payload_bytes=%llu in_bus_bytes=%llu in_msgs=%llu in_ms=%lu in_kbps=%llu in_mbps=%u.%03u\n",
               pdev->bench_in_running ? 1 : 0,
               (unsigned long long)in_payload_bytes,
               (unsigned long long)in_bus_bytes,
               (unsigned long long)pdev->bench_in_msgs,
               in_ms,
               (unsigned long long)in_kbps,
               in_mbps_i, in_mbps_f);

    seq_printf(s, "out_running=%u out_bus_bytes=%llu out_urbs_done=%llu out_errs=%llu out_ms=%lu out_kbps=%llu out_mbps=%u.%03u out_req_plen=%u out_eff_plen=%u out_msgs_per_urb=%u out_urb_len=%zu\n",
               pdev->bench_out_running ? 1 : 0,
               (unsigned long long)out_bus_bytes,
               (unsigned long long)pdev->bench_out_urbs_done,
               (unsigned long long)pdev->bench_out_errs,
               out_ms,
               (unsigned long long)out_kbps,
               out_mbps_i, out_mbps_f,
               pdev->bench_out_payload_len,
               pdev->bench_out_eff_payload_len,
               out_msgs_per_urb,
               pdev->bench_out_len);

    seq_printf(s, "usage: echo 'in <plen>'|'out <plen>'|'both <plen>'|'stop'|'reset' > bench_control\n");
    return 0;
}

static int pico_dbg_bench_stats_open(struct inode *inode, struct file *file)
{
    return single_open(file, pico_dbg_bench_stats_show, inode->i_private);
}

static ssize_t pico_dbg_bench_control_write(struct file *file,
                                            const char __user *buf,
                                            size_t len,
                                            loff_t *ppos)
{
    struct pico_dev *pdev = file->private_data;
    char in[64];
    char cmd[16] = {0};
    unsigned int plen = 0;
    size_t n = min_t(size_t, len, sizeof(in) - 1);
    int ret = 0;

    if (!pdev || n == 0)
        return -EINVAL;

    if (copy_from_user(in, buf, n))
        return -EFAULT;
    in[n] = '\0';

    while (n > 0 && (in[n - 1] == '\n' || in[n - 1] == '\r'))
    {
        in[n - 1] = '\0';
        n--;
    }

    if (sscanf(in, "%15s %u", cmd, &plen) < 1)
        return -EINVAL;

    mutex_lock(&pdev->bench_lock);

    if (!strcmp(cmd, "stop"))
    {
        pdev->bench_in_running = false;
        pico_bench_out_stop_locked(pdev);
        mutex_unlock(&pdev->bench_lock);
        /* Best-effort: stop device-side source. */
        pico_send_bench_stop(pdev);
        return len;
    }

    if (!strcmp(cmd, "reset"))
    {
        pdev->bench_in_running = false;
        pico_bench_out_stop_locked(pdev);
        pico_bench_reset_locked(pdev);
        mutex_unlock(&pdev->bench_lock);
        pico_send_bench_stop(pdev);
        return len;
    }

    if (!strcmp(cmd, "in") || !strcmp(cmd, "both"))
    {
        pdev->bench_in_bytes = 0;
        pdev->bench_in_msgs = 0;
        pdev->bench_in_start_j = jiffies;
        pdev->bench_in_running = true;
        ret = pico_send_bench_start(pdev, !strcmp(cmd, "both") ? 0x03 : 0x01, (u16)plen);
        if (ret)
        {
            pdev->bench_in_running = false;
            mutex_unlock(&pdev->bench_lock);
            return ret;
        }
    }

    if (!strcmp(cmd, "out"))
    {
        /* Tell device to enable fast-drop sink mode. */
        ret = pico_send_bench_start(pdev, 0x02, (u16)plen);
        if (ret)
        {
            mutex_unlock(&pdev->bench_lock);
            return ret;
        }
    }

    if (!strcmp(cmd, "out") || !strcmp(cmd, "both"))
    {
        ret = pico_bench_out_start_locked(pdev, (u16)plen);
        if (ret)
        {
            if (!strcmp(cmd, "both"))
            {
                pdev->bench_in_running = false;
                pico_send_bench_stop(pdev);
            }
            mutex_unlock(&pdev->bench_lock);
            return ret;
        }
    }

    mutex_unlock(&pdev->bench_lock);

    if (strcmp(cmd, "in") && strcmp(cmd, "out") && strcmp(cmd, "both"))
        return -EINVAL;

    return len;
}

static const struct file_operations pico_dbg_bench_stats_fops = {
    .owner = THIS_MODULE,
    .open = pico_dbg_bench_stats_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static const struct file_operations pico_dbg_bench_control_fops = {
    .owner = THIS_MODULE,
    .write = pico_dbg_bench_control_write,
    .open = simple_open,
};

static int pico_dbg_scan_results_show(struct seq_file *s, void *unused)
{
    struct pico_dev *pdev = s->private;
    struct pico_scan_result *results;
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

    for (i = 0; i < count; i++)
    {
        seq_printf(s, "SSID=\"%s\"  RSSI=%d  CH=%u  BSSID=%pM  SEC=0x%04x\n",
                   results[i].ssid, results[i].rssi, results[i].channel,
                   results[i].bssid, results[i].security);
    }

    kfree(results);
    return 0;
}

static int pico_dbg_scan_results_open(struct inode *inode, struct file *file)
{
    return single_open(file, pico_dbg_scan_results_show, inode->i_private);
}

static ssize_t pico_dbg_scan_start_write(struct file *file,
                                         const char __user *buf,
                                         size_t len,
                                         loff_t *ppos)
{
    struct pico_dev *pdev = file->private_data;
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

static ssize_t pico_dbg_scan_done_read(struct file *file,
                                       char __user *buf,
                                       size_t len,
                                       loff_t *ppos)
{
    struct pico_dev *pdev = file->private_data;
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

static ssize_t pico_dbg_connect_write(struct file *file,
                                      const char __user *buf,
                                      size_t len,
                                      loff_t *ppos)
{
    struct pico_dev *pdev = file->private_data;
    char in[96];
    char ssid[32];
    char psk[64];
    char *sep;
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
    if (sep)
    {
        ssid_len = min_t(size_t, sep - in, sizeof(ssid));
        psk_len = min_t(size_t, n - ssid_len - 1, sizeof(psk));
        if (ssid_len == 0)
            return -EINVAL;
        memcpy(ssid, in, ssid_len);
        if (psk_len)
            memcpy(psk, sep + 1, psk_len);
    }
    else
    {
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

static ssize_t pico_dbg_disconnect_write(struct file *file,
                                         const char __user *buf,
                                         size_t len,
                                         loff_t *ppos)
{
    struct pico_dev *pdev = file->private_data;
    int val;

    if (kstrtoint_from_user(buf, len, 0, &val))
        return -EINVAL;
    if (val != 1)
        return -EINVAL;

    if (pico_ctrl_disconnect(pdev))
        return -ENODEV;
    return len;
}

static ssize_t pico_dbg_status_read(struct file *file,
                                    char __user *buf,
                                    size_t len,
                                    loff_t *ppos)
{
    struct pico_dev *pdev = file->private_data;
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

static int pico_probe(struct usb_interface *interface,
                      const struct usb_device_id *id)
{
    struct usb_device *udev = interface_to_usbdev(interface);
    struct usb_host_interface *iface_desc;
    struct usb_endpoint_descriptor *endpoint;
    struct pico_dev *pdev;
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
    /*
     * disconnect() can race with probe() after usb_set_intfdata() is set.
     * Initialize the bench mutex early so disconnect never sees an
     * uninitialized lock.
     */
    mutex_init(&pdev->bench_lock);

    // find bulk endpoints
    for (i = 0; i < iface_desc->desc.bNumEndpoints; ++i)
    {
        endpoint = &iface_desc->endpoint[i].desc;

        if (usb_endpoint_is_bulk_in(endpoint) && !pdev->ep_in)
        {
            pdev->ep_in = endpoint->bEndpointAddress;
            pdev->ep_in_maxpkt = usb_endpoint_maxp(endpoint);
            dev_info(&interface->dev,
                     DRV_NAME ": Found bulk IN ep 0x%02x maxpkt=%u\n",
                     pdev->ep_in, pdev->ep_in_maxpkt);
        }

        if (usb_endpoint_is_bulk_out(endpoint) && !pdev->ep_out)
        {
            pdev->ep_out = endpoint->bEndpointAddress;
            pdev->ep_out_maxpkt = usb_endpoint_maxp(endpoint);
            dev_info(&interface->dev,
                     DRV_NAME ": Found bulk OUT ep 0x%02x maxpkt=%u\n",
                     pdev->ep_out, pdev->ep_out_maxpkt);
        }
    }

    if (!pdev->ep_in || !pdev->ep_out)
    {
        dev_err(&interface->dev, DRV_NAME ": Missing bulk endpoints\n");
        usb_put_dev(pdev->udev);
        kfree(pdev);
        return -ENODEV;
    }

    // Allocate RX URBs + buffers
    pdev->rx_buf_size = PICO_USB_RX_URB_SIZE;
    for (i = 0; i < PICO_USB_RX_URB_COUNT; i++)
    {
        pdev->rx_bufs[i] = kmalloc(pdev->rx_buf_size, GFP_KERNEL);
        pdev->rx_urbs[i] = usb_alloc_urb(0, GFP_KERNEL);
    }

    pdev->fr_cap = PICO_STREAM_FR_CAP;
    pdev->fr_buf = kmalloc(pdev->fr_cap, GFP_KERNEL);
    pdev->fr_len = 0;

    /* TX resources */
    spin_lock_init(&pdev->tx_lock);
    pdev->tx_busy_map = 0;
    for (i = 0; i < PICO_USB_TX_URB_COUNT; i++)
    {
        struct pico_tx_ctx *ctx;
        pdev->tx_bufs[i] = kmalloc(PICO_USB_TX_BUF_SIZE, GFP_KERNEL);
        pdev->tx_urbs[i] = usb_alloc_urb(0, GFP_KERNEL);
        if (pdev->tx_urbs[i])
        {
            // Slot context lets completion mark the right slot as free.
            ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
            if (ctx)
            {
                ctx->pdev = pdev;
                ctx->slot = (u8)i;
                pdev->tx_urbs[i]->context = ctx;
            }
        }
    }
    skb_queue_head_init(&pdev->tx_skb_q);
    pdev->tx_skb_q_limit = PICO_USB_TX_SKB_Q_LIMIT;
    INIT_WORK(&pdev->tx_work, pico_tx_work_fn);
    spin_lock_init(&pdev->scan_lock);
    pico_scan_clear(pdev);

    for (i = 0; i < PICO_USB_RX_URB_COUNT; i++)
    {
        if (!pdev->rx_bufs[i] || !pdev->rx_urbs[i])
        {
            dev_err(&interface->dev, DRV_NAME ": alloc failed\n");
            goto err_alloc;
        }
    }
    if (!pdev->fr_buf)
    {
        dev_err(&interface->dev, DRV_NAME ": alloc failed\n");
        goto err_alloc;
    }
    for (i = 0; i < PICO_USB_TX_URB_COUNT; i++)
    {
        if (!pdev->tx_bufs[i] || !pdev->tx_urbs[i] || !pdev->tx_urbs[i]->context)
        {
            dev_err(&interface->dev, DRV_NAME ": alloc failed\n");
            goto err_alloc;
        }
    }

    // success
    goto alloc_done;

err_alloc:
    pico_free_rx_resources(pdev);
    pico_free_tx_resources(pdev);
    kfree(pdev->fr_buf);
    usb_put_dev(pdev->udev);
    kfree(pdev);
    return -ENOMEM;

alloc_done:;

    usb_set_intfdata(interface, pdev);

    pdev->netdev = alloc_etherdev(sizeof(struct pico_netdev_priv));
    if (!pdev->netdev)
    {
        dev_err(&interface->dev, DRV_NAME ": netdev alloc failed\n");
        usb_put_dev(pdev->udev);
        kfree(pdev->fr_buf);
        pico_free_rx_resources(pdev);
        pico_free_tx_resources(pdev);
        kfree(pdev);
        return -ENOMEM;
    }
    {
        struct pico_netdev_priv *priv = netdev_priv(pdev->netdev);
        priv->pdev = pdev;
    }
    pdev->netdev->netdev_ops = &pico_netdev_ops;
    pdev->netdev->mtu = 1500;
    /* No offloads; we send raw Ethernet over USB. */
    pdev->netdev->features = NETIF_F_GRO;
    pdev->netdev->hw_features = 0;
    strscpy(pdev->netdev->name, "pico%d", IFNAMSIZ);
    eth_hw_addr_random(pdev->netdev);
    SET_NETDEV_DEV(pdev->netdev, &interface->dev);

    skb_queue_head_init(&pdev->rx_skb_q);
    pdev->rx_skb_q_limit = 1024;
    /*
     * netif_napi_add() signature differs across kernel versions:
     * - older kernels: netif_napi_add(dev, napi, poll, weight)
     * - newer kernels (e.g. 6.6.y): netif_napi_add(dev, napi, poll)
     *
     * Keep an explicit weight where possible.
     */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    netif_napi_add(pdev->netdev, &pdev->napi, pico_napi_poll);
    pdev->napi.weight = 64;
#else
    netif_napi_add(pdev->netdev, &pdev->napi, pico_napi_poll, 64);
#endif

    pdev->cfg = pico_cfg80211_init(pdev, pdev->netdev, &interface->dev);
    if (!pdev->cfg)
    {
        dev_err(&interface->dev, DRV_NAME ": cfg80211 init failed\n");
        netif_napi_del(&pdev->napi);
        free_netdev(pdev->netdev);
        usb_put_dev(pdev->udev);
        kfree(pdev->fr_buf);
        pico_free_rx_resources(pdev);
        pico_free_tx_resources(pdev);
        kfree(pdev);
        return -ENODEV;
    }

    if (register_netdev(pdev->netdev))
    {
        dev_err(&interface->dev, DRV_NAME ": netdev register failed\n");
        pico_cfg80211_deinit(pdev->cfg);
        pdev->cfg = NULL;
        netif_napi_del(&pdev->napi);
        free_netdev(pdev->netdev);
        usb_put_dev(pdev->udev);
        kfree(pdev->fr_buf);
        pico_free_rx_resources(pdev);
        pico_free_tx_resources(pdev);
        kfree(pdev);
        return -ENODEV;
    }

    netif_carrier_off(pdev->netdev);
    netif_stop_queue(pdev->netdev);

    INIT_DELAYED_WORK(&pdev->ctrl_work, pico_ctrl_work_fn);
    pdev->ctrl_cmd = PICO_CTRL_NONE;
    pdev->ctrl_quiesce = false;

    INIT_DELAYED_WORK(&pdev->perf_work, pico_perf_work_fn);
    pdev->perf_last_usb_rx_bytes = pdev->perf_usb_rx_bytes;
    pdev->perf_last_data_rx_bytes = pdev->perf_data_rx_bytes;
    pdev->perf_last_data_rx_netif_drop = pdev->perf_data_rx_netif_drop;
    pdev->perf_last_usb_tx_bytes = pdev->perf_usb_tx_bytes;
    pdev->perf_last_usb_tx_eagain = pdev->perf_usb_tx_eagain;
    schedule_delayed_work(&pdev->perf_work, HZ);

    /* Submit RX URB immediately to start receiving device responses */
    pico_kick_rx(pdev);

    /* Send HELLO to initiate handshake with device */
    dev_info(&interface->dev, DRV_NAME ": sending HELLO to initiate handshake\n");
    pico_send_hello(pdev);

    pdev->dbg_dir = debugfs_create_dir(DRV_NAME, NULL);
    if (pdev->dbg_dir)
    {
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
        debugfs_create_file("bench_control", 0200, pdev->dbg_dir, pdev,
                            &pico_dbg_bench_control_fops);
        debugfs_create_file("bench_stats", 0400, pdev->dbg_dir, pdev,
                            &pico_dbg_bench_stats_fops);
    }
    else
    {
        dev_warn(&interface->dev, DRV_NAME ": debugfs dir create failed\n");
    }

    dev_info(&interface->dev, DRV_NAME ": netdev registered as %s\n",
             pdev->netdev->name);

    dev_info(&interface->dev, DRV_NAME ": probe() success\n");
    return 0;
}

static void pico_disconnect(struct usb_interface *interface)
{
    struct pico_dev *pdev = usb_get_intfdata(interface);

    dev_info(&interface->dev, DRV_NAME ": disconnect()\n");

    usb_set_intfdata(interface, NULL);
    if (!pdev)
        return;

    pdev->disconnected = true;
    mutex_lock(&pdev->bench_lock);
    pdev->bench_in_running = false;
    pico_bench_out_stop_locked(pdev);
    mutex_unlock(&pdev->bench_lock);
    cancel_delayed_work_sync(&pdev->ctrl_work);
    cancel_delayed_work_sync(&pdev->perf_work);
    pdev->ctrl_cmd = PICO_CTRL_NONE;
    cancel_work_sync(&pdev->tx_work);
    skb_queue_purge(&pdev->tx_skb_q);

    if (pdev->netdev)
    {
        netif_stop_queue(pdev->netdev);
        netif_carrier_off(pdev->netdev);
    }

    /*
     * Stop USB I/O first to prevent RX completions racing against netdev/NAPI
     * teardown. usb_kill_urb() waits for in-flight callbacks to finish.
     */

    // stop RX
    {
        int i;
        for (i = 0; i < PICO_USB_RX_URB_COUNT; i++)
        {
            if (pdev->rx_urbs[i])
                usb_kill_urb(pdev->rx_urbs[i]);
            if (pdev->rx_urbs[i])
                usb_free_urb(pdev->rx_urbs[i]);
            kfree(pdev->rx_bufs[i]);
            pdev->rx_urbs[i] = NULL;
            pdev->rx_bufs[i] = NULL;
        }
    }

    // stop TX
    {
        int i;
        for (i = 0; i < PICO_USB_TX_URB_COUNT; i++)
        {
            if (pdev->tx_urbs[i])
                usb_kill_urb(pdev->tx_urbs[i]);
            if (pdev->tx_urbs[i])
            {
                kfree(pdev->tx_urbs[i]->context);
                pdev->tx_urbs[i]->context = NULL;
                usb_free_urb(pdev->tx_urbs[i]);
                pdev->tx_urbs[i] = NULL;
            }
            kfree(pdev->tx_bufs[i]);
            pdev->tx_bufs[i] = NULL;
        }
        pdev->tx_busy_map = 0;
    }
    kfree(pdev->fr_buf);
    debugfs_remove_recursive(pdev->dbg_dir);
    if (pdev->netdev)
    {
        unregister_netdev(pdev->netdev);
        /* unregister_netdev() may call ndo_stop(), which disables NAPI. */
        netif_napi_del(&pdev->napi);
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

MODULE_AUTHOR("Truc Mai");
MODULE_DESCRIPTION("USB Wi-Fi adapter");
MODULE_LICENSE("GPL");
MODULE_SOFTDEP("pre: cfg80211");
