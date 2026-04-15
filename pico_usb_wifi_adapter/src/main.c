#include <stdio.h>

#include "msg_queue.h"
#include "pico/stdlib.h"
#include "pwusb_handlers.h"
#include "pwusb_proto.h"
#include "pwusb_transport.h"
#include "usb_backend.h"
#include "usb.h"
#include "wifi_mgr.h"
#include "pwusb_debug.h"
#include "pwusb_perf.h"

msg_queue_t g_txq;

int main(void) {
    // No stdio over USB; we do protocol over vendor bulk.
    stdio_init_all();
    sleep_ms(1000);

    mq_init(&g_txq);
    wifi_mgr_set_txq(&g_txq);
    pwusb_transport_init();

    if (!wifi_mgr_init()) {
        // If Wi-Fi init fails, we still enumerate USB so host can see error later.
    }

    usb_backend_init();

    uint8_t rx_msg[MQ_MAX_MSG];
    uint16_t rx_len = 0;
    uint32_t next_stats_ms = 0;
    pwusb_perf_t last_perf = {0};

    while (true) {
        usb_backend_poll_rx();
        wifi_mgr_poll();

        // Process inbound messages
        while (pwusb_transport_try_get_msg(rx_msg, &rx_len)) {
            const pwusb_hdr_t* h = (const pwusb_hdr_t*)rx_msg;
            pwusb_handle_one(&g_txq, rx_msg, rx_len);
        }

        // Drain outbound queue to host
        usb_backend_try_tx();

        {
            uint32_t now = to_ms_since_boot(get_absolute_time());
            if ((int32_t)(now - next_stats_ms) >= 0) {
                uint32_t drop_bytes = 0, drop_events = 0, resync_bytes = 0;
                pwusb_transport_get_and_clear_stats(&drop_bytes, &drop_events, &resync_bytes);
                if (PWUSB_USB_DEBUG && (drop_events || resync_bytes)) {
                    printf("USB RX stats: drop_events=%lu drop_bytes=%lu resync_bytes=%lu\n",
                           (unsigned long)drop_events, (unsigned long)drop_bytes, (unsigned long)resync_bytes);
                }
                if (PWUSB_PERF_DEBUG) {
                    pwusb_perf_t cur = g_pwusb_perf;
                    pwusb_perf_t d = {0};

                    d.wifi_rx_pkts = cur.wifi_rx_pkts - last_perf.wifi_rx_pkts;
                    d.wifi_rx_bytes = cur.wifi_rx_bytes - last_perf.wifi_rx_bytes;
                    d.wifi_rx_drop_qfull = cur.wifi_rx_drop_qfull - last_perf.wifi_rx_drop_qfull;
                    d.wifi_rx_drop_oversize = cur.wifi_rx_drop_oversize - last_perf.wifi_rx_drop_oversize;

                    d.host_tx_eth_pkts = cur.host_tx_eth_pkts - last_perf.host_tx_eth_pkts;
                    d.host_tx_eth_bytes = cur.host_tx_eth_bytes - last_perf.host_tx_eth_bytes;
                    d.host_tx_eth_drop_oversize = cur.host_tx_eth_drop_oversize - last_perf.host_tx_eth_drop_oversize;

                    d.usb_in_bytes = cur.usb_in_bytes - last_perf.usb_in_bytes;
                    d.usb_in_writes = cur.usb_in_writes - last_perf.usb_in_writes;
                    d.usb_in_blocked = cur.usb_in_blocked - last_perf.usb_in_blocked;
                    d.usb_in_write0 = cur.usb_in_write0 - last_perf.usb_in_write0;
                    d.usb_in_flushes = cur.usb_in_flushes - last_perf.usb_in_flushes;

                    d.txq_pop_ok = cur.txq_pop_ok - last_perf.txq_pop_ok;
                    d.txq_pop_empty = cur.txq_pop_empty - last_perf.txq_pop_empty;

                    // 1 Hz summary: keep it short so it does not dominate USB/Wi-Fi throughput.
                    printf("PERF 1s: wifi_rx=%llu pkts %llu B drop_qfull=%llu drop_ov=%llu | usb_in=%llu B writes=%llu blocked=%llu flush=%llu | host_tx=%llu pkts %llu B\n",
                           (unsigned long long)d.wifi_rx_pkts, (unsigned long long)d.wifi_rx_bytes,
                           (unsigned long long)d.wifi_rx_drop_qfull, (unsigned long long)d.wifi_rx_drop_oversize,
                           (unsigned long long)d.usb_in_bytes, (unsigned long long)d.usb_in_writes,
                           (unsigned long long)d.usb_in_blocked, (unsigned long long)d.usb_in_flushes,
                           (unsigned long long)d.host_tx_eth_pkts, (unsigned long long)d.host_tx_eth_bytes);

                    last_perf = cur;
                }
                next_stats_ms = now + 1000;
            }
        }

        tight_loop_contents();
    }
}
