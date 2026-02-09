#include <stdio.h>

#include "msg_queue.h"
#include "pico/stdlib.h"
#include "pwusb_handlers.h"
#include "pwusb_proto.h"
#include "pwusb_transport.h"
#include "tusb.h"
#include "usb_device.h"
#include "wifi_mgr.h"

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

    tusb_init();

    uint8_t rx_msg[MQ_MAX_MSG];
    uint16_t rx_len = 0;
    uint32_t next_stats_ms = 0;

    while (true) {
        tud_task();
        usb_device_poll_rx();
        wifi_mgr_poll();

        // Process inbound messages
        while (pwusb_transport_try_get_msg(rx_msg, &rx_len)) {
            const pwusb_hdr_t* h = (const pwusb_hdr_t*)rx_msg;
            pwusb_handle_one(&g_txq, rx_msg, rx_len);
        }

        // Drain outbound queue to host
        usb_device_try_tx();

        {
            uint32_t now = to_ms_since_boot(get_absolute_time());
            if ((int32_t)(now - next_stats_ms) >= 0) {
                uint32_t drop_bytes = 0, drop_events = 0, resync_bytes = 0;
                pwusb_transport_get_and_clear_stats(&drop_bytes, &drop_events, &resync_bytes);
                if (drop_events || resync_bytes) {
                    printf("USB RX stats: drop_events=%lu drop_bytes=%lu resync_bytes=%lu\n",
                           (unsigned long)drop_events, (unsigned long)drop_bytes, (unsigned long)resync_bytes);
                }
                next_stats_ms = now + 1000;
            }
        }

        tight_loop_contents();
    }
}
