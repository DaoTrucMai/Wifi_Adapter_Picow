#ifndef PWUSB_PERF_H
#define PWUSB_PERF_H

#include <stdint.h>

// Compile-time performance debug toggle. Override via CMake options.
#ifndef PWUSB_PERF_DEBUG
#define PWUSB_PERF_DEBUG 0
#endif

/* Performance metrics structure */
typedef struct {
    /* Wi-Fi RX stats */
    uint64_t wifi_rx_pkts;
    uint64_t wifi_rx_bytes;
    uint64_t wifi_rx_drop_qfull;
    uint64_t wifi_rx_drop_oversize;

    /* Host TX (Ethernet) stats */
    uint64_t host_tx_eth_pkts;
    uint64_t host_tx_eth_bytes;
    uint64_t host_tx_eth_drop_oversize;

    /* USB IN (host read) stats */
    uint64_t usb_in_bytes;
    uint64_t usb_in_writes;
    uint64_t usb_in_blocked;
    uint64_t usb_in_write0;
    uint64_t usb_in_flushes;

    /* TX queue stats */
    uint64_t txq_pop_ok;
    uint64_t txq_pop_empty;
} pwusb_perf_t;

/* Global performance counters */
extern pwusb_perf_t g_pwusb_perf;

#endif /* PWUSB_PERF_H */
