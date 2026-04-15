#pragma once

#include <stddef.h>
#include <stdint.h>

// Lightweight performance counters for debugging throughput bottlenecks.
// Intentionally "dumb": just counters + 1 Hz summary printing in main().
typedef struct {
    // Wi-Fi -> Pico (RX from CYW43)
    uint64_t wifi_rx_pkts;
    uint64_t wifi_rx_bytes;
    uint64_t wifi_rx_drop_qfull;
    uint64_t wifi_rx_drop_oversize;

    // Host -> Pico (USB OUT, then TX to Wi-Fi)
    uint64_t host_tx_eth_pkts;
    uint64_t host_tx_eth_bytes;
    uint64_t host_tx_eth_drop_oversize;

    // Pico -> Host (USB IN stream)
    uint64_t usb_in_bytes;
    uint64_t usb_in_writes;
    uint64_t usb_in_blocked;   // tud_vendor_write_available() == 0
    uint64_t usb_in_write0;    // tud_vendor_write() returned 0 despite avail>0
    uint64_t usb_in_flushes;

    // TX queue feeding USB IN
    uint64_t txq_pop_ok;
    uint64_t txq_pop_empty;
} pwusb_perf_t;

extern pwusb_perf_t g_pwusb_perf;

static inline void pwusb_perf_wifi_rx(size_t len) {
    g_pwusb_perf.wifi_rx_pkts++;
    g_pwusb_perf.wifi_rx_bytes += (uint64_t)len;
}
static inline void pwusb_perf_wifi_rx_drop_qfull(void) {
    g_pwusb_perf.wifi_rx_drop_qfull++;
}
static inline void pwusb_perf_wifi_rx_drop_oversize(void) {
    g_pwusb_perf.wifi_rx_drop_oversize++;
}

static inline void pwusb_perf_host_tx_eth(size_t len) {
    g_pwusb_perf.host_tx_eth_pkts++;
    g_pwusb_perf.host_tx_eth_bytes += (uint64_t)len;
}
static inline void pwusb_perf_host_tx_eth_drop_oversize(void) {
    g_pwusb_perf.host_tx_eth_drop_oversize++;
}

static inline void pwusb_perf_usb_in_blocked(void) {
    g_pwusb_perf.usb_in_blocked++;
}
static inline void pwusb_perf_usb_in_write(size_t wrote) {
    g_pwusb_perf.usb_in_writes++;
    g_pwusb_perf.usb_in_bytes += (uint64_t)wrote;
}
static inline void pwusb_perf_usb_in_write0(void) {
    g_pwusb_perf.usb_in_write0++;
}
static inline void pwusb_perf_usb_in_flush(void) {
    g_pwusb_perf.usb_in_flushes++;
}

static inline void pwusb_perf_txq_pop_ok(void) {
    g_pwusb_perf.txq_pop_ok++;
}
static inline void pwusb_perf_txq_pop_empty(void) {
    g_pwusb_perf.txq_pop_empty++;
}

