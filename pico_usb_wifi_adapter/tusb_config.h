#ifndef _TUSB_CONFIG_H_
#define _TUSB_CONFIG_H_

// #include "tusb.h"

// Pico is Full Speed device
#define CFG_TUSB_RHPORT0_MODE (OPT_MODE_DEVICE)
#define CFG_TUSB_OS OPT_OS_PICO

// Endpoint 0 size
#define CFG_TUD_ENDPOINT0_SIZE 64

// Enable Vendor class (bulk IN/OUT)
#define CFG_TUD_VENDOR 1
// Endpoint max packet is still 64 bytes on Full-Speed, but TinyUSB's vendor
// class uses CFG_TUD_VENDOR_EPSIZE as the *transfer buffer size* it arms per
// xfer. Increasing this reduces per-packet re-arming overhead and can improve
// Full-Speed bulk throughput for streaming workloads.
#define CFG_TUD_VENDOR_EPSIZE 512
// Larger FIFOs reduce full-speed (64B maxpacket) overhead and decrease
// backpressure when the host drains in bursts.
#define CFG_TUD_VENDOR_RX_BUFSIZE 2048
// Increase TX FIFO to allow larger device->host "superframes" and reduce
// short/underfilled FS bulk IN packets.
#define CFG_TUD_VENDOR_TX_BUFSIZE 32768

// Disable other classes for now
#define CFG_TUD_CDC 0
#define CFG_TUD_HID 0
#define CFG_TUD_MSC 0

#endif
