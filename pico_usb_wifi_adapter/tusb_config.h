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
#define CFG_TUD_VENDOR_RX_BUFSIZE 512
#define CFG_TUD_VENDOR_TX_BUFSIZE 512

// Disable other classes for now
#define CFG_TUD_CDC 0
#define CFG_TUD_HID 0
#define CFG_TUD_MSC 0

#endif
