#ifndef PWUSB_DEBUG_H
#define PWUSB_DEBUG_H

// Compile-time debug toggles. Override via `target_compile_definitions(...)`.
#ifndef PWUSB_USB_DEBUG
#define PWUSB_USB_DEBUG 0
#endif

#ifndef PWUSB_WIFI_DEBUG
#define PWUSB_WIFI_DEBUG 0
#endif

#ifndef PWUSB_DHCP_DEBUG
#define PWUSB_DHCP_DEBUG 0
#endif

// 1 Hz perf summary (counters, not per-packet logs). Safe to leave ON.
#ifndef PWUSB_PERF_DEBUG
#define PWUSB_PERF_DEBUG 0
#endif

#endif
