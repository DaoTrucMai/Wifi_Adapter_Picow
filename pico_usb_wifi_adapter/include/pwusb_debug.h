#ifndef PWUSB_DEBUG_H
#define PWUSB_DEBUG_H

#include <stdio.h>

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

#define PWUSB_WARN(...) do { printf(__VA_ARGS__); } while (0)
#define PWUSB_ERR(...)  do { printf(__VA_ARGS__); } while (0)

#if PWUSB_USB_DEBUG
#define PWUSB_INFO(...) do { printf(__VA_ARGS__); } while (0)
#else
#define PWUSB_INFO(...) do { } while (0)
#endif

#endif
