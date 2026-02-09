# Pico W USB Wi-Fi Adapter (Vendor Bulk + STA scan)

## What it does (v0.1)
- Pico enumerates as a USB vendor device (bulk IN/OUT).
- Implements a framed protocol "PHTM".
- Supports:
  - HELLO -> HELLO_RSP
  - CMD_SCAN_START -> EVT_SCAN_RESULT (many) -> EVT_SCAN_DONE
  - CMD_CONNECT / CMD_DISCONNECT / GET_STATUS
  - DATA_TX_ETH / DATA_RX_ETH for raw Ethernet bridging (L2)

## Requirements
- Pico SDK installed, PICO_SDK_PATH set.
- pico-examples style build system.
- Build on Raspberry Pi Linux (host) is fine.
- lwIP is disabled; the Pico acts as a pure L2 bridge (Linux does DHCP/IP).

## UART logs
- Logs are printed via Pico UART (not USB CDC).
- Default Pico SDK stdio UART is typically UART0 on GPIO0/1 at 115200 baud (unless you changed it).

## cyw43-driver (vendored)
This project vendors `cyw43-driver` under `third_party/cyw43-driver` and
points `PICO_CYW43_DRIVER_PATH` to it. This keeps your system SDK pristine
and applies a minimal non-lwIP guard for raw Ethernet bridging.

## Build
mkdir build
cd build
cmake .. -DPICO_BOARD=pico_w
make -j4

Flash:
- hold BOOTSEL and plug Pico W
- copy UF2 from build output.

## Host testing
You can use libusb or python pyusb to:
- claim interface
- bulk OUT: send HELLO or CMD_SCAN_START
- bulk IN: read events/responses

VID/PID used:
- VID 0xCAFE, PID 0x4001

## Bring-up (with linux_pico_usb_wifi)
Typical end-to-end test flow:
- Load the kernel module from `linux_pico_usb_wifi/kernel_driver/`.
- Use debugfs `connect` to associate the Pico STA to your AP.
- Run DHCP on `pico0` and ping through it.

See `linux_pico_usb_wifi/kernel_driver/README.md` for the exact commands.
