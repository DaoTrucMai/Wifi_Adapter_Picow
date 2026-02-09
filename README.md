# Pico W USB Wi-Fi Adapter (FullMAC) — Thesis Project

Turn a **Raspberry Pi Pico W** into a **USB Wi-Fi adapter** for Linux using a **FullMAC** design:

- **Pico W firmware** handles Wi-Fi (scan / connect / disconnect / status + data plane).
- **Linux host kernel driver** communicates with Pico over **USB (TinyUSB vendor endpoints)**.

> **⚠️ Note:** This is a research/thesis project. Expect rough edges. See [Troubleshooting](#troubleshooting) if something looks “stuck”.

---

## Table of Contents
- [Project Overview](#project-overview)
- [Repository Layout](#repository-layout)
- [Requirements](#requirements)
- [Build & Flash Pico W Firmware](#build--flash-pico-w-firmware)
- [Build & Load Linux Kernel Driver](#build--load-linux-kernel-driver)
- [Control Plane (debugfs)](#control-plane-debugfs)
- [Data Plane (DHCP + Ping)](#data-plane-dhcp--ping)
- [Testing Checklist](#testing-checklist)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)
- [License](#license)

---

## Project Overview

This project implements a USB Wi-Fi adapter with:

- **TinyUSB vendor interface** on Pico W for USB transport
- **CYW43** stack in **STA mode**
- A **Linux kernel module** that:
  - sends control commands (scan/connect/disconnect/status)
  - bridges **Ethernet frames** between Linux and Pico over USB

Recommended engineering order (and what this repo targets):
1) Stable firmware control + L2 data path  
2) Stable Linux driver (net_device + reliability)  
3) Integrate **cfg80211** for standard Linux Wi-Fi UX (iw / NetworkManager / wpa_supplicant)

### Data Plane (Ethernet Frames)
- Linux sends an Ethernet frame → kernel driver → USB → Pico → Wi-Fi
- Pico receives Wi-Fi traffic → Pico → USB → driver → injected into Linux `net_device`

This enables standard networking:
- ARP
- DHCP
- ping
- TCP/UDP apps

---

## Repository Layout

Typical structure (may vary slightly as the repo evolves):

- `pico_usb_wifi_adapter/` — Pico W firmware (TinyUSB + CYW43 STA)
- `kernel_driver/` — Linux kernel module (USB driver + net_device + debugfs)

---

## Requirements

### Host (Linux)
Ubuntu is recommended.

Install build tools and kernel headers:
```bash
sudo apt update
sudo apt install -y build-essential linux-headers-$(uname -r) git
```

(Optional but useful for testing)
```bash
sudo apt install -y tcpdump net-tools iw wireless-tools
```

### Pico Firmware Toolchain
Install CMake and the ARM toolchain:
```bash
sudo apt install -y cmake gcc-arm-none-eabi
```

You also need the Raspberry Pi Pico SDK on your machine and `PICO_SDK_PATH` set.

Example:
```bash
export PICO_SDK_PATH="$HOME/pico/pico-sdk"
```

---

## Build & Flash Pico W Firmware

### Build
```bash
cd pico_usb_wifi_adapter
mkdir -p build
cd build

# If not already set:
export PICO_SDK_PATH="$HOME/pico/pico-sdk"

cmake ..
make -j
```

### Flash
1) Put Pico W in **BOOTSEL** mode (hold **BOOTSEL** while plugging USB).  
2) It mounts as a drive (usually `RPI-RP2`).  
3) Copy the UF2:

```bash
cp *.uf2 /media/$USER/RPI-RP2/
sync
```

---

## Build & Load Linux Kernel Driver

### Build
```bash
cd kernel_driver
make
```

### Load
```bash
sudo insmod pico_usb_wifi.ko
```

### Verify
```bash
lsmod | grep pico_usb_wifi || true
sudo dmesg -T | tail -n 80
```

### Unload
```bash
# bring interface down first (ignore errors if it doesn't exist)
sudo ip link set pico0 down 2>/dev/null || true

sudo rmmod pico_usb_wifi
```

> **⚠️ Important:** If the module says “in use”, a process may still hold the netdev.  
> Try bringing the interface down and stopping NetworkManager traffic (see Troubleshooting).

---

## Control Plane (debugfs)

The driver exposes control commands via `debugfs` for easy bring-up and testing.

### Mount debugfs
```bash
sudo mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
```

### Locate the debugfs node
```bash
ls -l /sys/kernel/debug/ | grep pico || true
ls -l /sys/kernel/debug/pico_usb_wifi/ || true
```

Expected files (names may vary by implementation):
- `scan_start`
- `scan_results`
- `scan_done`
- `connect`
- `disconnect`
- `status`

### Scan
```bash
echo 1 | sudo tee /sys/kernel/debug/pico_usb_wifi/scan_start > /dev/null

cat /sys/kernel/debug/pico_usb_wifi/scan_results
cat /sys/kernel/debug/pico_usb_wifi/scan_done
```

### Connect

**Open network**
```bash
echo "MyOpenSSID" | sudo tee /sys/kernel/debug/pico_usb_wifi/connect > /dev/null
```

**WPA2-PSK** (format used by this project: `SSID:PSK` or `SSID PSK` depending on driver)
```bash
# If your driver expects "SSID:PSK"
echo "MySSID:MyPassword" | sudo tee /sys/kernel/debug/pico_usb_wifi/connect > /dev/null

# If your driver expects "SSID PSK"
echo "MySSID MyPassword" | sudo tee /sys/kernel/debug/pico_usb_wifi/connect > /dev/null
```

### Status
```bash
cat /sys/kernel/debug/pico_usb_wifi/status
```

### Disconnect
```bash
echo 1 | sudo tee /sys/kernel/debug/pico_usb_wifi/disconnect > /dev/null
```

---

## Data Plane (DHCP + Ping)

The driver registers a Linux `net_device` (commonly named `pico0`).

### Bring the interface up
```bash
ip link show pico0
sudo ip link set pico0 up
```

### Obtain an IP address (DHCP)
```bash
sudo dhclient -v pico0
ip a show pico0
```

### Ping test
```bash
ping -c 4 8.8.8.8
ping -c 4 google.com
```

### Inspect traffic (optional)
```bash
sudo tcpdump -i pico0 -n
```

6) **Data plane**
```bash
sudo ip link set pico0 up
sudo dhclient -v pico0
ping -c 4 8.8.8.8
```
