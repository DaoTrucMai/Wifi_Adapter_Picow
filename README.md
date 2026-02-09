# Pico W USB Wi-Fi Adapter (FullMAC) — Thesis Project

This repository turns a **Raspberry Pi Pico W** into a **USB Wi-Fi adapter** for Linux using a **FullMAC** design:

- **Pico W firmware** handles Wi-Fi (scan / connect / disconnect / status + data path).
- **Linux host kernel driver** talks to the Pico over **USB (TinyUSB vendor endpoints)**.

---

## Project Overview

This project implements a USB Wi-Fi adapter with:
- **TinyUSB vendor interface** on Pico W for USB transport
- **CYW43** (Pico W Wi-Fi chip stack) in **STA mode**
- A **Linux kernel module** that:
  - sends control commands (scan/connect/disconnect/status)
  - bridges **Ethernet frames** between Linux and Pico over USB

The goal is a working FullMAC adapter + a clean thesis-ready engineering story:
1) stable firmware (connect + L2)
2) stable driver (net_device + reliability)
3) integrate **cfg80211** for standard Linux Wi-Fi UX

---

### Data Plane (Ethernet Frames)
- Linux sends an Ethernet frame → driver → USB → Pico → Wi-Fi
- Pico receives Wi-Fi traffic → Pico → USB → driver → injected into Linux net_device

This enables standard networking:
- ARP
- DHCP
- ping
- TCP/UDP apps

---

## Repository Layout

Typical structure:
- `pico_usb_wifi_adapter/` — Pico W firmware (TinyUSB + CYW43 STA)
- `kernel_driver/` — Linux kernel module (USB driver + net_device + debugfs)

---

## Requirements

### Host (Linux)
- Ubuntu recommended
- Build tools + kernel headers:
  ```bash
  sudo apt update
  sudo apt install -y build-essential linux-headers-$(uname -r) git

### Pico firmware toolchain
- CMake + ARM toolchain: sudo apt install -y cmake gcc-arm-none-eabi
- Pico SDK installed locally (set PICO_SDK_PATH)

---

## Build & Flash Pico W Firmware

### Build
cd pico_usb_wifi_adapter
mkdir -p build
cd build

# If not already set:
# export PICO_SDK_PATH=~/pico/pico-sdk

cmake ..
make -j

### Flash
- Put Pico W in BOOTSEL mode (hold BOOTSEL while plugging USB).
- It mounts as a drive (usually RPI-RP2).
- Copy the UF2: cp *.uf2 /media/$USER/RPI-RP2/

---

## Build & Load Linux Kernel Driver

### Build
cd kernel_driver
make

### Load 
sudo insmod pico_usb_wifi.ko

### Verify
lsmod | grep pico_usb_wifi || true
sudo dmesg -T | tail -n 80

### Unload
sudo ip link set pico0 down 2>/dev/null || true
sudo rmmod pico_usb_wifi

---

## Control Plane Usage (debugfs)

### Mount debugfs
sudo mount -t debugfs none /sys/kernel/debug || true

### Locate debugfs node
ls -l /sys/kernel/debug/
ls -l /sys/kernel/debug/pico_usb_wifi/ || true
Expected files:
scan_start
scan_results
scan_done
connect
disconnect
status

### Scan
echo 1 | sudo tee /sys/kernel/debug/pico_usb_wifi/scan_start > /dev/null
cat /sys/kernel/debug/pico_usb_wifi/scan_results
cat /sys/kernel/debug/pico_usb_wifi/scan_done

### Connect
- Open network: echo "MyOpenSSID" | sudo tee /sys/kernel/debug/pico_usb_wifi/connect > /dev/null
- WPA2-PSK (format: SSID PASSWORD): echo "MySSID MyPassword" | sudo tee /sys/kernel/debug/pico_usb_wifi/connect > /dev/null

### Status
cat /sys/kernel/debug/pico_usb_wifi/status

### Disconnect
echo 1 | sudo tee /sys/kernel/debug/pico_usb_wifi/disconnect > /dev/null

---

## Data Plane Usage (DHCP + Ping)
The driver registers a Linux net_device (pico0)

### Bring the interface up
ip link show pico0
sudo ip link set pico0 up

### Get an IP address
sudo dhclient -v pico0

### sudo dhclient -v pico0
ip a show pico0
ping -c 4 8.8.8.8
ping -c 4 google.com

### Inspect traffic (optional)
sudo tcpdump -i pico0 -n