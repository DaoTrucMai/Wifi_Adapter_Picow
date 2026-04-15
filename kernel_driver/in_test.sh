#!/bin/bash
set -euo pipefail

LOG_FILE="kernel_log_in"

# Kill stale log followers from older runs. These can survive an interrupted
# script and keep appending to the same file, which makes new runs look like
# they contain "old" logs.
pkill -f "dmesg -w --time-format=iso" 2>/dev/null || true
pkill -f "grep --line-buffered pico_usb_wifi" 2>/dev/null || true

cleanup() {
  if [[ -n "${DMESG_PID:-}" ]]; then
    kill "${DMESG_PID}" 2>/dev/null || true
    wait "${DMESG_PID}" 2>/dev/null || true
  fi
}

trap cleanup EXIT INT TERM

# This system supports `dmesg -w` but not `dmesg -W/--follow-new`.
# `-w` prints the current ring buffer first, then follows, so drain the old
# buffer before starting the follower. This keeps `kernel_log_in` limited to
# messages generated during this test run.
sudo dmesg -c > /dev/null || true

# Capture only new kernel messages from this driver while the benchmark runs.
: > "${LOG_FILE}"
sudo dmesg -w --time-format=iso | stdbuf -oL grep --line-buffered 'pico_usb_wifi' > "${LOG_FILE}" &
DMESG_PID=$!

sleep 0.2

for i in 1 2 3; do
  echo stop  | sudo tee /sys/kernel/debug/pico_usb_wifi/bench_control
  echo reset | sudo tee /sys/kernel/debug/pico_usb_wifi/bench_control
  echo "in 2032" | sudo tee /sys/kernel/debug/pico_usb_wifi/bench_control
  sleep 20
  sudo cat /sys/kernel/debug/pico_usb_wifi/bench_stats
  echo stop | sudo tee /sys/kernel/debug/pico_usb_wifi/bench_control
done
