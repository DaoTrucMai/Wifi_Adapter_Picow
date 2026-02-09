# pico_usb_wifi kernel module (skeleton)

## Build
make

## Load/unload
sudo insmod pico_usb_wifi.ko
sudo rmmod pico_usb_wifi

## Logs
dmesg | tail -100

## DebugFS (Wi-Fi control)
The driver exposes a small control surface via debugfs under:
- /sys/kernel/debug/pico_usb_wifi/

If debugfs is not mounted yet:
sudo mount -t debugfs none /sys/kernel/debug

### Files
- scan_start (write-only): trigger a scan by writing "1"
- scan_done (read-only): "1" when the scan completes, "0" otherwise
- scan_results (read-only): human-readable scan results (SSID/RSSI/CH/BSSID/SEC)
- connect (write-only): connect using "ssid" or "ssid:psk"
- disconnect (write-only): disconnect by writing "1"
- status (read-only): cached connection status (also triggers a status request)

### Examples
Trigger scan:
echo 1 | sudo tee /sys/kernel/debug/pico_usb_wifi/scan_start

Check if scan is done:
cat /sys/kernel/debug/pico_usb_wifi/scan_done

Read scan results:
cat /sys/kernel/debug/pico_usb_wifi/scan_results

Connect (open network):
echo "MySSID" | sudo tee /sys/kernel/debug/pico_usb_wifi/connect

Connect (WPA2 PSK):
echo "MySSID:MyPassword" | sudo tee /sys/kernel/debug/pico_usb_wifi/connect

Disconnect:
echo 1 | sudo tee /sys/kernel/debug/pico_usb_wifi/disconnect

Status:
cat /sys/kernel/debug/pico_usb_wifi/status

## Bring-up (DHCP + ping)
After `connect`, the driver registers a netdev named `pico0` (or `pico1`, ...).

Request an IPv4 address via DHCP:
sudo dhclient -v -1 pico0

Verify address + routes:
ip addr show pico0
ip route

Ping the AP gateway (replace with your LAN gateway if different):
ping -c 3 -I pico0 192.168.100.1

Ping the Internet via this interface:
ping -c 3 -I pico0 8.8.8.8

Optional: sniff DHCP on the interface:
sudo tcpdump -i pico0 -n -e -vv -s0 'udp port 67 or 68'

Notes:
- Your system may also have another default route (e.g. Ethernet). Use `-I pico0` while testing.
- If NetworkManager also runs DHCP on `pico0`, you can see "two clients fighting". Prefer running only one DHCP client during bring-up.

## Expected
On plug-in:
- probe() prints VID/PID
- prints bulk IN ep (0x81) and bulk OUT ep (0x01)

On unplug:
- disconnect()
