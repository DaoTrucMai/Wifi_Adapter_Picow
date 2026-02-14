# pico_usb_wifi kernel module (skeleton)

## Build
make

## Load/unload
sudo modprobe cfg80211
sudo insmod pico_usb_wifi.ko
sudo rmmod pico_usb_wifi

## WPA2 via wpa_supplicant (cfg80211 path)
`iw dev pico0 connect` is only good for open networks. For WPA/WPA2 PSK you typically use `wpa_supplicant`.

### What the flags/commands mean (quick reference)
`wpa_supplicant` flags:
- `-i pico0`: operate on interface `pico0`
- `-D nl80211`: use the standard Linux Wi-Fi control interface (cfg80211/nl80211)
- `-B`: run in the background (daemonize)
- `-c <file>`: read config file (networks, ctrl socket, options)
- `-c /dev/null`: start with an empty config (use `wpa_cli` to add networks)
- `-C /run/wpa_supplicant`: create control sockets under this directory
- `-dd`: extra verbose debug logs
- `-f <file>`: write logs to a file

`wpa_cli` flags:
- `-p /run/wpa_supplicant`: directory where the control socket lives
- `-i pico0`: which interface’s socket to talk to

Common `wpa_cli` commands:
- `scan`: trigger a scan
- `scan_results`: show AP list discovered by the last scan
- `add_network`: create a new network profile (returns an id like `0`)
- `set_network <id> ssid '"SSID"'`: set SSID (must be quoted string)
- `set_network <id> psk '"PASSWORD"'`: set WPA2 passphrase (must be quoted string)
- `enable_network` / `select_network`: allow/choose a network to connect
- `disconnect`: disconnect from the current network
- `reassociate`: retry association
- `status`: current WPA state (look for `wpa_state=COMPLETED`)

### Clean start (after reboot or if you get stuck)
If you see errors like:
- `wpa_cli ... Failed to connect ... No such file or directory` (no control socket)
- `Operation already in progress (-114)`

Reset everything:
`pkill` stops any old `wpa_supplicant` instance for `pico0` and removing the socket fixes stale state.
sudo pkill -f "wpa_supplicant.*pico0" || true
sudo rm -f /run/wpa_supplicant/pico0

# Optional: release any previous DHCP lease / routes on pico0
These help when re-testing DHCP from a clean state.
sudo dhclient -r pico0 || true
sudo ip addr flush dev pico0 || true
sudo ip route flush dev pico0 || true

Before starting WPA:
Bring the netdev administratively up (required so scan/connect can run):
sudo ip link set pico0 up

### Option A: Use a config file (recommended)
This is the usual workflow for reproducible testing (and what NetworkManager generates behind the scenes).

Create config:
Creates `/etc/wpa_supplicant/pico0.conf` with a single WPA2-PSK network.
sudo sh -c 'cat > /etc/wpa_supplicant/pico0.conf <<EOF
ctrl_interface=/run/wpa_supplicant
update_config=1

network={
    ssid="MySSID"
    psk="MyPassword"
    key_mgmt=WPA-PSK
}
EOF'

If you already started `wpa_supplicant` before, you may have a stale control socket:
Stops old instances and removes stale `/run/wpa_supplicant/pico0` so `wpa_cli` can connect.
sudo pkill -f "wpa_supplicant.*pico0" || true
sudo rm -f /run/wpa_supplicant/pico0

Start and watch logs:
Starts `wpa_supplicant` in the background for interface `pico0` using the nl80211 driver and prints verbose logs.
sudo wpa_supplicant -B -i pico0 -c /etc/wpa_supplicant/pico0.conf -D nl80211 -dd

Check status:
`wpa_cli` queries the running `wpa_supplicant` over its control socket.
sudo wpa_cli -p /run/wpa_supplicant -i pico0 status

Save logs to a file (optional):
Writes verbose logs to `/tmp/pico0_wpa.log` for later inspection.
sudo wpa_supplicant -B -i pico0 -c /etc/wpa_supplicant/pico0.conf -D nl80211 -dd -f /tmp/pico0_wpa.log

### Option B: No config file (configure via wpa_cli)
This is useful for quick experiments. The key detail: for `ssid`/`psk`, the value must be a quoted string.

Start `wpa_supplicant`:
Starts with an empty config (`/dev/null`) and creates the control socket under `/run/wpa_supplicant/`.
sudo wpa_supplicant -B -i pico0 -c /dev/null -C /run/wpa_supplicant -D nl80211 -dd -f /tmp/pico0_wpa.log

Trigger scan:
sudo wpa_cli -p /run/wpa_supplicant -i pico0 scan

Show scan results (choose SSID from here):
sudo wpa_cli -p /run/wpa_supplicant -i pico0 scan_results

Create a new network profile:
sudo wpa_cli -p /run/wpa_supplicant -i pico0 add_network

Set SSID and PSK (note the nested quotes):
sudo wpa_cli -p /run/wpa_supplicant -i pico0 set_network 0 ssid '"MySSID"'
sudo wpa_cli -p /run/wpa_supplicant -i pico0 set_network 0 psk  '"MyPassword"'
sudo wpa_cli -p /run/wpa_supplicant -i pico0 set_network 0 key_mgmt WPA-PSK

Enable and connect:
sudo wpa_cli -p /run/wpa_supplicant -i pico0 enable_network 0
sudo wpa_cli -p /run/wpa_supplicant -i pico0 select_network 0
sudo wpa_cli -p /run/wpa_supplicant -i pico0 reassociate

Check status (wait for `wpa_state=COMPLETED`):
sudo wpa_cli -p /run/wpa_supplicant -i pico0 status

Disconnect (optional):
sudo wpa_cli -p /run/wpa_supplicant -i pico0 disconnect

## Logs
dmesg | tail -100

## Enable verbose driver logs (when debugging)
The module supports runtime-togglable logging via module parameters:

Load with debug enabled:
sudo insmod pico_usb_wifi.ko debug=1

Optional: force BOOTP broadcast flag for DHCP (some APs/relays behave better):
sudo insmod pico_usb_wifi.ko debug=1 dhcp_force_broadcast=1

You can also toggle at runtime (module params are 0644):
echo 1 | sudo tee /sys/module/pico_usb_wifi/parameters/debug
echo 1 | sudo tee /sys/module/pico_usb_wifi/parameters/dhcp_force_broadcast

For live logs while testing:
sudo dmesg -w

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
sudo cat /sys/kernel/debug/pico_usb_wifi/scan_done

Read scan results:
sudo cat /sys/kernel/debug/pico_usb_wifi/scan_results

Connect (open network):
echo "MySSID" | sudo tee /sys/kernel/debug/pico_usb_wifi/connect

Connect (WPA2 PSK):
echo "MySSID:MyPassword" | sudo tee /sys/kernel/debug/pico_usb_wifi/connect

Disconnect:
echo 1 | sudo tee /sys/kernel/debug/pico_usb_wifi/disconnect

Status:
sudo cat /sys/kernel/debug/pico_usb_wifi/status

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

### NetworkManager note (recommended for bring-up)
During development it's convenient to keep NetworkManager enabled, but mark `pico0` as unmanaged so it does not start DHCP / change routes while you are testing.
The filename under `/etc/NetworkManager/conf.d/` is arbitrary; `10-pico0.conf` is just an example.

Make `pico0` unmanaged:
sudo sh -c 'cat > /etc/NetworkManager/conf.d/10-pico0.conf <<EOF
[keyfile]
unmanaged-devices=interface-name:pico0
EOF'
sudo systemctl restart NetworkManager

Undo (return to normal):
sudo rm -f /etc/NetworkManager/conf.d/10-pico0.conf
sudo systemctl restart NetworkManager

If you previously disabled NetworkManager globally:
sudo systemctl enable --now NetworkManager

### NetworkManager GUI / nmcli (optional)
If NetworkManager is managing `pico0`, you can connect via the Ubuntu GUI or `nmcli`.

Show device status:
nmcli dev status
nmcli dev show pico0

Scan for networks using `pico0`:
nmcli dev wifi list ifname pico0

Connect:
sudo nmcli dev wifi connect "MySSID" password "MyPassword" ifname pico0

Disconnect:
sudo nmcli dev disconnect pico0

## Expected
On plug-in:
- probe() prints VID/PID
- prints bulk IN ep (0x81) and bulk OUT ep (0x01)

On unplug:
- disconnect()
