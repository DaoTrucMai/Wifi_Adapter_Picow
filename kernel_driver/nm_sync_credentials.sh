#!/bin/bash
set -eu

debugfs_cred="/sys/kernel/debug/pico_usb_wifi/credential"

if [ ! -w "$debugfs_cred" ]; then
    echo "debugfs credential endpoint is not writable: $debugfs_cred" >&2
    exit 1
fi

nmcli -t -f UUID,TYPE connection show | while IFS=: read -r uuid type; do
    ssid=""
    key_mgmt=""
    psk=""

    [ "$type" = "802-11-wireless" ] || continue

    mapfile -t fields < <(
        nmcli --show-secrets -g \
            802-11-wireless.ssid,\
802-11-wireless-security.key-mgmt,\
802-11-wireless-security.psk \
            connection show "$uuid" 2>/dev/null || true
    )

    [ "${#fields[@]}" -ge 3 ] || continue
    ssid="${fields[0]}"
    key_mgmt="${fields[1]}"
    psk="${fields[2]}"

    [ -n "$ssid" ] || continue
    [ "$key_mgmt" = "wpa-psk" ] || continue
    [ -n "$psk" ] || continue

    printf '%s:%s\n' "$ssid" "$psk" > "$debugfs_cred"
    echo "synced credential for SSID: $ssid"
done
