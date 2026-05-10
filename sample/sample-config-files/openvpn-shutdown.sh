#!/bin/sh

# stop all openvpn processes (Linux-specific; systemd users may prefer
#   systemctl stop openvpn-client@\* or scoped unit names)

PATH="/usr/sbin:/usr/local/sbin:/sbin:${PATH}"

if command -v killall >/dev/null 2>&1
then killall -TERM openvpn >/dev/null 2>&1 || true
elif command -v pkill >/dev/null 2>&1
then pkill -TERM -x openvpn >/dev/null 2>&1 || true
else
    echo >&2 "$0: need killall(1) or pkill(1)"
    exit 1
fi
