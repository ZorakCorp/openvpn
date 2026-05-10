#!/bin/sh

# A sample OpenVPN startup script
# for Linux.

# openvpn config file directory (override with OV_DIR if needed)
dir=${OV_DIR:-/etc/openvpn}

if ! [ -d "$dir" ]; then
    echo >&2 "$0: missing config directory '$dir'"
    exit 1
fi

if [ ! -x "$dir/firewall.sh" ]; then
    echo >&2 "$0: skipping firewall — executable '$dir/firewall.sh' missing"
else
    "$dir/firewall.sh"
fi

# load TUN/TAP kernel module
modprobe tun

# enable IP forwarding
if ! echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null; then
    echo >&2 "$0: cannot enable ip_forward — run as root or fix permissions"
fi

# Invoke openvpn for each VPN tunnel
# in daemon mode.  Alternatively,
# you could remove "--daemon" from
# the command line and add "daemon"
# to the config file.
#
# Each tunnel should run on a separate
# UDP port.  Use the "port" option
# to control this.  Like all of
# OpenVPN's options, you can
# specify "--port 8000" on the command
# line or "port 8000" in the config
# file.

openvpn --cd "$dir" --daemon --config vpn1.conf
openvpn --cd "$dir" --daemon --config vpn2.conf
# Third tunnel requires vpn3.conf; remove if unused:
openvpn --cd "$dir" --daemon --config vpn3.conf
