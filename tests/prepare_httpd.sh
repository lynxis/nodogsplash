#!/bin/sh

# fail when something fails
set -e

cd /testing

# eth0 -> internet (autoconf by lxc)
# eth1 -> httpd (192.168.250.1/24)
ip addr flush dev eth0
ip route add 192.168.55.0/24 via 192.168.250.2
