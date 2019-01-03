#!/bin/sh

# fail when something fails
set -e

# checkout the repo
cd /srv
git clone /git_repo nodogsplash
cd /srv/nodogsplash
git checkout "$1"

cd /srv/nodogsplash/tests

ip addr add 192.168.55.2/24 dev vnet0
ip route add default via 192.168.55.1
