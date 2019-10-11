#!/bin/sh

# fail when something fails
set -e

# checkout the repo
cd /srv
git clone /git_repo nodogsplash
cd /srv/nodogsplash
git checkout "$1"

cd /srv/nodogsplash/tests

# eth0 -> internet (autoconf by lxc)
# eth1 -> httpd
ip addr flush dev eth0
ip addr add 192.168.250.1/24 dev eth1
