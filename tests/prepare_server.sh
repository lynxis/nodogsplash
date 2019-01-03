#!/bin/sh
#
# prepare_server.sh: <GIT_REV> [<MHD_VERSION>]

set -e

# checkout the repo
cd /srv
git clone /git_repo nodogsplash
cd /srv/nodogsplash
git checkout "$1"

./resources/build_libmicrohttpd.sh --compile "$2"

make clean
make
make install

ip addr 192.168.250.2/24 dev eth0
ip route add default via 192.168.250.1

ip addr 192.168.55.1/24 dev eth1
