#!/bin/sh
#
# prepare_server.sh: <GIT_REV> [<MHD_VERSION>]

set -e
set -x

# checkout the repo
cd /srv
git clone /git_repo nodogsplash
cd /srv/nodogsplash
git checkout "$1"

./resources/build_libmicrohttpd.sh --compile "$2"

export CFLAGS="-I/tmp/libmicrohttpd_install/include" LDFLAGS="-L/tmp/libmicrohttpd_install/lib"
make clean
make
make install

# eth0 -> internet (autoconf by lxc)
# eth1 -> httpd
# eth2 -> client
ip addr add 192.168.250.2/24 dev eth1
ip addr add 192.168.55.1/24 dev eth2
