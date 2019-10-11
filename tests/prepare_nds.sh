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
# eth1 -> httpd (192.168.250.2/24)
# eth2 -> client (192.168.55.1/24)
