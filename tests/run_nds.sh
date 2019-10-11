#!/bin/sh

set -e

export LD_LIBRARY_PATH=/tmp/libmicrohttpd_install/lib
cd /srv/nodogsplash/
./nodogsplash -c tests/nodogsplash.conf
