#!/bin/bash
# 2019 Copyright Alexander Couzens <lynxis@fe80.eu>
# MIT

set -e

TOP=$(dirname "$0")
REVISION="$1"

if [ -z "$REVISION" ] ; then
	REVISION=$(git log -n 1 --format="%H")
fi

cd "$TOP"

./nodogsplash.py --check-host
./nodogsplash.py --setup
./nodogsplash.py --server "$REVISION" --test
