#!/bin/sh
. $(dirname $0)/common.sh

#
#  Run the home server.
#
exec $DIR/build/make/jlibtool --mode=execute $FR_DEBUGGER $DIR/build/bin/local/radiusd -d $(dirname $0)/raddb-totp -D $DIR/share/ -fxxxx -l stdout $@
