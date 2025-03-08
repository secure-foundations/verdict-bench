#!/bin/sh

set -e

if [ -z $1 ] || [ -z $2 ]; then
    # Remove previously set limit
    tc qdisc del dev lo root
else
    tc qdisc del dev lo root || true

    # Add delay to loopback at a particular port
    tc qdisc add dev lo root handle 1: prio
    tc qdisc add dev lo parent 1:3 handle 30: netem delay $2

    # Outbound
    tc filter add dev lo protocol ip parent 1: prio 1 \
    u32 match ip sport $1 0xffff flowid 1:3

    # Inbound
    tc filter add dev lo protocol ip parent 1: prio 1 \
    u32 match ip dport $1 0xffff flowid 1:3
fi
