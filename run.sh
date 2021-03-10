#!/bin/bash

sudo setcap 'CAP_NET_ADMIN+eip' build/Exe/$1
./build/Exe/$1 &
pid=$!
sudo ip addr add 10.0.0.1/24 dev tun0
sudo ip link set up dev tun0
trap "kill $pid" INT TERM
wait $pid

echo "finish."