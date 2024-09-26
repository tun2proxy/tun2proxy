#!/bin/bash

# sudo apt install iperf3 dante-server
# sudo systemctl stop danted

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo $SCRIPT_DIR

netns="test"
dante="danted"
tun2proxy="${SCRIPT_DIR}/../../target/release/tun2proxy-bin"

ip netns add "$netns"

ip link add veth0 type veth peer name veth0 netns "$netns"

# Configure veth0 in default ns
ip addr add 10.0.0.2/24 dev veth0
ip link set dev veth0 up

# Configure veth0 in child ns
ip netns exec "$netns" ip addr add 10.0.0.3/24 dev veth0
ip netns exec "$netns" ip addr add 10.0.0.4/24 dev veth0
ip netns exec "$netns" ip link set dev veth0 up

# Configure lo interface in child ns
ip netns exec "$netns" ip addr add 127.0.0.1/8 dev lo
ip netns exec "$netns" ip link set dev lo up

echo "Starting Dante in background ..."
ip netns exec "$netns" "$dante" -f ${SCRIPT_DIR}/dante.conf &

# Start iperf3 server in netns
ip netns exec "$netns" iperf3 -s -B 10.0.0.4 &

sleep 1

# Prepare tun2proxy
ip tuntap add name tun0 mode tun
ip link set tun0 up
ip route add 10.0.0.4 dev tun0
"$tun2proxy" --proxy socks5://10.0.0.3:10800 &

# Run iperf client through tun2proxy
iperf3 -c 10.0.0.4

iperf3 -c 10.0.0.4 -R -P 10

# Clean up
# sudo sh -c "pkill tun2proxy-bin; pkill iperf3; pkill danted; ip link del tun0; ip netns del test"
