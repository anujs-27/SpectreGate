#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

# Define namespace and interface variables
CLIENT_NS="client_ns"
VETH_CLIENT="veth_client"
VETH_SERVER="veth_server"
CLIENT_IP="10.0.0.2/24"
SERVER_IP="10.0.0.1/24"

echo "=== Cleaning up any existing environment ==="
ip netns del $CLIENT_NS 2>/dev/null || true
ip link del $VETH_SERVER 2>/dev/null || true
sudo nft delete table inet spectregate 2>/dev/null || true

echo "=== Creating Client Network Namespace ==="
ip netns add $CLIENT_NS

echo "=== Creating Virtual Ethernet (veth) Pair ==="
ip link add $VETH_SERVER type veth peer name $VETH_CLIENT

echo "=== Moving Client Interface to Namespace ==="
ip link set $VETH_CLIENT netns $CLIENT_NS

echo "=== Configuring Host (Server) Network Stack ==="
ip addr add $SERVER_IP dev $VETH_SERVER
ip link set $VETH_SERVER up

echo "=== Configuring Client Network Stack ==="
ip netns exec $CLIENT_NS ip addr add $CLIENT_IP dev $VETH_CLIENT
ip netns exec $CLIENT_NS ip link set $VETH_CLIENT up
ip netns exec $CLIENT_NS ip link set lo up

echo "=== Initializing Host nftables Base Ruleset ==="
# 1. Create the persistent table container
nft add table inet spectregate

# 2. Add standard input filter hook targeting incoming interface traffic (Default: DROP)
nft add chain inet spectregate input \{ type filter hook input priority 0 \; policy drop \; \}

# 3. Create the atomic concatenation tracking set with flags to allow timed rule decay
nft add set inet spectregate allowed_knocks \{ type ipv4_addr . inet_service \; flags timeout \; \}

# 4. Bind the set constraint rule to allow immediate TCP access matching elements
nft add rule inet spectregate input ip saddr . tcp dport @allowed_knocks accept

# 5. Allow essential local loopback interface communications
nft add rule inet spectregate input iifname "lo" accept

echo "=== Environment Setup Completed Successfully ==="
echo "Host Interface: $VETH_SERVER ($SERVER_IP)"
echo "Client Namespace: $CLIENT_NS via $VETH_CLIENT ($CLIENT_IP)"