ns:
	ip netns add host
	ip netns add RT
	ip netns add NextRouter

cable:
	ip link add host_veth1 type veth peer name RT_veth0
	ip link add RT_veth1 type veth peer name NR_veth0
	ip link add NR_veth1 type veth peer name Linux_veth0

link_set:
	ip link set host_veth1 netns host
	ip link set RT_veth0 netns RT
	ip link set RT_veth1 netns RT
	ip link set NR_veth0 netns NextRouter
	ip link set NR_veth1 netns NextRouter

set_ip:
	ip netns exec host ip addr add 192.168.0.1/24 dev host_veth1
	ip netns exec RT ip addr add 192.168.0.254/24 dev RT_veth0
	ip netns exec RT ip addr add 192.168.1.1/24 dev RT_veth1
	ip netns exec NextRouter ip addr add 192.168.1.254/24 dev NR_veth0
	ip netns exec NextRouter ip addr add 192.168.2.1/24 dev NR_veth1
	ip addr add 192.168.2.254/24 dev Linux_veth0

if_up:
	ip netns exec host ip link set lo up
	ip netns exec RT ip link set lo up
	ip netns exec NextRouter ip link set lo up

	ip netns exec host ip link set host_veth1 up
	ip netns exec RT ip link set RT_veth0 up
	ip netns exec RT ip link set RT_veth1 up
	ip netns exec NextRouter ip link set NR_veth0 up
	ip netns exec NextRouter ip link set NR_veth1 up

	ip link set Linux_veth0 up

route:
	ip netns exec host ip route add default via 192.168.0.254
	ip netns exec RT ip route add default via 192.168.1.254
	ip netns exec NextRouter ip route add default via 192.168.2.254
	ip netns exec NextRouter ip route add 192.168.0.0/24 via 192.168.1.1

	ip route add 192.168.0.0/24 via 192.168.2.1
	ip route add 192.168.1.0/24 via 192.168.2.1

ip_forward:
	cp /etc/sysctl.conf /etc/netns/RT/
	sysctl -w net.ipv4.ip_forward=1
	ip netns exec RT sysctl -w net.ipv4.ip_forward=0

setup: ns cable link_set set_ip if_up route ip_forward
