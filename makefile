create_v_eth1:
	sudo ip link add eth1 type dummy
	sudo ip link set eth1 up
	sudo ip addr add 192.168.1.100/24 dev eth1