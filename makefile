create_v_eth1:
	sudo ip link add eth1 type dummy
	sudo ip link set eth1 up
	sudo ip addr add 192.168.1.100/24 dev eth1

NS1 = ns1
NS2 = ns2
VETH1 = veth1
VETH2 = veth2
ROUTER_IP_NS1 = 192.168.1.254
ROUTER_IP_NS2 = 192.168.2.254
ROUTER_SCRIPT = router.rb

# 名前空間の作成
create-ns:
	sudo ip netns add $(NS1)
	sudo ip netns add $(NS2)

# 仮想インターフェースの作成
create-veth:
	sudo ip link add $(VETH1) type veth peer name $(VETH2)

# 名前空間にインターフェースを割り当て
set-veth-ns:
	sudo ip link set $(VETH1) netns $(NS1)
	sudo ip link set $(VETH2) netns $(NS2)

# IP アドレスの設定
set-ip:
	sudo ip netns exec $(NS1) ip addr add 192.168.1.1/24 dev $(VETH1)
	sudo ip netns exec $(NS1) ip link set $(VETH1) up
	sudo ip netns exec $(NS1) ip link set lo up
	sudo ip netns exec $(NS2) ip addr add 192.168.2.1/24 dev $(VETH2)
	sudo ip netns exec $(NS2) ip link set $(VETH2) up
	sudo ip netns exec $(NS2) ip link set lo up

# 仮想インターフェースをホストに追加
set-host-interfaces:
	sudo ip link add eth0 type dummy
	sudo ip link add eth1 type dummy
	sudo ip addr add $(ROUTER_IP_NS1)/24 dev eth0
	sudo ip addr add $(ROUTER_IP_NS2)/24 dev eth1
	sudo ip link set eth0 up
	sudo ip link set eth1 up

# IP フォワーディングを有効化
enable-ip-forwarding:
	sudo sysctl -w net.ipv4.ip_forward=1

# RubyRouter の実行
run-router:
	ruby $(ROUTER_SCRIPT)

# 名前空間の削除
delete-ns:
	sudo ip netns del $(NS1)
	sudo ip netns del $(NS2)
	sudo ip link delete $(VETH1)
	sudo ip link delete $(VETH2)

# クリーンアップ: 名前空間とインターフェースの削除
clean: delete-ns
	sudo ip link delete eth0
	sudo ip link delete eth1

# 実行フロー: 名前空間作成 -> インターフェース設定 -> ルータ起動
setup: create-ns create-veth set-veth-ns set-ip set-host-interfaces enable-ip-forwarding
