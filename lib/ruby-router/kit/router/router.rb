# frozen_string_literal: true

require_relative "../socket_utils"
require_relative "net_util"
require_relative "../packet_analyzer/packet_analyzer"
require_relative "router_base"
require_relative "../packet_analyzer/packet_analyzer"
require_relative "../constants"
require "ipaddr"

module Router
  class Router < RouterBase
    include SocketUtils
    include NetUtil
    
    #
    # @param [String] interface1 インターフェイス1の名前
    # @param [String] interface2 インターフェイス2の名前
    # @param [String] nextIp 送信先(ルータ)IP
    #
    def initialize(interface1, interface2, next_ip)
      super(interface1, interface2, next_ip)
    end

    def run
      
    end

    def router
      buf_size = 2048

      disable_ip_forward

      @logger.info("Router is running...")

      while not end_flag
        begin
          readable, _, _ = IO.select(self.devices.map { |d| d.socket }, nil, nil, 0.1)

          next unless readable

          readable.each do |socket|
            begin
              data = socket.read_nonblock(buf_size)
              if data.nil? || data.empty?
                @logger.debug("Connection closed or no data")
              else
                d_idx = search_device_idx(socket)
                analyze_packet(d_idx, data)
              end
            rescue IO::WaitReadable
              next
            rescue StandardError => e
              @logger.warn("Error reading socket: #{e.message}")
            end
          end
        rescue
          enable_ip_forward
          self.end_flag = true
        end
      end
    end

    private

    def send_icmp_time_exceeded(device_no, ether_header, ip_header, data)
      device = self.devices[device_no]
      
      r_ether_header = ETHER.new(
        dhost: ether_header.shost,
        shost: mac_addr_to_arr(device.hwaddr),
        type: [Constants::EtherTypes::IP].pack("S>"),
      )
  
      r_iphdr = IP.new(
        version: 4,
        ihl: 20 / 4,
        tos: 0,
        tot_len: 8 + 64,
        id: 0,
        frag_off: 0,
        ttl: 64,
        protocol: 1,
        check: 0,
        saddr: ip_addr_to_arr(device.addr),
        daddr: ip_header.saddr,
      )

      r_iphdr.check = checksum(r_iphdr.to_binary.bytes)

      icmp = ICMP.new(
        type: 11, # ICMP_TIME_EXCEEDED
        code: 0,  # ICMP_TIMXCEED_INTRANS
        check: 0,
        void: 0,
      )

      icmp.check = checksum(icmp.to_binary.bytes + ether_header)

      packet = r_ether_header.to_binary + r_iphdr.to_binary + icmp.to_binary + data.slice(14..(14 + 64))

      socket = @devices[device_no].socket
      socket.write(packet)
    end

    def analyze_packet(device_no, data)
      @analyzed_data = PacketAnalyzer.new(data.bytes, disable_log: true).analyze
      ether = @analyzed_data[:ether]

      if ether.nil?
        @logger.debug("#{@devices[device_no].if_name}: Ethernet header not found")
        return
      end

      if ether.dst_mac_address != @devices[device_no].hwaddr
        @logger.debug("#{@devices[device_no].if_name}: Destination MAC does not match => #{ether.dst_mac_address}")
        return
      end

      case ether.type
      when Constants::EtherTypes::ARP
        analyze_arp(device_no, @analyzed_data[:arp])
      when Constants::EtherTypes::IP
        analyze_ip(device_no, @analyzed_data[:ip], ether, data)
      end
    end

    def disable_ip_forward
      File.open("/proc/sys/net/ipv4/ip_forward", "w") do |f|
        f.puts "0"
      end
    end

    def enable_ip_forward
      File.open("/proc/sys/net/ipv4/ip_forward", "w") do |f|
        f.puts "1"
      end
    end

    def search_device_idx(socket)
      @devices.each_with_index do |d, i|
        return i if d.socket == socket
      end
    end

    def analyze_arp(device_no, arp)
      arp_op = to_hex_int(arp.arp_op)

      @logger.debug("#{@devices[device_no].if_name}: Receive ARP REQUEST") if arp_op == 1 # ARPOP_REQUEST
      @logger.debug("#{@devices[device_no].if_name}: Receive ARP REPLY") if arp_op == 2 # ARPOP_REPLY
      
      ip2mac(device_no, arp.arp_spa, arp.arp_sha)
    end

    def analyze_ip(device_no, ip, ether, data)
      ip_cpy = IP.new
      ip_cpy.copy_from_analyzed(ip)

      ip_checksum = checksum(ip_cpy.to_binary.bytes)

      unless valid_checksum?(ip_checksum)
        @logger.debug("#{@devices[device_no].if_name}: Bad IP checksum")
        return
      end

      if ip_cpy.ttl <= 1
        @logger.debug("#{@devices[device_no].if_name}: TTL expired")
        send_icmp_time_exceeded(device_no, ether, ip_cpy, data)
        return
      end

      dest_ip = ip_cpy.dest_ip.join(":")
      sender_devices = @devices.clone.delete_at(device_no)

      sender_devices.each_with_index do |device, idx|
        if (IPAddr.new(dest_ip) & IPAddr.new(device.netmask).to_i) == IPAddr.new(devive.subnet).to_i
          handle_segment(device_no, idx, ip_cpy, data)
        else
          handle_next(device_no, idx, ip_cpy, data)
        end
      end
    end

    def handle_segment(device_no, tno, ip, data)
      dest_ip = ip.dest_ip.join(":")
      if dest_ip == @devices[device_no].addr
        @logger.debug("#{@devices[device_no].if_name}: Received for this device")

        return
      end

      ip2mac = ip_to_mac(tno, dest_ip, nil)
      if ip2mac.flag == :ng || ip2mac.send_data.dno != 0
        append_send_data(ip2mac, 1, ip.dest_ip, data)
      else
        forward_packet(ip2mac.hwaddr, tno, ip, data)
      end
    end

    def handle_next(device_no, tno, ip, data)
      ip2mac = ip_to_mac(tno, @next_ip, nil)
      if ip2mac.flag == :ng || ip2mac.send_data.dno != 0
        append_send_data(ip2mac, 1, @next_ip, nil)
      else
        forward_packet(ip2mac.hwaddr, tno, ip, data)
      end
    end

    def forward_packet(dest_mac, tno, ip, data)
      ip.ttl -= 1
      ip_checksum_for_sending(ip)

      analyzed_eth = @analyzed_data[:ether]

      ether_bin = ETHER.new(
        dest_mac.pack("C*"),
        analyzed_eth.dst_mac_address.pack("C*"),
        analyzed_eth.type.pack("S>"),
      ).to_binary

      ip_bin = ip.to_binary

      packet = ether_bin + ip_bin + data[ether_bin.length + ip_bin.length..]

      @devices[tno].socket.write(packet)
    end
  end
end
