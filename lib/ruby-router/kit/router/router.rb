# frozen_string_literal: true

require_relative "../socket_utils"
require_relative "net_util"
require_relative "../packet_analyzer/packet_analyzer"
require_relative "router_base"

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
                # analyze_packet(device, data)
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
        saddr: device.addr,
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

    def test
      source_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]   # 送信元MAC
      target_mac = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]   # ブロードキャストMAC
      source_ip  = [192, 168, 1, 10]                      # 送信元IP
      target_ip  = [192, 168, 1, 20]                      # ターゲットIP
      send_arp_request(init_socket(@interface1), source_mac, target_mac, source_ip, target_ip)
    end

    private

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
  end
end
