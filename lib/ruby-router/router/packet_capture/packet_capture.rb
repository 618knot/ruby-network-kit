# frozen_string_literal: true

# @note ref: https://github.com/kuredev/simple_capture/blob/fe1b043774045d677e7aca3321ceb12a40989558/lib/simple_capture/capture.rb

require "socket"
require_relative "analyzer/packet_analyzer"

module PacketCapture
  class Capture
    ETH_P_ALL = 768.freeze # htons(ETH_P_ALL) netinet/if_ethre.h Every packet
    SIOCGIFINDEX = 0x8933.freeze # bits/ioctls.h

    #
    # @param [String] interface interface_name
    #
    def initialize(interface)
      @interface = interface
    end

    def run
      socket = generate_raw_socekt
      bind_interface(socket, @interface)
      capture_loop(socket)
    end

    private

    #
    # Socketの生成
    #
    # @param [String] interface interface_name
    #
    # @return [Socket] socket raw_socket
    #
    def generate_raw_socekt
      Socket.new(Socket::AF_PACKET, Socket::SOCK_RAW, ETH_P_ALL)
    end

    
    #
    # interfaceのバインド
    # @note ref: https://github.com/prolaag/socket2/blob/master/lib/socket2.rb
    #       ref: https://github.com/kuredev/simple_capture/blob/fe1b043774045d677e7aca3321ceb12a40989558/lib/simple_capture/capture.rb#L35
    #
    # @param [<Type>] socket
    # @param [<Type>] interface interface_name
    #
    def bind_interface(socket, interface)
      interface_idx = interface_idx_str(socket, interface)
      eth_p_all_hbo = [ ETH_P_ALL ].pack("S").unpack('S>').first # ホストバイトオーダーでパックしたものをビッグエンディアンに変換して整数にする
      sockaddr_ll = [ Socket::AF_PACKET, eth_p_all_hbo, interface_idx ].pack("SS>a16") # [ホストバイトオーダー, ネットワークバイトオーダー, 16Byte固定長文字列]

      socket.bind(sockaddr_ll)
    end

    #
    # interfaceのindexを文字列で返す
    #
    # @param [String] interface interface_name
    #
    # @return [String] interface index
    #
    def interface_idx_str(socket, interface)
      ifreq = [interface, ""].pack("a16a16") # 16 Byte string * 2
      socket.ioctl(SIOCGIFINDEX, ifreq) # get ifreq struct
      ifreq.slice!(16, 4)
    end

    #
    # caputureのmain loop
    #
    # @param [Socket] socket
    #
    def capture_loop(socket)
      logger = CustomLogger.new
      logger.info("PacketCapture running")
      loop do
        # @note https://www.cloudflare.com/ja-jp/learning/network-layer/what-is-mtu/
        msg, _ = socket.recvfrom(1514) # MTU + MAC_ADDRESS * 2 + TYPE = 1514
        PacketAnalyzer.new(msg.bytes).analyze
      end
    end
  end
end
