# frozen_string_literal: true

require_relative "../socket_utils"
require_relative "net_util"
require_relative "../packet_analyzer/packet_analyzer"

module Router
  class Router
    include SocketUtils
    include NetUtil
    
    #
    # @param [String] interface1 インターフェイス1の名前
    # @param [String] interface2 インターフェイス2の名前
    # @param [String] nextIp 送信先(ルータ)IP
    #
    def initialize(interface1, interface2, nextIp)
      @interface1 = interface1
      @interface2 = interface2
      @nextIp = nextIp
    end

    def run
      sockets = {
        @interface1 => init_socket(@interface1),
        @interface2 => init_socket(@interface2),
      }.to_a.freeze
    end

    def test
      source_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]   # 送信元MAC
      target_mac = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]   # ブロードキャストMAC
      source_ip  = [192, 168, 1, 10]                      # 送信元IP
      target_ip  = [192, 168, 1, 20]                      # ターゲットIP
      send_arp_request(init_socket(@interface1), source_mac, target_mac, source_ip, target_ip)
    end

    private

    def init_socket(interface)
      socket = generate_raw_socekt
      bind_interface(socket, interface)
      socket
    end
  end
end
