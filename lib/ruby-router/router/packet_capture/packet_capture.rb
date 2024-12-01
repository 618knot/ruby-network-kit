# frozen_string_literal: true

# @note ref: https://github.com/kuredev/simple_capture/blob/fe1b043774045d677e7aca3321ceb12a40989558/lib/simple_capture/capture.rb

require "socket"
require_relative "analyzer/packet_analyzer"
require_relative "../socket_utils"

module PacketCapture
  class Capture
    include SocketUtils

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
    # caputureのmain loop
    #
    # @param [Socket] socket
    #
    def capture_loop(socket)
      logger = CustomLogger.new
      logger.info("PacketCapture is running")
      loop do
        # @note https://www.cloudflare.com/ja-jp/learning/network-layer/what-is-mtu/
        msg, _ = socket.recvfrom(1514) # MTU + MAC_ADDRESS * 2 + TYPE = 1514
        PacketAnalyzer.new(msg.bytes).analyze
      end
    end
  end
end
