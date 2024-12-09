# frozen_string_literal: true

# @note ref: https://github.com/kuredev/simple_bridge/blob/main/lib/simple_bridge/bridge.rb

require_relative "../socket_utils"
require_relative "../packet_analyzer/packet_analyzer"

module Bridge
  class Bridge
    include SocketUtils

    #
    # @param [String] *interfaces 2つ以上のinterface名 
    #
    def initialize(*interfaces)
      raise ArgumentError if interfaces.length < 2
      @interfaces = interfaces
    end
  
    def run
      sockets = []
  
      @interfaces.map { |_i|
        sockets << generate_raw_socekt
      }

      if_sockets = @interfaces.zip(sockets).to_h

      if_sockets.map { |itfc, soc|
        bind_interface(soc, itfc)
      }

      logger = CustomLogger.new
      logger.info("Bridge is running")
      logger.debug("Socket IDs #{sockets.map(&:object_id).join(", ")}")

      loop do
        arrivals = IO::select(sockets)

        arrivals.first.each do |soc|
          logger.info("■■■■■ Received at #{soc.object_id} ■■■■■")

          msg = soc.recv(1514)
          sockets_tmp = sockets.reject { |s| s == soc }

          logger.debug("Send to #{sockets_tmp.map(&:object_id).join(", ")}")
          PacketAnalyzer.new(msg.bytes).analyze

          sockets_tmp.map { |dest_soc|
            dest_soc.send(msg, 0)
          }
        end
      end
    end
  end
end