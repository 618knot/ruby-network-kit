# frozen_string_literal: true

# @note ref: https://github.com/kuredev/simple_capture/blob/main/lib/simple_capture/recv_message.rb

module PacketCapture
  class PacketAnalyzer

    #
    # @param [String] msg
    #
    def initialize(msg)
      @msg_bytes = msg.bytes
    end

    def to_packet
      headers = []
      ether_header = EtherHeader.new(@msg_bytes.slice(0..13))
      ether_header.print_headers
      headers << ether_header
    end
  end
end
