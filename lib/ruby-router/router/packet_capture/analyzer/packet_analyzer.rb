# frozen_string_literal: true

# @note ref: https://github.com/kuredev/simple_capture/blob/main/lib/simple_capture/recv_message.rb

require_relative "header_analyzer/ether"
require_relative "protocol_analyzer/arp"

class PacketAnalyzer

  #
  # @param [String] msg
  #
  def initialize(msg)
    @msg_bytes = msg.bytes
  end

  def to_packet
    ether_header = HeaderAnalyzer::Ether.new(@msg_bytes)
    ether_header.print_header

    case ether_header.int_hex_type
    when Constants::EtherTypes::ARP
      ProtocolAnalyzer::Arp.new(@msg_bytes.slice(14..)).analyze
    else
      return
    end
  end
end
