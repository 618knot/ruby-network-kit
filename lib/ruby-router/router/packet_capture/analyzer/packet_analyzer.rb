# frozen_string_literal: true

# @note ref: https://github.com/kuredev/simple_capture/blob/main/lib/simple_capture/recv_message.rb

require_relative "header_analyzer/ether"
require_relative "header_analyzer/arp"
require_relative "header_analyzer/ip"
require_relative "header_analyzer/icmp"

class PacketAnalyzer

  #
  # @param [String] msg
  #
  def initialize(msg)
    @msg_bytes = msg.bytes
  end

  def to_packet
    ether_header = HeaderAnalyzer::Ether.new(@msg_bytes)
    ether_header.analyze

    case ether_header.int_hex_type
    when Constants::EtherTypes::ARP
      HeaderAnalyzer::Arp.new(@msg_bytes.slice(14..)).analyze
    when Constants::EtherTypes::IP
      ip = HeaderAnalyzer::Ip.new(@msg_bytes.slice(14..))
      ip.analyze

      case ip.protocol
      when "ICMP"
        HeaderAnalyzer::Icmp.new(@msg_bytes.slice(21..)).analyze #範囲要修正
      else

      end

    else
      return
    end
  end
end
