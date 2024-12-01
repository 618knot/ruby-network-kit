# frozen_string_literal: true

# @note ref: https://github.com/kuredev/simple_capture/blob/main/lib/simple_capture/recv_message.rb

require_relative "header_analyzer/ether"
require_relative "header_analyzer/arp"
require_relative "header_analyzer/ip"
require_relative "header_analyzer/icmp"
require_relative "header_analyzer/tcp"
require_relative "header_analyzer/udp"
require_relative "base_analyzer"

class PacketAnalyzer < BaseAnalyzer
  def analyze
    ether_header = HeaderAnalyzer::Ether.new(@msg_bytes.clone)
    ether_header.analyze

    @msg_bytes.slice!(...14)

    case ether_header.int_hex_type
    when Constants::EtherTypes::ARP
      HeaderAnalyzer::Arp.new(@msg_bytes.clone).analyze
    when Constants::EtherTypes::IP
      ip = HeaderAnalyzer::Ip.new(@msg_bytes.clone)
      ip.analyze

      @msg_bytes.slice!(...(ip.ihl * 4))

      case ip.protocol        
      when "ICMP"
        HeaderAnalyzer::Icmp.new(@msg_bytes.clone).analyze
      when "TCP"
        HeaderAnalyzer::Tcp.new(@msg_bytes.clone, ip).analyze
      when "UDP"
        HeaderAnalyzer::Udp.new(@msg_bytes.clone, ip).analyze
      else
      end

    else
      return
    end

    @logger.debug("--------------------------------------------")
  end
end
