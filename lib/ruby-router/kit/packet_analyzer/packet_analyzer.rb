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
    result = {}

    ether_header = HeaderAnalyzer::Ether.new(@msg_bytes.clone)
    ether_header.analyze

    result[:ether] = ether_header

    @msg_bytes.slice!(...14)

    case ether_header.int_hex_type
    when Constants::EtherTypes::ARP
      arp = HeaderAnalyzer::Arp.new(@msg_bytes.clone)
      arp.analyze

      result[:arp] = arp_header
    when Constants::EtherTypes::IP
      ip = HeaderAnalyzer::Ip.new(@msg_bytes.clone)
      ip.analyze

      result[:ip] = ip

      @msg_bytes.slice!(...(ip.ihl * 4))

      case ip.protocol
      when Constants::Ip::ICMP
        icmp = HeaderAnalyzer::Icmp.new(@msg_bytes.clone)
        icmp.analyze

        result[:icmp] = icmp
      when Constants::Ip::TCP
        tcp = HeaderAnalyzer::Tcp.new(@msg_bytes.clone, ip)
        tcp.analyze

        result[:tcp] = tcp
      when Constants::Ip::UDP
        udp = HeaderAnalyzer::Udp.new(@msg_bytes.clone, ip)
        udp.analyze

        result[:udp] = udp
      else
      end

    else
      return
    end
    @logger.debug("--------------------------------------------")

    result
  end
end
