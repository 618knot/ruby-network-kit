# frozen_string_literal: true

require_relative "protocol"

module ProtocolAnalyzer
  class Arp < Protocol
    HRD = [
      "From KA9Q: NET/ROM pseudo.",
      "Ethernet 10/100Mbps.",
      "Experimental Ethernet.",
      "AX.25 Level 2.",
      "PROnet token ring.",
      "Chaosnet.",
      "IEEE 802. Ethernet/TR/TB.",
      "ARCnet.",
      "APPLEtalk",
      nil,
      nil,
      nil,
      nil,
      nil,
      nil,
      "Frame Relay DLCI.",
      nil,
      nil,
      nil,
      "ATM.",
      nil,
      nil,
      nil,
      "Metricom STRIP (new IANA id)."
    ].freeze

    OP = [
      nil,
      "ARP request.",
      "ARP reply.",
      "RARP request.",
      "RARP reply.",
      nil,
      nil,
      nil,
      "InARP request.",
      "InARP reply.",
      "(ATM)ARP NAK."
    ].freeze

    attr_reader(
      :arp_hrd,
      :arp_pro,
      :arp_hln,
      :arp_pln,
      :arp_op,
      :arp_sha,
      :arp_spa,
      :arp_tha,
      :arp_tpa
      )

    def analyze
      @arp_hrd = @msg_bytes.slice(0..1)    # Hardware Type:      2Byte
      @arp_pro = @msg_bytes.slice(2..3)    # Protocol Type:      2Byte
      @arp_hln = @msg_bytes.slice(4)       # Hardware Size:      1Byte
      @arp_pln = @msg_bytes.slice(5)       # Protocol Size:      1Byte
      @arp_op = @msg_bytes.slice(6..7)     # Opcode:             2Byte
      @arp_sha = @msg_bytes.slice(8..13)   # Sender MAC address: 6Byte
      @arp_spa = @msg_bytes.slice(14..17)  # Sender IP address:  4Byte
      @arp_tha = @msg_bytes.slice(18..23)  # Target MAC address: 6Byte
      @arp_tpa = @msg_bytes.slice(24..27)  # Target IP address:  4Byte

      print_arp
    end

    private

    def print_arp
      @logger.info("■■■■■ ARP ■■■■■")

      msg = [
        "Hardware Type => #{HRD[self.to_hex_int(@arp_hrd)]}",
        "Protocol Type => #{Constants::EtherTypes::STR_HASH[self.to_hex_int(@arp_pro)]}",
        "Hardware Size => #{@arp_hln} Byte",
        "Protocol Size => #{@arp_pln} Byte",
        "Opcode => #{OP[self.to_hex_int(@arp_op)]}",
        "Sender MAC address => #{macaddr_to_s(@arp_sha)}",
        "Sender IP address => #{@arp_spa.join(".")}",
        "Target MAC address => #{macaddr_to_s(@arp_tha)}",
        "Target IP address => #{@arp_tpa.join(".")}"
      ]

      msg.map { |m| @logger.debug(m) }
    end
  end
end
