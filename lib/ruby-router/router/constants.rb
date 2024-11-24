module Constants
  module EtherTypes
    # @note net/ethernet.h
    PUP = 0x0200.freeze # Xerox PUP
    IP = 0x0800.freeze # IPv4
    ARP = 0x0806.freeze # Address resolution
    REVARP = 0x8035.freeze # Reverse ARP
    IPv6 = 0x86dd.freeze # IPv6

    STR_HASH = {
      PUP => "Xerox PUP",
      IP => "IPv4",
      ARP => "Address resolution",
      REVARP => "Reverse ARP",
      IPv6 => "IPv6",
  }.freeze
  end

  module Ip
    PROTO = [
      nil,
      "ICMP",
      "IGMP",
      nil,
      "IPIP",
      nil,
      "TCP",
      nil,
      "EGP",
      nil,
      nil,
      nil,
      "PUP",
      nil,
      nil,
      nil,
      nil,
      "UDP"
  ].freeze
  end

  module Icmp
    TYPE = [
      "Echo Reply",
      nil,
      nil,
      "Destination Unreachable",
      "Source Quench",
      "Redirect",
      nil,
      nil,
      "Echo Request",
      "Router Adverisement",
      "Router Selection",
      "Time Exceeded for Datagram",
      "Parameter Problem for Datagram",
      "Timestamp Request",
      "Timestamp Reply",
      "Information Request",
      "Information Reply",
      "Address Mask Request",
      "Address Mask Reply"
  ].freeze
  end
end