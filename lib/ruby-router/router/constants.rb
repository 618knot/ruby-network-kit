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
end