# frozen_string_literal: true

module Protocol
  ETHER = Struct.new(
    "Ether",
    :dhost, # Destination MAC address
    :shost, # Source MAC address
    :type,  # Protocol type
    )

  IP = Struct.new(
    "Ip",
    :version,  # IPv4 version
    :ihl,      # Header length
    :tos,      # Type of Service
    :tot_len,  # Total Length
    :id,       # Identifier
    :frag_off, # Fragment Offset
    :ttl,      # Time to Live
    :protocol, # Protocol
    :check,    # Checksum
    :saddr,    # Source Address
    :daddr,    # Destination Address
  )

  ICMP = Struct.new(
    "Icmp",
    :type, # ICMP Type
    :code, # ICMP Code
    :check, # Checksum
    :void,
  )

  ARP = Struct.new(
    "Arp",
    :hrd, # Hardware Type
    :pro, # Protocol Type
    :hln, # Hardware Size
    :pln, # Protocol Size
    :op,  # Opcode
    :sha, # Sender MAC address
    :spa, # Sender IP address
    :tha, # Target MAC address
    :tpa, # Target IP address
  )
end
