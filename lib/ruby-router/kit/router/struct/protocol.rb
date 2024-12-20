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
    :option,
  ) do

    def copy_from_analyzed(ip)
      self.members.each do |attr|
        self.send("#{attr}=", ip.send(attr))
      end
    end

    def to_binary
      [
        pack_c((version << 4) | ihl),
        pack_c(tos),
        two_bytes(tot_len),
        two_bytes(id),
        two_bytes(frag_off),
        pack_c(ttl),
        pack_c(protocol),
        two_bytes(check),
        four_bytes(saddr),
        four_bytes(daddr),
      ].join
    end
  end

  ICMP = Struct.new(
    "Icmp",
    :type, # ICMP Type
    :code, # ICMP Code
    :check, # Checksum
    :void,
  ) do
    
    def to_binary
      [
        pack_c(type),
        pack_c(code),
        two_bytes(check),
        four_bytes(void),
      ].join
    end
  end

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

  private

  def two_bytes(v)
    [v].flatten.pack("S>")
  end

  def four_bytes(v)
    [v].flatten.pack("L>")
  end

  def pack_c(v)
    [v].flatten.pack("C*")
  end
end
