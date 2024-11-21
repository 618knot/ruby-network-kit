# frozen_string_literal: true

module HeaderAnalyzer
  class Ip < Header
    attr_reader(
      :version,
      :ihl,
      :tos,
      :tot_len,
      :id,
      :frag_off,
      :ttl,
      :protocol,
      :check,
      :saddr,
      :daddr,
      :option
      )

    def analyze
      @version = @msg_bytes.slice(0)[4..7]                 # IPv4 version:        4bit
      @ihl = @msg_bytes.slice(0)[0..3]                     # Header length:       4bit
      @tos = @msg_bytes.slice(1)                           # Type of Service:     1Byte
      @tot_len = @msg_bytes.slice(2..3)                    # Total Length:        2Byte
      @id = @msg_bytes.slice(4..5)                         # Identifier:          2Byte
      @frag_off = @msg_bytes.slice(6..7)                   # Fragment Offset:     2Byte
      @ttl = @msg_bytes.slice(8)                           # Time to Live:        1Byte
      @protocol = @msg_bytes.slice(9)                      # Protocol:            1Byte
      @check = @msg_bytes.slice(10..11)                    # Checksum:            2Byte
      @saddr = @msg_bytes.slice(12..15).join(".")          # Source Address:      4Byte
      @daddr = @msg_bytes.slice(16..19).join(".")          # Destination Address: 4Byte
      @option = @ihl > 5 ? @msg_bytes.slice(20..@ihl) : [] # Option

      @tot_len = self.to_hex_int(@tot_len)
      @id = self.to_hex_int(@id)
      @frag_off = self.to_hex_int(@frag_off)
      @protocol = Constants::Ip::PROTO[@protocol]
      @check = self.to_hex_string(@check, is_formated: true)

      print_ip
    end

    private
    
    def print_ip
      @logger.info("■■■■■ IP Header ■■■■■")

      msg = [
        "Version => #{@version}",
        "Header Length => #{@ihl} (#{@ihl * 4} Byte)",
        "Type of Service => #{@tos}",
        "Total Length => #{@tot_len} Byte",
        "Identifier => #{@id}",
        "Flags => 0b#{(@frag_off & 0xe000).to_s(2).slice(0..2).rjust(3, "0")}",
        "Fragment offset => 0x#{(@frag_off & 0x1fff).to_s(16)}",
        "Time to Live => #{@ttl}",
        "Protocol => #{@protocol}",
        "Checksum => #{@check}",
        "Source Address => #{@saddr}",
        "Destination Address => #{@daddr}",
        "Option => #{@option}"
      ]

      out_msg_array(msg)
    end
  end
end
