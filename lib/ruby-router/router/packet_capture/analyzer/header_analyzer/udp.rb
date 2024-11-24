# frozen_string_literal: true

module HeaderAnalyzer
  class Udp < Header
    def analyze
      @source = @msg_bytes.slice(0..1) # Source Port:      2Byte
      @dest = @msg_bytes.slice(2..3)   # Destination Port: 2Byte
      @len = @msg_bytes.slice(4..5)    # Data Length:      2Byte
      @check = @msg_bytes.slice(5..7)  # Check Sum:        2Byte

      @source = self.to_hex_int(@source)
      @dest = self.to_hex_int(@dest)
      @len = self.to_hex_int(@len)
      @check = self.to_hex_string(@check, is_formated: true)

      print_udp
    end

    private

    def print_udp
      @logger.info("■■■■■ TCP Header ■■■■■")

      msg = [
        "Source Port => #{@source}",
        "Destination Port => #{@dest}",
        "Data Length => #{@len}",
        "Check Sum => #{@check}",
      ]

      out_msg_array(msg)
    end
  end
end