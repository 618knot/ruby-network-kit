class Protocol

  #
  # @param [Array] msg_bytes
  #
  def initialize(msg_bytes)
    @msg_bytes = msg_bytes
    @logger ||= CustomLogger.new
  end

  def analyze
    # 子クラスでoverrideする
  end

  protected

  #
  # Int Arrayを16進数文字列にする
  #
  # @param [Array] array
  #
  # @return [String]
  #
  def to_hex_string(array)
    str = "0x"
    array.map!{ |e| str << e.to_s(16).rjust(2, "0") }
  end

  def to_hex_int(array)
    str = ""
    array.map!{ |e| str << e.to_s(16).rjust(2, "0") }
    str.to_i(16)
  end

  #
  # MACアドレスを整形済み文字列にする
  #
  # @param [Array] mac_addr MACアドレスのbyte array
  #
  # @return [String] 整形済みMACアドレス
  #
  def macaddr_to_s(mac_addr)
    mac_addr.map { |addr| addr.to_s(16).rjust(2, "0") }.join(":")
  end
end
