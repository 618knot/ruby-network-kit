class BaseAnalyzer

  #
  # @param [Array] msg_bytes
  #
  def initialize(msg_bytes, disable_log: false)
    @msg_bytes = msg_bytes
    @logger ||= CustomLogger.new(is_disabled: disable_log)
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
  def to_hex_string(array, is_formated: false)
    str = is_formated ? "0x" : ""
    array.map{ |e| str << e.to_s(16).rjust(2, "0") }
    str
  end

  #
  # Int Arrayを16進数値(10進数)に直す
  #
  # @param [Array] array
  #
  # @return [Integer]
  #
  def to_hex_int(array)
    str = ""
    array.map{ |e| str << e.to_s(16).rjust(2, "0") }
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

  #
  # 配列に格納されたメッセージをデバッガに出力する
  #
  # @param [Array] msg 出力する文字列を持つ配列
  #
  def out_msg_array(msg)
    msg.map { |m| @logger.debug(m) }
  end

  #
  # checksumを計算する
  #
  # @param [Array] data header
  #
  # @return [Array] bytes
  #
  def checksum(data)
    sum = 0

    data.each_slice(2) do |b|
      sum += (b.first << 8) + b.last
    end

    while sum > 0xffff
      sum = (sum & 0xffff) + (sum >> 16)
    end

    ~sum & 0xffff
  end

  def valid_checksum?(c)
    c == 0 || c == 0xffff
  end

  #
  # 疑似IPヘッダ
  #
  # @param [Array] len IP以下のパケット長(長さ2の配列)
  #
  # @return [Array] 疑似IPヘッダ
  #
  def pseudo_hddr(len)
    [
      @ip.saddr,    # Source Address:      4Byte
      @ip.daddr,    # Destination Address: 4Byte
      0,            # Reserved Division:   1Byte
      @ip.protocol, # Protocol:            1Byte
      len           # TCP/UDP Length:      2Byte
    ].flatten
  end
end
