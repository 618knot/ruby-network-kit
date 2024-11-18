# frozen_string_literal: true

# @note ref: https://github.com/kuredev/simple_capture/blob/main/lib/simple_capture/header/ehter_header.rb
#       ref: https://en.wikipedia.org/wiki/Ethernet_frame
#       ref: https://shinmeisha.co.jp/newsroom/2020/06/09/%E3%82%A4%E3%83%BC%E3%82%B5%E3%83%8D%E3%83%83%E3%83%88%E3%83%98%E3%83%83%E3%83%80%E3%81%AE%E3%83%95%E3%82%A9%E3%83%BC%E3%83%9E%E3%83%83%E3%83%88%E3%81%A8%E3%82%B5%E3%82%A4%E3%82%BA%E3%81%AE%E5%9F%BA/

require_relative "../../../constants"

# module PacketCapture
include Constants
class EtherHeader
  ETHERTYPE = {
    Constants::EtherTypes::PUP => "Xerox PUP",
    Constants::EtherTypes::IP => "IPv4",
    Constants::EtherTypes::ARP => "Address resolution",
    Constants::EtherTypes::REVARP => "Reverse ARP",
    Constants::EtherTypes::IPv6 => "IPv6",
  }

  attr_reader :dst_mac_address, :src_mac_address, :type

  #
  # @param [Array] msg_bytes
  #
  def initialize(msg_bytes)
    to_headers(msg_bytes)
  end

  #
  # ヘッダー情報を出力する
  #
  def print_headers
    logger = CustomLogger.new
    logger.info("■■■■■ Ether Header ■■■■■")
    logger.debug("dst_mac_address=> #{macaddr_to_s(dst_mac_address)}")
    logger.debug("src_mac_address=> #{macaddr_to_s(src_mac_address)}")
    logger.debug("type=> #{type_to_s(type)}")
  end

  private

  #
  # Ether Headerから必要な情報を取り出す
  # 
  # @param [Array] msg_bytes
  # 
  # @note variables
  #         @dst_mac_address 送信先MACアドレス
  #         @src_mac_address 送信元MACアドレス
  #         @type タイプ/長さ
  #
  def to_headers(msg_bytes)
    @dst_mac_address = msg_bytes.slice(0..5)
    @src_mac_address = msg_bytes.slice(6..11)
    @type = msg_bytes.slice(12..13)
  end

  #
  # MACアドレスを整形済み文字列にする
  #
  # @param [Array] mac_addr MACアドレスのbyte array
  #
  # @return [String] 整形済みMACアドレス
  #
  def macaddr_to_s(mac_addr)
    hex_macaddr = mac_addr.map { |addr| addr.to_s(16).rjust(2, "0") }
    hex_macaddr.join(":")
  end

  #
  # ETHERTYPE文字列にする
  #
  # @param [Array] type typeのbyte array
  #
  # @return [String or nil] ETHERTYPE文字列(該当するものがないときはnil)
  #
  def type_to_s(type)
    hex_type = type.map { |byte| byte.to_s(16).rjust(2, "0") }
    int_hex_type = hex_type.join.to_i(16)

    ETHERTYPE[int_hex_type]
  end
end
