# frozen_string_literal: true

require_relative "../constants"
require_relative "./struct/protocol"
require "socket"

module NetUtil
  include Protocol
  include SocketUtils

  def send_arp_request(socket, s_mac, t_mac, s_ip, t_ip)
    s_mac_packed = s_mac.pack("C*")
    t_mac_packed = t_mac.pack("C*")
    s_ip_packed = s_ip.pack("C*")
    t_ip_packed = t_ip.pack("C*")

    ether_header = ETHER.new(
      dhost: t_mac_packed,
      shost: s_mac_packed,
      type: [0x0806].pack("S>"),
    ).to_binary

    packed_arp_header = [0x0001, 0x0800, 6, 4, 0x0001].pack("S>S>CCS>")

    arp = ARP.new(
      hrd: packed_arp_header.slice(0..1),
      pro: packed_arp_header.slice(2..3),
      hln: packed_arp_header[4],
      pln: packed_arp_header[5],
      op: packed_arp_header.slice(6..),
      sha: s_mac_packed,
      spa: s_ip_packed,
      tha: t_mac_packed,
      tpa: t_ip_packed,
    ).to_binary

    packet = ether_header + arp

    socket.write(packet)
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

  private

  def calculate_subnet(ip_address, netmask)
    ip = IPAddr.new(ip_address)
    mask = IPAddr.new(netmask).to_i.to_s(2).delete("0").length
  
    subnet = ip.mask(mask)
  
    subnet.to_s
  end
end