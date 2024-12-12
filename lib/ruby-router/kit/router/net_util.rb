# frozen_string_literal: true

require_relative "../constants"
require_relative "protocol_struct"
require "socket"

module NetUtil
  include ProtocolStruct
  include SocketUtils

  # def send_icmp_time_exceeded(if_socket, ether_header, ip_header)
  #   r_ether_header = ETHER.new(
  #     dhost: ether_header.dhost,
  #     shost: ether_header.shost,
  #     type: Constants::EtherTypes::IP,
  #   )

  #   r_iphdr = IP.new(
  #     version: 4,
  #     ihl: 20 / 4,
  #     tos: 0,
  #     tot_len: ,
  #     id: 0,
  #     frag_off: 0,
  #     ttl: 64,
  #     protocol: 1,
  #     check: 0,
  #     saddr: get_interface_ip(if_socket.first),
  #     daddr: ip_header.saddr,
  #   )
  # end

  def get_device_info(interface)
    result = {}
  
    Socket.getifaddrs.each { |iface|
      next unless iface.name == interface
      next if iface.addr.nil?
  
      if iface.addr.pfamily == Socket::AF_PACKET
        match = iface.addr.inspect_sockaddr.match(/hwaddr=([\h:]+)/)
        result[:mac_address] = match[0].delete("hwaddr=")
      end
  
      if iface.addr.ipv4?
        result[:ipv4_address] = iface.addr.ip_address
        result[:netmask] = iface.netmask.ip_address if iface.netmask
      end
  
      if result[:ipv4_address] && result[:netmask]
        result[:subnet] = calculate_subnet(result[:ipv4_address], result[:netmask])
      end
    }
  
    result
  end

  def send_arp_request(socket, s_mac, t_mac, s_ip, t_ip)
    s_mac_packed = s_mac.pack("C*")
    t_mac_packed = t_mac.pack("C*")
    s_ip_packed = s_ip.pack("C*")
    t_ip_packed = t_ip.pack("C*")

    ether_header = ETHER.new(
      dhost: t_mac_packed,
      shost: s_mac_packed,
      type: [0x0806].pack('S>'),
    ).to_packet

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
    ).to_packet

    packet = ether_header + arp

    socket.send(packet, 0)    
  end

  private

  def calculate_subnet(ip_address, netmask)
    ip = IPAddr.new(ip_address)
    mask = IPAddr.new(netmask).to_i.to_s(2).delete("0").length
  
    subnet = ip.mask(mask)
  
    subnet.to_s
  end
end