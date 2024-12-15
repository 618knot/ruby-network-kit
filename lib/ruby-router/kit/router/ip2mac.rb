# frozen_string_literal: true

require_relative "protocol_struct"
require_relative "send_buf"

module Ip2Mac
  include SocketUtils
  include SendBuf

  IP2MAC_TIMEOUT_SEC = 60.freeze
  IP2MAC_TIMEOUT_NG_SEC = 1.freeze

  ETHER_HEADER_SIZE = 14.freeze
  IP_HEADER_BASE_SIZE = 20.freeze

  class IP2MacTable
    attr_accessor :data, :size, :no

    def initialize
      @data = []
      @size = 1024
      @no = 0
    end
  end

  $ip2macs = [IP2MacTable.new, IP2MacTable.new]

  def ip2mac_search(device_no, addr, hwaddr)
    now = Time.now
    free_no = nil

    $ip2macs[device_no].data.each_with_index do |ip2mac, i|
      if ip2mac.flag == :free
        free_no ||= i
        next
      end

      if ip2mac.addr == addr
        ip2mac.last_time = now if ip2mac.flag == :ok

        if hwaddr.present?
          ip2mac.hwaddr = hwaddr
          ip2mac.flag = :ok

          append_send_data(device_no, i) if ip2mac.send_data.top.present?

          return ip2mac
        elsif can_free_send?(ip2mac, now)
          free_send_data(ip2mac)
          ip2mac.flag = :free

          free_no ||= i
        else
          return ip2mac
        end
      else
        if can_free_send?(ip2mac, now)
          free_send_data(ip2mac)
          ip2mac.flag = :free

          free_no ||= i
        end
      end
    end

    new_ip2mac = IP2MAC.new(device_no, addr, hwaddr)

    if free_no.nil?
      $ip2macs[device_no].data[free_no] = new_ip2mac
    else
      $ip2macs[device_no].data << new_entry
    end
  end

  def ip_to_mac(device_no, addr, hwaddr)
    ip2mac = ip2mac_search(device_no, addr, hwaddr)

    if ip2mac.flag == :ok
      return ip2mac
    else
      # send_arp_request()
      return ip2mac
    end
  end

  def buffer_send_one
    loop do
      send_data_hash = get_send_data
      break if send_data_hash.values.compact.empty?
      
      ptr = send_data_hash[:data].clone
      eth

    end
  end

  def append_send_req_data
    
  end

  def get_send_req_data
    
  end

  def buffer_send
    
    loop do
      # break if get_send_req_data
      
      # buffer_send_one
    end
  end

  private

  def can_free_send?(ip2mac, now)
    is_ok_flg_timed_out = ip2mac.flag == :ok && now - ip2mac.last_time > IP2MAC_TIMEOUT_SEC
    is_ng_flg_timed_out = ip2mac.flag == :ng && now - ip2mac.last_time > IP2MAC_TIMEOUT_NG_SEC

    is_ok_flg_timed_out || is_ng_flg_timed_out
  end
end
