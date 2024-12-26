# frozen_string_literal: true

require_relative "struct/protocol"
require_relative "send_data_manager"
require_relative "send_req_data_manager"
require_relative "router_base"
require "singleton"

class IP2MacTable
  attr_accessor :data, :size, :no

  def initialize
    @data = []
    @size = 0
    @no = 0
  end
end 

class Ip2MacManager
  include Singleton

  attr_accessor :ip2macs

  IP2MAC_TIMEOUT_SEC = 60.freeze
  IP2MAC_TIMEOUT_NG_SEC = 1.freeze

  def initialize
    @ip2macs = [IP2MacTable.new, IP2MacTable.new]
  end

  def ip_to_mac(device_no, addr, hwaddr)
    ip2mac = ip2mac_search(device_no, addr, hwaddr)

    if ip2mac.flag == :ok
      return ip2mac
    else
      device = RouterBase.devices[device_no]
      send_arp_request(device.socket, addr, [0xff] * 6, device.addr.split(".").map(&:to_i), device.hwaddr.split(":").map(&:to_i))
      return ip2mac
    end
  end

  private

  def ip2mac_search(device_no, addr, hwaddr)
    now = Time.now
    free_no = nil
    no = nil
    ip2mac_table = @ip2macs[device_no]

    ip2mac_table.data.each_with_index do |ip2mac, i|
      if ip2mac.flag == :free
        free_no ||= i
        next
      end

      if ip2mac.addr == addr
        ip2mac.last_time = now if ip2mac.flag == :ok

        if hwaddr.present?
          ip2mac.hwaddr = hwaddr
          ip2mac.flag = :ok

          SendReqDataManager.instance.append_send_req_data(device_no, i) if ip2mac.send_data.top.present?

          return ip2mac
        elsif can_clear_data?(ip2mac, now)
          ip2mac.send_data.clear
          ip2mac.flag = :free

          free_no ||= i
        else
          return ip2mac
        end
      elsif can_clear_data?(ip2mac, now)
        ip2mac.send_data.clear
        ip2mac.flag = :free

        free_no ||= i
      end
    end

    if free_no.nil?
      no = ip2mac_table.no

      if no >= ip2mac_table.size
        ip2mac_table.size += 1024
      end

      ip2mac_table.no += 1
    else
      no = free_no
    end

    new_ip2mac = IP2MAC.new(device_no, addr, hwaddr)
    ip2mac_table.data[no] = new_ip2mac

    new_ip2mac
  end

  def can_clear_data?(ip2mac, now)
    is_ok_flg_timed_out = ip2mac.flag == :ok && now - ip2mac.last_time > IP2MAC_TIMEOUT_SEC
    is_ng_flg_timed_out = ip2mac.flag == :ng && now - ip2mac.last_time > IP2MAC_TIMEOUT_NG_SEC

    is_ok_flg_timed_out || is_ng_flg_timed_out
  end
end
