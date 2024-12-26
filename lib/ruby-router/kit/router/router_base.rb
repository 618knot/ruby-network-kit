# frozen_string_literal: true

require_relative "../socket_utils"
require_relative "../custon_logger"
require_relative "struct/base"
require "ipaddr"
require "socket"

class RouterBase
  include Base

  attr_reader :logger, :next_ip, :devices

  class << self
    attr_accessor :end_flag
    attr_reader :devices
  end

  def initialize(interface1, interface2, next_ip)
    @logger = CustomLogger.new
    @interface1 ||= interface1
    @interface2 ||= interface2
    @next_ip ||= next_ip
    @devices ||= get_device_info(@interface1, @interface2)
    @end_flag = false
  end

  private

  def get_device_info(*interfaces)
    devices = []

    interfaces.each do |interface|
      result = DEVICE.new(if_name: interface)

      Socket.getifaddrs.each do |iface|
        next unless iface.name == interface
        next if iface.addr.nil?
    
        if iface.addr.pfamily == Socket::AF_PACKET
          match = iface.addr.inspect_sockaddr.match(/hwaddr=([\h:]+)/)
          result.hwaddr = match[1]
        end
    
        if iface.addr.ipv4?
          result.addr = iface.addr.ip_address
          result.netmask = iface.netmask.ip_address if iface.netmask
        end
    
        if result.addr && result.netmask
          result.subnet = calculate_subnet(result.addr, result.netmask)
        end
      end

      result.socket = init_socket(interface)
      devices << result
    end

    devices
  end

  def init_socket(interface)
    socket = generate_raw_socekt
    bind_interface(socket, interface)
    socket
  end
end
