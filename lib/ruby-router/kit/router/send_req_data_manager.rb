# frozen_string_literal: true

require "singleton"
require "thread"
require_relative "struct/base"
require_relative "struct/protocol"
require_relative "router_base"
require_relative "../packet_analyzer/packet_analyzer"
require_relative "net_util"
require_relative "ip2mac"

class SendReqDataManager
  include Singleton

  include NetUtil

  def initialize
    @queue = Queue.new
    @set = Set.new
    @mutex = Mutex.new
    @cond = ConditionVariable.new
    @end_flag = false
  end

  def append_send_req_data(device_no, ip2mac_no)
    arr = [device_no, ip2mac_no]

    @mutex.synchronize do
      return unless @set.add?(arr)

      @queue.push(arr)
    end
  end

  def get_send_req_data
    return if @queue.empty?

    req_data = nil

    @mutex.synchronize do
      req_data = @queue.pop
      @set.delete(req_data)
    end

    req_data
  end

  def buffer_send
    until @end_flag
      @mutex.synchronize do
        begin
          @cond.wait(@mutex, 1)
        rescue
        end
      end

      loop do
        req_data = get_send_req_data

        break if req_data.nil?

        buffer_send_one(*req_data)
      end
    end
  end

  def buffer_send_one(device_no, ip2mac_no)
    loop do
      ip2mac = Ip2MacManager.instance.ip2macs[device_no].data[ip2mac_no]
      data = ip2mac.send_data.get_send_data

      break if data.nil?

      analyzed_data = PacketAnalyzer.new(data.bytes).analyze
      analyzed_ether = analyzed_data[:ether]

      ether_bin = ETHER.new(
        dhost: ip2mac.hwaddr,
        shost: analyzed_ether.src_mac_address,
        type: analyzed_ether.type,
      ).to_binary

      ip_header = IP.new
      ip_header.copy_from_analyzed(analyzed_data[:ip])
      ip_header.ttl[0] -= 1
      ip_checksum_for_sending(ip_header.to_binary.bytes)
      ip_bin = ip_header.to_binary

      packet = ether_bin + ip_bin + data.slice(ether_bin.length + ip_bin.length..)

      socket = RouterBase.devices[device_no].socket
      socket.write(packet)
    end
  end

  def stop
    @end_flag = true
  end
end
