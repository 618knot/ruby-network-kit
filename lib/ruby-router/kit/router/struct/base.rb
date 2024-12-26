# frozen_string_literal: true

require_relative "../send_data_manager"

module Base
  DEVICE = Struct.new(
    "Device",
    :if_name,
    :socket,
    :hwaddr,
    :addr,
    :subnet,
    :netmask,
  )

  DATA_BUF = Struct.new(
    "DataBuf",
    :time,
    :size,
    :data,
  )

  class IP2MAC
    attr_accessor :flag, :device_no, :addr, :hwaddr, :last_time, :send_data

    def initialize(device_no, addr, hwaddr)
      @flag = hwaddr ? :ok : :ng
      @device_no = device_no
      @addr = addr
      @hwaddr = hwaddr || [0, 0, 0, 0, 0, 0]
      @last_time = Time.now
      @send_data = SendDataManager.new
    end
  end
end
