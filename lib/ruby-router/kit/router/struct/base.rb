# frozen_string_literal: true

module Base
  DEVICE = Struct.new(
    "Device",
    :hwaddr,
    :addr,
    :subnet,
    :netmask,
  )

  DATA_BUF = Struct.new(
    "DataBuf",
    :next,
    :before,
    :time,
    :size,
    :data,
  )

  SEND_DATA = Struct.new(
    "SendData",
    :top,
    :bottom,
    :dno,
    :in_bucket_size,
    :mutex,
  )

  IP2MAC = Struct.new(
    "Ip2mac",
    :flag,
    :device_no,
    :addr,
    :hwaddr,
    :last_time,
    :send_data,
  )
end