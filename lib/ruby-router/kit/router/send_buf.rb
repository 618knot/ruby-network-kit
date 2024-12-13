# frozen_string_literal: true

require_relative "struct/base"

module SendBuf
  include Base
  MUX_BUCKET_SIZE = 1024 * 1024

  def append_send_data(ip2mac, device_no, addr, data, size)
    send_data = ip2mac.send_data

    return if send_data.in_bucket_size > MUX_BUCKET_SIZE

    new_buf = DATA_BUF.new(
      next: nil,
      before: nil,
      time: Time.now,
      size: size,
      data: data,
    )

    send_data.mutex.synchronize do
      if send_data.buttom.nil?
        send_data.top = send_data.buttom = new_buf
      else
        send_data.buttom.next = new_buf
        new_buf.before = send_data.buttom
        send_data.buttom = new_buf
      end

      send_data.dno += 1
      send_data.in_bucket_size += size
    end

    send_data
  end

  def get_send_data(ip2mac, size, data)
    send_data = ip2mac.send_data

    return if send_data.top.nil?

    d = nil

    send_data.mutex.synchronize do
      d = send_data.top
      send_data.top = d.next

      if send_data.top.nil?
        send_data.bottom = nil
      else
        send_data.top.before = nil?
      end

      send_data.dno -= 1
      send_data.in_bucket_size -= d.size
    end

    {
      :size => d.size,
      :data => d.data,
    }
  end

  def free_send_data(ip2mac)
    send_data = ip2mac.send_data

    return if send_data.top.nil?

    send_data.mutex.synchronize do
      current = send_data.top

      while current
        next_buf = current.next
        current.data.clear
        current = next_buf
      end

      send_data.top = send_data.buttom = nil
    end
  end
end