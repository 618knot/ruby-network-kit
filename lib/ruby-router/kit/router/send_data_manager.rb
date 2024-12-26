# frozen_string_literal: true

require_relative "struct/base"
require_relative "../custon_logger"

# module SendDataManager
#   include Base
#   MAX_BUCKET_SIZE = 1024 * 1024

#   def append_send_data(ip2mac, device_no, addr, data, size)
#     send_data = ip2mac.send_data

#     return if send_data.in_bucket_size > MAX_BUCKET_SIZE

#     new_buf = DATA_BUF.new(
#       next: nil,
#       prev: nil,
#       time: Time.now,
#       size: size,
#       data: data,
#     )

#     send_data.mutex.synchronize do
#       if send_data.bottom.nil?
#         send_data.top = send_data.bottom = new_buf
#       else
#         send_data.bottom.next = new_buf
#         new_buf.prev = send_data.bottom
#         send_data.bottom = new_buf
#       end

#       send_data.dno += 1
#       send_data.in_bucket_size += size
#     end

#     send_data
#   end

#   def get_send_data(ip2mac, size, data)
#     send_data = ip2mac.send_data

#     return if send_data.top.nil?

#     d = nil

#     send_data.mutex.synchronize do
#       d = send_data.top
#       send_data.top = d.next

#       if send_data.top.nil?
#         send_data.bottom = nil
#       else
#         send_data.top.prev = nil
#       end

#       send_data.dno -= 1
#       send_data.in_bucket_size -= d.size
#     end

#     send_data
#   end

#   def ip2mac.send_data.clear
#     send_data = ip2mac.send_data

#     return if send_data.top.nil?

#     send_data.mutex.synchronize do
#       current = send_data.top

#       while current
#         next_buf = current.next
#         current.data = nil
#         current = next_buf
#       end

#       send_data.top = send_data.bottom = nil
#     end
#   end
# end

class SendDataManager

  MAX_BUCKET_SIZE = (1024 * 1024).freeze

  def initialize
    @queue = Queue.new
    @in_bucket_size = 0
    @mutex = Mutex.new
    @logger = CustomLogger.new
  end

  def append_send_data(addr, data, size)
    @mutex.synchronize do
      return if @in_bucket_size > MAX_BUCKET_SIZE

      new_buf = DATA_BUF.new(
        time: Time.now,
        data: data,
      )

      @queue.push(new_buf)
      @in_bucket_size += size
    end
  end

  def get_send_data
    return if @queue.empty?

    send_data = nil

    @mutex.synchronize do
      send_data = @queue.pop
      @in_bucket_size -= send_data.size
    end
  end

  def clear
    @mutex.synchronize do
      @queue.clear
      @in_bucket_size = 0
    end
  end
end