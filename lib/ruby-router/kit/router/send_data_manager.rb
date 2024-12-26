# frozen_string_literal: true

require_relative "struct/base"
require_relative "../custon_logger"

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