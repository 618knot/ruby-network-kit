# frozen_string_literal: true

require_relative "router/custon_logger"
require_relative "router/string"
require_relative "router/packet_capture/packet_capture"

module RubyRouter
  include PacketCapture
end