# frozen_string_literal: true

require_relative "router/custon_logger"
require_relative "router/string"
require_relative "router/packet_capture/packet_capture"
require_relative "router/bridge/bridge"

module RubyRouter
  include PacketCapture
  include Bridge
end