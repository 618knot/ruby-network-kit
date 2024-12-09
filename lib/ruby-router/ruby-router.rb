# frozen_string_literal: true

require_relative "kit/custon_logger"
require_relative "kit/string"
require_relative "kit/packet_capture/packet_capture"
require_relative "kit/bridge/bridge"

module RubyRouter
  include PacketCapture
  include Bridge
end