# frozen_string_literal: true

require_relative "kit/custon_logger"
require_relative "kit/string"
require_relative "kit/struct"
require_relative "kit/packet_capture/packet_capture"
require_relative "kit/bridge/bridge"
require_relative "kit/router/router"

module RubyRouter
  include PacketCapture
  include Bridge
  include Router
end