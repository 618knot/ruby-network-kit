# frozen_string_literal: true

require_relative "router/custon_logger"
require_relative "router/string"
require_relative "router/packet_capture/packet_capture"
require_relative "router/packet_capture/analyzer/packet_analyzer"
require_relative "router/packet_capture/analyzer/header/ether_header"

module RubyRouter
  include PacketCapture
end