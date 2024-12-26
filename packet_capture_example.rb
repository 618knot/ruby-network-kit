require_relative "lib/ruby-router/ruby-router"

RubyRouter::PacketCapture.new("eth0").run
