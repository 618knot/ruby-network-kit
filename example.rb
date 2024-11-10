require_relative "lib/ruby-router/ruby-router"

# ping -I eth0 8.8.8.8  # Google DNS に対して ping
RubyRouter::Capture.new("eth0").run