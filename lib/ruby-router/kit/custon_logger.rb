# frozen_string_literal: true

require "logger"

class CustomLogger

  #
  # @param [String or Class] mode outputのモード
  #
  def initialize(mode: nil, is_disabled: false)
    # @logger = Logger.new(
    #   mode.nil? ? STDOUT : mode
    # )
    @logger = Logger.new("dbg.log")
    @is_disabled = is_disabled
  end

  def debug(str)
    @logger.debug(str) unless @is_disabled
  end

  def info(str)
    @logger.info(str.info) unless @is_disabled
  end

  def warn(str)
    @logger.warn(str.warn) unless @is_disabled
  end

  def fatal(str)
    @logger.fatal(str.danger) unless @is_disabled
  end
end
