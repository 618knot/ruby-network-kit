# frozen_string_literal: true

require "logger"

class CustomLogger

  #
  # @param [String or Class] mode outputのモード
  #
  def initialize(mode: nil)
    @logger = Logger.new(
      mode.nil? ? STDOUT : mode
    )
  end

  def debug(str)
    @logger.debug(str)
  end

  def info(str)
    @logger.info(str.info)
  end

  def warn(str)
    @logger.warn(str.warn)
  end

  def fatal(str)
    @logger.fatal(str.danger)
  end
end
