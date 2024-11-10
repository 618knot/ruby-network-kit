# frozen_string_literal: true

class String
  #
  # ANSIエスケープシーケンスする
  #
  # @param [Integer] str_code 文字列のカラーコード
  # @param [Integer] bg_code 背景色のカラーコード(default: nil)
  #
  # @return [String] ANSIエスケープシーケンスされた文字列
  #
  def ansi_color(str_code, bg_code: nil)
    return "\e[#{str_code}m#{self}\e[0m" if bg_code.nil?
    "\e[#{str_code}m\e[#{bg_code}m#{self}\e[0m"
  end

  def danger
    ansi_color(41)
  end

  def danger_bg
    ansi_color(37, 41)
  end

  def warn
    ansi_color(33)
  end

  def warn_bg
    ansi_color(30, 43)
  end

  def info
    ansi_color(34)
  end

  def info_bg
    ansi_color(37, 44)
  end

  def safe
    ansi_color(32)
  end

  def safe_bg
    ansi_color(30, 42)
  end
end
