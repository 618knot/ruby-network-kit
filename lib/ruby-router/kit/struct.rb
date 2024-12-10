# frozen_string_literal: true

class Struct
  def to_packet
    self.to_a.flatten.join
  end
end
