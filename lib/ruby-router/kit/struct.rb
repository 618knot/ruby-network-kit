# frozen_string_literal: true

class Struct
  def to_binary
    self.to_a.flatten.join
  end
end
