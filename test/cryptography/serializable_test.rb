require 'test_helper'

describe Cryptography::Serializable do
  def self.protocol_buffer_enum_value(type, name, value)
    enum  = Cryptography::Serializable.const_get(type.to_s.capitalize)
    const = name.to_s.upcase

    it "must never change the value of the #{name} #{type}" do
      enum.const_get(const).must_equal value
    end
  end

  protocol_buffer_enum_value :context, :unknown,                0
  protocol_buffer_enum_value :context, :authenticated_message, 10

  protocol_buffer_enum_value :primitive, :unknown,             0
  protocol_buffer_enum_value :primitive, :pbkdf2,             10
  protocol_buffer_enum_value :primitive, :hkdf,               11
  protocol_buffer_enum_value :primitive, :hmacsha256,       1000
  protocol_buffer_enum_value :primitive, :hmacsha512256,    1001
  protocol_buffer_enum_value :primitive, :xsalsa20poly1305, 1100
end
