require 'cryptography'
require 'protocol_buffers'

module Cryptography::Serializable
  module Enum
    def self.included(base)
      base.send :include, ::ProtocolBuffers::Enum
      base.send :extend,  self
    end

    def [](key)
      self.values.include?(key.to_sym)  ?
        self.const_get(key.to_s.upcase) :
        nil
    end

    def values
      self.constants.map(&:to_s).map(&:downcase).map(&:to_sym)
    end
  end

  module Context
    include Enum

    UNKNOWN = 0
    VAULT   = 10
  end

  module Primitive
    include Enum

    UNKNOWN = 0

    # Cryptography::KDF primitives
    PBKDF2 = 10
    HKDF   = 11

    # Sodium::Auth primitives
    HMACSHA256    = 1000
    HMACSHA512256 = 1001

    # Sodium::SecretBox primitives
    XSALSA20POLY1305 = 1100
  end

  module ClassMethods
    def from_s(string)
      self.from_sodium_buffer Sodium::Buffer.new(string)
    end

    protected

    def from_hash(hash)
      self.deserialize(hash)
    end

    def from_sodium_buffer(buffer)
      # FIXME: don't dup
      self.from_protocol_buffer self.serializer.parse(buffer.to_str.dup)
    end

    def from_protocol_buffer(buffer)
      self.from_hash buffer.fields.values.inject({}) { |attributes, field|
        next attributes unless buffer.send(:"has_#{field.name}?")

        value = buffer.send(field.name)
        value = case field
          # wrap byte buffers in a Sodium::Buffer ASAP for safety
          when ProtocolBuffers::Field::BytesField
            Sodium::Buffer.new(value)

          # convert enums to their symbolic representation
          when ProtocolBuffers::Field::EnumField
            field.value_to_name[value].downcase.to_sym

          else
            value
        end

        attributes[field.name] = value
        attributes
      }
    end

    def deserialize(attributes)
      self.allocate.tap do |o|
        o.send :attributes=, attributes
        o.send :on_initialize!
      end
    end

    def serialize(&block)
      @_serializer = Class.new(ProtocolBuffers::Message, &block)
    end

    def serializer
      @_serializer
    end
  end

  def self.included(base)
    base.extend(ClassMethods)
  end

  def to_s
    self.to_sodium_buffer.to_str
  end

  protected

  attr_accessor :attributes

  def serializer
    self.class.send(:serializer)
  end

  def to_hash
    self.send(:attributes)
  end

  def to_sodium_buffer
    Sodium::Buffer.new(self.to_protocol_buffer.serialize_to_string)
  end

  def to_protocol_buffer
    self.send(:on_serialize!)

    attributes = self.to_hash
    hash       = {}

    self.serializer.fields.values.each do |field|
      next unless attributes.has_key?(field.name)

      value = attributes[field.name]
      value = case field
        # convert byte buffers into strings from Sodium::Buffers
        when ProtocolBuffers::Field::BytesField
          value.to_str

        # convert enums from their symbolic representation
        when ProtocolBuffers::Field::EnumField
          field.value_to_name.key value.to_s.upcase

        else
          value
      end

      hash[field.name] = value
      hash
    end

    self.serializer.new(hash)
  end
end
