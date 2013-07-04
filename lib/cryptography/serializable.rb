require 'cryptography'
require 'protocol_buffers'

module Cryptography::Serializable
  module Context
    include ::ProtocolBuffers::Enum

    UNKNOWN = 0
    VAULT   = 10
  end

  module Primitive
    include ::ProtocolBuffers::Enum

    UNKNOWN = 0

    # Cryptography::KDF primitives
    PBKDF2 = 10
    HKDF   = 11

    # Sodium::Auth primitives
    HMACSHA256    = 100
    HMACSHA512256 = 101
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
        o.send :initialize!
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

#
#
#
#
#
#
#module Cryptography::Serializable
#  CONTEXTS = {
#    :vault => 1,
#  }
#
#  PRIMITIVES = {
#    :xsalsa20poly1305 => 1,
#  }
#
#  module ClassMethods
#    def version(version, &block)
#      self.serializer[version] = block
#    end
#
#    def serializer
#      @_serializer ||= Cryptography::Serializable::Serializer.new
#    end
#
#    def deserialize(hash)
#      version    = hash[:version]
#      serializer = self.serializer[version]
#      object     = self.allocate
#
#      object.extend(serializer.extension) if serializer.extension
#      object.send(:deserialize, hash)
#    end
#
#    def from_bytes(bytes)
#      self.deserialize(
#        self.serializer.from_bytes(bytes)
#      )
#    end
#
#    def from_hash(hash)
#      self.deserialize(
#        self.serializer.from_hash(hash)
#      )
#    end
#  end
#
#  def self.included(klass)
#    klass.extend ClassMethods
#  end
#
#  def to_bytes
#    self.class.serializer.to_bytes(self)
#  end
#
#  def to_hash
#    self.class.serializer.to_hash(self)
#  end
#
#  protected
#
#  attr_accessor :version
#
#  def deserialize(hash)
#    hash.each_pair {|field, value| self.send(:"#{field}=", value) }
#    self
#  end
#end
#
#module Cryptography::Serializable
#  class Serializer
#    def []=(version, block)
#      self.descriptors ||= []
#      self.descriptors[version] = Descriptor.new(version, &block)
#    end
#
#    def [](version)
#      self.descriptors ||= []
#      self.descriptors[version]
#    end
#
#    def from_bytes(bytes)
#      buffer     = Sodium::Buffer.new(bytes)
#      descriptor = self.descriptors.detect {|d| d.match?(buffer) }
#      offset     = 0
#
#      descriptor.inject({}) do |attributes, field|
#        value, offset = field.consume(buffer.to_str, offset)
#
#        attributes.update(field.name => value)
#      end
#    end
#
#    def from_hash(hash)
#      version    = hash[:version]
#      descriptor = self.descriptors[version]
#
#      descriptor.inject({}) do |attributes, field|
#        value = field.canonicalize hash[field.name]
#
#        attributes.update field.name => value
#      end
#    end
#
#    def to_bytes(serializable)
#      version    = serializable.send(:version)
#      descriptor = self.descriptors[version]
#      bytes      = Sodium::Buffer.new('')
#
#      descriptor.inject(bytes) do |string, field|
#        string + field.emit(serializable)
#      end
#    end
#
#    def to_hash(serializable)
#      version    = serializable.send(:version)
#      descriptor = self.descriptors[version]
#
#      descriptor.inject({}) do |hash, field|
#        hash.update field.name => field.fetch(serializable)
#      end
#    end
#
#    protected
#
#    attr_accessor :descriptors
#  end
#
#  class Descriptor
#    include Enumerable
#
#    attr_accessor :version
#    attr_accessor :extension
#
#    def initialize(version)
#      self.version = version
#      self.integer :version, 2
#
#      yield self
#    end
#
#    def enum(name, options, bytesize = 2)
#      self.fields << Field.new(name, options, :enum, bytesize)
#    end
#
#    def integer(name, bytesize = 4)
#      self.fields << Field.new(name, nil, :integer, bytesize)
#    end
#
#    def buffer(name, bytesize = 4)
#      self.fields << Field.new(name, nil, :buffer, bytesize)
#    end
#
#    def extend(&block)
#      self.extension = block
#    end
#
#    def each(&block)
#      self.fields.each(&block)
#    end
#
#    def match?(buffer)
#      self.fields.first.consume(buffer, 0).first == self.version
#    end
#
#    protected
#
#    def fields
#      @fields ||= []
#    end
#  end
#
#  class Field
#    attr_reader :name
#
#    def initialize(name, context, type, bytesize)
#      self.name     = name
#      self.context  = context
#      self.type     = type
#      self.bytesize = bytesize
#    end
#
#    def consume(buffer, offset)
#      case type
#        when :enum    then consume_enum    buffer, offset
#        when :integer then consume_integer buffer, offset
#        when :buffer  then consume_buffer  buffer, offset
#      end
#    end
#
#    def emit(serializable)
#      case type
#      when :enum    then emit_enum    self.fetch(serializable)
#      when :integer then emit_integer self.fetch(serializable)
#      when :buffer  then emit_buffer  self.fetch(serializable)
#      end
#    end
#
#    def canonicalize(value)
#      case type
#        when :enum    then canonicalize_enum    value
#        when :integer then canonicalize_integer value
#        when :buffer  then canonicalize_buffer  value
#      end
#    end
#
#    def fetch(serializable)
#      serializable.send(self.name)
#    end
#
#    protected
#
#    attr_writer   :name
#    attr_accessor :type
#    attr_accessor :context
#    attr_accessor :bytesize
#
#    private
#
#    def packer
#      case self.bytesize
#        when 1 then 'C>'
#        when 2 then 'S>'
#        when 4 then 'L>'
#        when 8 then 'Q>'
#        else
#          raise ArgumentError,
#            %{field bytesize may only be 1, 2, 4, or 8}
#      end
#    end
#
#    def consume_enum(buffer, offset)
#      bytes = buffer.byteslice(offset, self.bytesize)
#      value = bytes.to_str.unpack(packer).first
#
#      return canonicalize_enum(value), (offset + self.bytesize)
#    end
#
#    def consume_integer(buffer, offset)
#      bytes = buffer.byteslice(offset, self.bytesize)
#      value = bytes.to_str.unpack(packer).first
#
#      return canonicalize_integer(value), (offset + self.bytesize)
#    end
#
#    def consume_buffer(buffer, offset)
#      bytesize, offset = consume_integer(buffer, offset)
#      value            = buffer.byteslice(offset, bytesize)
#
#      return canonicalize_buffer(value), (offset + self.bytesize)
#    end
#
#    def emit_enum(value)
#      self.context.values_at(value).pack(packer)
#    end
#
#    def emit_integer(value)
#      [ value ].pack(packer)
#    end
#
#    def emit_buffer(value)
#      Sodium::Buffer.new(
#        [ value.bytesize ].pack(packer)
#      ) + value
#    end
#
#    def canonicalize_enum(value)
#      # fuck Ruby 1.8
#      key_for = self.context.respond_to?(:key) ? :key : :index
#
#      self.context.has_key?(value) ?
#        value : self.context.send(key_for, value)
#    end
#
#    def canonicalize_integer(value)
#      value.to_i
#    end
#
#    def canonicalize_buffer(value)
#      Sodium::Buffer.new(value)
#    end
#  end
#end
#
