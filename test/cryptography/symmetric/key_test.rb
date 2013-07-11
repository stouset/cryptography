require 'test_helper'

describe Cryptography::Symmetric::Key do
  let(:klass)     { Cryptography::Symmetric::Key }
  let(:size)      { 32 }
  let(:context)   { :vault }
  let(:primitive) { :xsalsa20poly1305 }

  def self.protocol_buffer_enum_value(type, name, value)
    enum  = Cryptography::Serializable.const_get(type.to_s.capitalize)
    const = name.to_s.upcase

    it "must never change the value of the #{name} #{type}" do
      enum.const_get(const).must_equal value
    end
  end

  def self.protocol_buffer_key_test_vector(context, primitive, *args)
    # ensure the input string is converted to binary encoding
    string   = args.pop
    key      = Sodium::Buffer.new(args.pop)
    password = args.pop

    it "must never break backwards compatibility with the serialization format" do
      self.klass.from_s(string).bytes(context, primitive) do |bytes|
        bytes.to_str.must_equal key.to_str
      end if password.nil?

      self.klass.from_s(string).unlock(password) do |unlocked|
        unlocked.bytes(context, primitive) do |bytes|
          bytes.to_str.must_equal key.to_str
        end
      end unless password.nil?
    end
  end

  protocol_buffer_enum_value :context, :unknown,  0
  protocol_buffer_enum_value :context, :vault,   10

  protocol_buffer_enum_value :primitive, :unknown,             0
  protocol_buffer_enum_value :primitive, :pbkdf2,             10
  protocol_buffer_enum_value :primitive, :hkdf,               11
  protocol_buffer_enum_value :primitive, :hmacsha256,       1000
  protocol_buffer_enum_value :primitive, :hmacsha512256,    1001
  protocol_buffer_enum_value :primitive, :xsalsa20poly1305, 1100

  protocol_buffer_key_test_vector :unknown, :unknown,
    "*",
    "\x00\x00\b\x00\x12\x01*"

  protocol_buffer_key_test_vector :vault, :xsalsa20poly1305,
    "\xB5\x9D\x8D\xAC\xD6@)n\xCEy\xC8\xB3|\x04\xCF?[\x17\fyP\xD7!\x9F)\x1F\xD2i\x10\x93I\xAA",
    "\x00\n\b\xCC\b\x12 \xB5\x9D\x8D\xAC\xD6@)n\xCEy\xC8\xB3|\x04\xCF?[\x17\fyP\xD7!\x9F)\x1F\xD2i\x10\x93I\xAA"

  protocol_buffer_key_test_vector :vault, :xsalsa20poly1305, 'password',
    "\x0E\xCA\x11\xEF!v\xD7\x8AF7_\x80\x86\xA4\x93 ",
    "\x00\n\b\xCC\b\x12\x10\xA3b\xDC\x13\xE1\x03B\x12\x7F\xBE\xCA\xAE\x9C\x96D\xF7P\x01X\n`\xE9\ah\xD6\xD3\x02r\x10\xAA\xAF\xBB@\x16#\x88\x10++\xF3#\xCA\xF4\xA0\xCB"

  describe 'without a password' do
    subject { self.klass.new(self.context, self.primitive, self.size) }

    it 'must require a valid context, primitive, and size' do
      self.klass.new(self.context, self.primitive, self.size).
          must_be_kind_of self.klass
      end

    it 'must not allow unknown contexts' do
      lambda { self.klass.new(:wat, self.primitive, self.size) }.
        must_raise ArgumentError
    end

    it 'must not allow unknown primitives' do
      lambda { self.klass.new(self.context, :wat, self.size) }.
        must_raise ArgumentError
    end

    it 'must not allow invalid sizes' do
      lambda { self.klass.new(self.context, self.primitive, 0) }.
        must_raise ArgumentError

      lambda { self.klass.new(self.context, self.primitive, -1) }.
        must_raise ArgumentError
    end

    it 'must allow access to its bytes' do
      self.subject.bytes(self.context, self.primitive) do |bytes|
        bytes.must_be_kind_of Sodium::Buffer
        bytes.bytesize.must_equal self.size
      end
    end

    it 'must never create duplicate keys' do
      key1 = self.subject
      key2 = self.klass.new(self.context, self.primitive, self.size)

      key1.bytes(self.context, self.primitive) do |bytes1|
        key2.bytes(self.context, self.primitive) do |bytes2|
          bytes1.to_str.wont_equal bytes2.to_str
        end
      end
    end

    it 'must use a random source of data for key generation' do
      Sodium::Buffer.stub(:key, "\0" * 32) do
        self.subject.bytes(self.context, self.primitive) do |bytes|
          bytes.to_str.must_equal "\0" * 32
        end
      end
    end

    it 'must not be unlockable' do
      lambda { self.subject.unlock('password') }.
        must_raise ArgumentError
    end

    it 'must serialize to a protocol buffer' do
      key = self.klass.from_s(self.subject.to_s)
      key.must_be_kind_of self.klass

      self.subject.bytes(self.context, self.primitive) do |bytes1|
        key.bytes(self.context, self.primitive) do |bytes2|
          bytes1.to_str.must_equal bytes2.to_str
        end
      end
    end
  end

  describe 'with a password' do
    subject { self.klass.new(self.context, self.primitive, self.size, self.password) }

    # Sodium::Buffer clears cached `let`s
    def password
      'password'
    end

    it 'must not allow direct access to its bytes' do
      lambda { self.subject.bytes(self.context, self.primitive) }.
        must_raise ArgumentError
    end

    it 'must unlock its bytes with the password' do
      self.subject.unlock(self.password) do |key|
        key.bytes(self.context, self.primitive) {|_| _ }
      end.must_be_kind_of Sodium::Buffer
    end
  end
end
