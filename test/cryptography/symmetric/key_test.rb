require 'test_helper'

describe Cryptography::Symmetric::Key do
  let(:klass)     { Cryptography::Symmetric::Key }
  let(:size)      { 32 }
  let(:context)   { :authenticated_message }
  let(:primitive) { :xsalsa20poly1305 }

  def self.protocol_buffer_key_test_vector(context, primitive, *args)
    string   = args.pop
    key      = Sodium::Buffer.new(args.pop)
    password = args.pop

    it "must never break backwards compatibility with the serialization format" do
      self.klass.from_s(string).bytes(context, primitive) do |bytes|
        bytes.to_s.must_equal key
      end if password.nil?

      self.klass.from_s(string).unlock(password) do |unlocked|
        unlocked.bytes(context, primitive) do |bytes|
          bytes.to_s.must_equal key
        end
      end unless password.nil?
    end
  end

  protocol_buffer_key_test_vector :unknown, :unknown,
    "*",
    "\x00\x00\b\x00\x12\x01*"

  protocol_buffer_key_test_vector :authenticated_message, :hmacsha512256,
    "\x00h\xA4\xAC\xB2\xA3\xB2u\xE9\xFE[\x9B\x1D\xC3\x196\xB3\xF2y\n\x9EH\xA7\x91\xEDit'E\xA4%C",
    "\x00\n\b\xE9\a\x12 \x00h\xA4\xAC\xB2\xA3\xB2u\xE9\xFE[\x9B\x1D\xC3\x196\xB3\xF2y\n\x9EH\xA7\x91\xEDit'E\xA4%C"

  protocol_buffer_key_test_vector :authenticated_message, :hmacsha512256, 'password',
    "\xB9\x06?W$\xB4$2\x163/\x0E\xB2\x02\xC2\x8A)",
    "\x00\n\b\xE9\a\x12\x11\x1D\xF3p\xDB()\b{\xD7\xA5xL\x01\x85N\xA3\x90P\x01X\n`\xE9\ah\x82\x97\x02r\x11+\xCF\xF3P\x8A\x92\xD1l&\xD9\xC0\xAA*\xF48T\xF6"

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
          bytes1.to_s.wont_equal bytes2.to_s
        end
      end
    end

    it 'must use a random source of data for key generation' do
      Sodium::Buffer.stub(:key, "\0" * 32) do
        self.subject.bytes(self.context, self.primitive) do |bytes|
          bytes.to_s.must_equal "\0" * 32
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
          bytes1.to_s.must_equal bytes2.to_s
        end
      end
    end
  end

  describe 'with a password' do
    subject { self.klass.new(self.context, self.primitive, self.size, self.password) }

    # Sodium::Buffer clears cached `let`s
    def password
      'password'.gsub('', '')
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
