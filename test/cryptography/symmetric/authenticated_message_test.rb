require 'test_helper'

describe Cryptography::Symmetric::AuthenticatedMessage do
  subject         { self.klass.new(self.key, self.plaintext) }
  let(:klass)     { Cryptography::Symmetric::AuthenticatedMessage }
  let(:key)       { self.klass.key }

  def plaintext
    'message'
  end

  def self.protocol_buffer_authenticated_message_test_vector(plaintext, key, bytes)
    it "must never break backwards compatibility with the serialization format" do
      key = Cryptography::Symmetric::Key.from_s(key)

      self.klass.from_s(bytes).contents(key).to_s.must_equal(plaintext)
    end
  end

  protocol_buffer_authenticated_message_test_vector(
    %{hello},
    %{\x00\n\b\xE8\a\x12 \x06\xC6\xC9\xF7\xC4\xBF\xE5\xCF`W`\xEDV\x98\xD88\x92\x97\x0Ew\xF4e\x9Fl\x9A\xF7\xD1\xCD4\xFA-~},
    %{\x00\n\b\xE8\a\x12\x05hello\x1A =-\xEF\xF8\xD7v8\xC2\x17;\x9AK\x8E\xE2\nO\"rq\xAE|1Jq\x17\x11\xFD\\8Vz\x1D}
  )

  protocol_buffer_authenticated_message_test_vector(
    %{This is a larger sentence authenticated with HMACSHA512256},
    %{\x00\n\b\xE9\a\x12 _\x16k\xEA\xCD\xF6Er\x94p\x9D \x16\xE8\xBD\xE5\x8Dk\x936\x94\xE8\xCC\x97\x84\\\xE5\xE0K8\x1D\xED},
    %{\x00\n\b\xE9\a\x12:This is a larger sentence authenticated with HMACSHA512256\x1A A\xDC\xE9`%\x9AN\xE71\x95A^\xC9|\n\xD0\xF0|Gc\xB7\xE0t\x80.]E>\xD6\xB9~n}
  )

  it 'must generate usable keys' do
    self.key.context  .must_equal :authenticated_message
    self.key.primitive.must_equal Sodium::Auth.primitive
  end

  it 'must require a key and message' do
    self.klass.new(self.key, self.plaintext).
      must_be_kind_of self.klass
  end

  it '#contents must require the key to reveal the message' do
    self.subject.contents(self.key).to_s.must_equal self.plaintext
  end
end
