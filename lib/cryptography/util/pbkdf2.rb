require 'cryptography/util'
require 'securerandom'

class Cryptography::Util::PBKDF2
  IMPLEMENTATIONS = [
    Cryptography::NaCl::Auth::HMACSHA256,
    Cryptography::NaCl::Auth::HMACSHA512256,
  ]

  IMPLEMENTATION = IMPLEMENTATIONS.last

  PRIMITIVES = IMPLEMENTATIONS.inject({}) do |h, i|
    h.update(i::PRIMITIVE => i)
  end

  attr_accessor :primitive
  attr_accessor :iterations
  attr_accessor :length

  def self.iterations
    @iterations ||= self.calibrate(0.1)
  end

  def self.iterations=(iterations)
    @iterations = iterations.to_i
  end

  def self.calibrate(seconds)
    (seconds / self.benchmark).to_i
  end

  def self.benchmark
    password   = SecureRandom.random_bytes(8)
    salt       = SecureRandom.random_bytes(32)
    iterations = 5_000
    pbkdf2     = self.new(32, :iterations => iterations)
    now        = Time.now

    pbkdf2.key(password, salt)

    (Time.now - now) / iterations
  end

  def initialize(length, options = {})
    self.primitive  = options[:primitive]  || IMPLEMENTATION::PRIMITIVE
    self.iterations = options[:iterations] || self.class.iterations
    self.length     = length

    _verify_primitive!
    _verify_iterations!
    _verify_length!
  end

  def key(password, salt)
    1.upto(self.blocks).inject("") do |result, i|
      password = password.ljust(self.key_length, "\0")
      seed     = salt + [ i ].pack('l>')

      result << _xor_chained_hmac(password, seed, self.iterations)
    end[0, self.length]
  end

  protected

  def implementation
    @implementation ||= IMPLEMENTATIONS.detect do |i|
      i::PRIMITIVE == self.primitive
    end
  end

  def key_length
    self.implementation::KEY_LEN
  end

  def hmac_length
    self.implementation::HMAC_LEN
  end

  def blocks
    (self.length.to_f / self.hmac_length).ceil
  end

  private

  def _verify_primitive!
    raise ArgumentError, %{unknown primitive #{self.primitive}} unless
      PRIMITIVES.keys.include?(self.primitive)
  end

  def _verify_iterations!
    raise ArgumentError, %{iterations must be at least one} unless
      self.iterations > 0
  end

  def _verify_length!
    raise ArgumentError, %{length must be at least one} unless
      self.length > 0
  end

  #
  # TODO: implement in C; beat OpenSSL benchmark
  #
  def _xor_chained_hmac(password, seed, iterations)
    result = self.implementation.auth(seed, password)

    (iterations - 1).times.inject(result) do |xor|
      result = self.implementation.auth(result, password)
      xor    = _xor(xor, result)
    end
  end

  def _xor(left, right)
    left   = left .bytes
    right  = right.bytes.to_a
    result = ""

    left.each.with_index {|b, i| result << (b ^ right[i]) }

    result
  end
end
