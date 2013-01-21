require 'cryptography/util'

class Cryptography::Util::PBKDF2
  IMPLEMENTATIONS = [
    Cryptography::NaCl::Auth::HMACSHA256,
    Cryptography::NaCl::Auth::HMACSHA512256,
  ]

  PRIMITIVES = IMPLEMENTATIONS.inject({}) do |h, i|
    h.update(i::PRIMITIVE => i)
  end

  IMPLEMENTATION = IMPLEMENTATIONS.last
  ITERATIONS     = 1000 # TODO: self.calibrate(0.1)

  attr_accessor :primitive
  attr_accessor :iterations
  attr_accessor :length

  def self.calibrate(seconds)
  end

  def initialize(length, options = {})
    self.primitive  = options[:primitive]  || IMPLEMENTATION::PRIMITIVE
    self.iterations = options[:iterations] || ITERATIONS
    self.length     = length

    _verify_primitive!
    _verify_iterations!
    _verify_length!
  end

  def key(password, salt)
    1.upto(self.blocks).map do |i|
      _xor_chained_hmac(password, salt, self.iterations, i)
    end.join
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
    self.length / self.hmac_length
  end

  private

  def _verify_primitive!
    raise ArgumentError, %{unknown primitive #{self.primitive}} unless
      PRIMITIVES.keys.include?(self.primitive)
  end

  def _verify_iterations!
    raise ArgumentError, %{iterations must be no less than zero} unless
      self.iterations >= 0
  end

  def _verify_length!
    raise ArgumentError, %{length must be greater than zero} unless
      self.length > 0

    raise ArgumentError, %{length must be a multiple of %{self.hmac_length}} unless
      self.length % self.hmac_length == 0
  end

  def _xor_chained_hmac(password, salt, iterations, i)
    password = password.ljust(self.key_length, 0.chr)
    seed     = salt + [ i ].pack('l>')

    hmacs = iterations.times.inject [ seed ] do |results, _|
      results << self.implementation.auth(results.last, password)
    end.drop(1)

    hmacs.inject do |xor, hmac|
      xor.bytes.zip(hmac.bytes).map {|pair| pair[0] ^ pair[1] }.map(&:chr).join
    end
  end
end
