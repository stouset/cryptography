require 'test_helper'

describe Cryptography::KDF::PBKDF2 do
  subject      { self.klass.new(32) }
  let(:klass)  { Cryptography::KDF::PBKDF2 }
  let(:size)   { 32 }

  def self.pbkdf2_hmac_sha256_test_vector(dk_len, cost, password, salt, string)
    # normalize the string
    string = string.strip.gsub %r{\s+}, ' '

    it "must generate a key matching test vector #{string}" do
      kdf = self.klass.new(dk_len, :cost => cost, :primitive => :hmacsha256)
      dk  = kdf.derive(password, salt)
      dk.to_s.unpack('H*').first.scan(%r{\w\w}).join(' ').must_equal string
    end
  end

  it '::cost must reflect the number of iterations that can be run in reasonable time' do
    cost   = self.klass.cost
    pbkdf2 = self.klass.new(self.size, :cost => cost)

    Benchmark.measure do
      pbkdf2.derive('xyz', 'xyz')
    end.total.must_be_within_delta self.klass::DEFAULT_SECONDS, 0.2
  end

  it '::cost must be different for different primitives' do
    self.klass.cost(:hmacsha256).must_be :>, self.klass.cost
  end

  it '::calibrate must change the cost based on the allowed running time' do
    old_cost = self.klass.cost
    new_cost = self.klass.calibrate(0.05)

    old_cost.must_be :>, new_cost
  end

  it '::benchmark should return the average of seconds for a single iteration'

  it '#initialize must initialize the key size, primitive, and cost' do
    pbkdf2 = self.klass.new(self.size)
    pbkdf2.size.must_equal      self.size
    pbkdf2.cost.must_equal      self.klass.cost
    pbkdf2.primitive.must_equal self.klass::DEFAULT_PRIMITIVE
  end

  it '#initialize must validate the size' do
    lambda { self.klass.new( 0) }.must_raise ArgumentError
    lambda { self.klass.new(-1) }.must_raise ArgumentError
  end

  it '#initialize must validate the cost' do
    lambda { self.klass.new(self.size, :cost =>  0) }.must_raise ArgumentError
    lambda { self.klass.new(self.size, :cost => -1) }.must_raise ArgumentError
  end

  it '#initialize must validate the primitive' do
    lambda { self.klass.new(self.size, :primitive => :xyz) }.
      must_raise ArgumentError
  end

  pbkdf2_hmac_sha256_test_vector 20, 1,
    'password', 'salt',
    '12 0f b6 cf fc f8 b3 2c 43 e7 22 52 56 c4 f8 37 a8 65 48 c9'

  pbkdf2_hmac_sha256_test_vector 20, 2,
    'password', 'salt',
    'ae 4d 0c 95 af 6b 46 d3 2d 0a df f9 28 f0 6d d0 2a 30 3f 8e'

  pbkdf2_hmac_sha256_test_vector 20, 16_777_216,
    'password', 'salt',
    'cf 81 c6 6f e8 cf c0 4d 1f 31 ec b6 5d ab 40 89 f7 f1 79 e8' if
    ENV['ENABLE_SLOW_TESTS']

  pbkdf2_hmac_sha256_test_vector 25, 4_096,
    'passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt',
    '34 8c 89 db cb d3 2b 2f 32 d8 14 b8 11 6e 84 cf 2b 17 34 7e bc 18 00 18 1c'

  pbkdf2_hmac_sha256_test_vector 16, 4_096,
    "pass\0word", "sa\0lt",
    '89 b6 9d 05 16 f8 29 89 3c 69 62 26 65 0a 86 87'

  pbkdf2_hmac_sha256_test_vector 100, 4_096,
    'password', 'salt',
    %{ c5 e4 78 d5 92 88 c8 41 aa 53 0d b6 84 5c 4c 8d 96 28 93 a0 01 ce 4e
       11 a4 96 38 73 aa 98 13 4a f7 ad 98 c1 b4 58 ce 3f d7 4c a3 5b eb a3
       cd a7 b8 d1 03 8d 6a 87 07 1b 91 8f 83 74 05 f3 fe 77 28 ff e7 f0 97
       6f c3 5d d8 2f c0 e5 e4 6c e9 ce 26 a7 88 b2 c7 d1 83 fa 5b f8 d9 60
       7e ec d7 1d 01 b4 f1 19 }
end
