require 'cryptography/kdf'
require 'benchmark'

class Cryptography::KDF::PBKDF2
  PRIMITIVES = {
    :hmacsha256    => 1,
    :hmacsha512256 => 2,
  }

  attr_accessor :size
  attr_accessor :primitive
  attr_accessor :cost

  def self.cost
    @cost ||= self.calibrate(0.2)
  end

  def self.cost=(cost)
    @cost = cost.to_i
  end

  def self.calibrate(seconds)
    (seconds / self.benchmark).to_i
  end

  def self.benchmark
    password   = Sodium::Buffer.key(8)
    salt       = Sodium::Buffer.key(32)
    iterations = 50_000
    pbkdf2     = self.new(32, :cost => iterations)

    # do our best to ensure garbage collection doesn't get run during
    # the measured interval
    GC.start

    # measure the total CPU time (not wall-clock time) and use it to
    # determine the time to calculate an average iteration
    Benchmark.measure do
     pbkdf2.stretch(password, salt)
    end.total / iterations
  end

  def initialize(size, options = {})
    # TODO: default cost based on the primitive
    self.size      = size
    self.primitive = options[:primitive] || Sodium::Auth.primitive
    self.cost      = options[:cost]      || self.class.cost

    # _verify_primitive!
    # _verify_cost!
    # _verify_length!
  end

  def stretch(password, salt)
    # the password must be padded to the size of the HMAC key
    password = Sodium::Buffer.ljust(password, self.key_size)

    # the seed for each hmac round is the salt prepended to the
    # four-byte round number, so we allocate four extra blank bytes to
    # be filled in later
    seed = Sodium::Buffer.rpad(salt, 4)

    # cache the block size for performance reasons
    size = self.block_size

    Sodium::Buffer.empty(self.size) do |key|
      self.blocks.times do |block|
        seed[salt.bytesize, 4] = [ block + 1 ].pack('L>')
        offset                 = block * size

        key[offset, size] = _xor_chained_hmac(password, seed, self.cost)
      end
    end
  end

  protected

  def implementation
    @implementation ||= Sodium::Auth.implementation(self.primitive)
  end

  def key_size
    self.implementation::KEYBYTES
  end

  def block_size
    self.implementation::BYTES
  end

  def blocks
    (self.size.to_f / self.block_size).ceil
  end

  private

  #
  # TODO: implement in C; beat OpenSSL benchmark
  #
  def _xor_chained_hmac(password, seed, iterations)
    hmac = self.implementation
    auth = Sodium::Buffer.empty(self.block_size)
    xor  = Sodium::Buffer.empty(self.block_size)

    # cache the method calls to the bytes and sizes inside of each
    # buffer for performance reasons
    auth_bytes = auth.to_str
    seed_bytes = seed.to_str
    pass_bytes = password.to_str
    xor_bytes  = xor.to_str

    # cache the method calls to bytesizes for the same reason
    auth_bytesize = auth_bytes.bytesize
    seed_bytesize = seed_bytes.bytesize

    # generate the first HMAC of the seed and password separately,
    # since generating it from the seed is a special-case that only
    # happens on the first iteration (all other times it uses the
    # previous calculation)
    hmac.nacl(
      auth_bytes,
      seed_bytes,
      seed_bytesize,
      pass_bytes
    )

    Sodium::FFI::Memory.sodium_memxor(
      xor_bytes,
      xor_bytes,
      auth_bytes,
      auth_bytesize
    )

    (iterations - 1).times do
      hmac.nacl(
        auth_bytes,
        auth_bytes,
        auth_bytesize,
        pass_bytes
      )

      Sodium::FFI::Memory.sodium_memxor(
        xor_bytes,
        xor_bytes,
        auth_bytes,
        auth_bytesize
      )
    end

    xor
  end
end
