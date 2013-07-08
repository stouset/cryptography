require 'cryptography/kdf'
require 'benchmark'

class Cryptography::KDF::PBKDF2
  DEFAULT_SECONDS   = 0.2
  DEFAULT_PRIMITIVE = Sodium::Auth.primitive

  BENCHMARK_KEY_LENGTH = 32
  BENCHMARK_ITERATIONS = 50_000

  attr_accessor :size
  attr_accessor :primitive
  attr_accessor :cost

  def self.cost(primitive = DEFAULT_PRIMITIVE)
    @costs            ||= {}
    @costs[primitive] ||  self.calibrate(DEFAULT_SECONDS, primitive)
  end

  def self.calibrate(seconds = DEFAULT_SECONDS, primitive = DEFAULT_PRIMITIVE)
    @costs            ||= {}
    @costs[primitive]   = (
      seconds / self.benchmark(primitive)
    ).to_i
  end

  def self.benchmark(primitive = DEFAULT_PRIMITIVE)
    password   = Sodium::Buffer.key BENCHMARK_KEY_LENGTH
    salt       = Sodium::Buffer.key BENCHMARK_KEY_LENGTH
    iterations = BENCHMARK_ITERATIONS
    pbkdf2     = self.new BENCHMARK_KEY_LENGTH,
      :cost      => iterations,
      :primitive => primitive

    # measure the total CPU time (not wall-clock time) and use it to
    # determine the time needed to calculate a single iteration on average
    Benchmark.measure do
      pbkdf2.derive(password, salt)
    end.total / iterations
  end

  def initialize(size, options = {})
    self.size      = size
    self.primitive = options[:primitive] || DEFAULT_PRIMITIVE
    self.cost      = options[:cost]      || self.class.cost(self.primitive)

    _verify_size!
    _verify_cost!
    _verify_primitive!
  end

  def derive(password, salt, options = {})
    # disable GC for the duration of the critical section of PBKDF2,
    # so we can squeeze out as many iterations as possible
    GC.disable

    # the password must be padded to the size of the HMAC key
    password = Sodium::Buffer.ljust(password, self.key_size)

    # the seed for each hmac round is the salt prepended to the
    # four-byte round number, so we allocate four extra blank bytes to
    # be filled in later
    seed = Sodium::Buffer.rpad(salt, 4)

    # allow the cost to be overridden
    cost = options[:cost] || self.cost

    # cache the block size for performance reasons
    block_size = self.block_size

    # ensure the buffer is sized to a multiple of the block size; we
    # trim it down to the requested number of bytes later
    buffer_size = block_size * (self.size.to_f / block_size).ceil

    Sodium::Buffer.empty(buffer_size) do |key|
      self.blocks.times do |block_number|
        seed[salt.bytesize, 4] = [ block_number + 1 ].pack('L>')
        offset                 = block_number * block_size

        key[offset, block_size] = _xor_chained_hmac(password, seed, cost)
      end
    end[0, self.size]
  ensure
    # be a good citizen and turn GC back on :)
    GC.enable
  end

  protected

  def implementation
    @implementation ||= Sodium::Auth.implementation(self.primitive)
  end

  def key_size
    self.implementation[:KEYBYTES]
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

  def _verify_size!
    raise ArgumentError, %{size must be positive} unless
      self.size > 0
  end

  def _verify_cost!
    raise ArgumentError, %{cost must be positive} unless
      self.cost > 0
  end

  def _verify_primitive!
    raise ArgumentError, %{#{self.primitive} is not a recognized HMAC} unless
      self.implementation
  end
end
