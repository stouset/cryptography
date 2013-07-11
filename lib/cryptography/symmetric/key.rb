require 'cryptography/symmetric'

class Cryptography::Symmetric::Key
  include Cryptography::Serializable

  serialize do
    # core attributes
    required Cryptography::Serializable::Context,   :context,   0
    required Cryptography::Serializable::Primitive, :primitive, 1
    required :bytes,                                :bytes,     2

    # attributes for password-protected keys
    optional :bool,                                 :locked,        10
    optional Cryptography::Serializable::Primitive, :kdf,           11
    optional Cryptography::Serializable::Primitive, :kdf_primitive, 12
    optional :int64,                                :kdf_cost,      13
    optional :bytes,                                :kdf_signature, 14
  end

  def on_initialize!
    _verify_context!
    _verify_primitive!
    _verify_size!

    self.attributes.freeze
    self           .freeze
  end

  def on_serialize!
    _verify_serializable!
  end

  def initialize(context, primitive, size, password = nil)
    self.attributes = {
      :context   => context,
      :primitive => primitive,
      :bytes     => Sodium::Buffer.key(size)
    }

    self.lock!(password) unless password.nil?

    self.on_initialize!
  end

  def bytes(context, primitive)
    _verify_context!   context
    _verify_primitive! primitive
    _verify_unlocked!

    yield self.attributes[:bytes]
  end

  def unlock(password)
    _verify_locked!
    _verify_kdf! :pbkdf2

    # TODO: support other KDFs besides PBKDF2
    kdf = Cryptography::KDF::PBKDF2.new(
      self.attributes[:bytes].bytesize,
      :primitive => self.attributes[:kdf_primitive],
      :cost      => self.attributes[:kdf_cost]
    )

    password  = Sodium::Buffer.new(password)
    key       = kdf.derive password, self.attributes[:bytes]
    signature = kdf.derive password, key, :cost => 1

    _verify_signature! signature

    yield self.class.send :from_hash,
      :context      => self.attributes[:context],
      :primitive    => self.attributes[:primitive],
      :bytes        => key,
      :protected    => true
  end

  protected

  def context
    self.attributes[:context]
  end

  def primitive
    self.attributes[:primitive]
  end

  def lock!(password)
    kdf = Cryptography::KDF::PBKDF2.new(
      self.attributes[:bytes].bytesize
    )

    password  = Sodium::Buffer.new(password)
    key       = kdf.derive password, self.attributes[:bytes]
    signature = kdf.derive password, key, :cost => 1

    self.attributes.update(
      :locked        => true,
      :kdf           => :pbkdf2,
      :kdf_primitive => kdf.primitive,
      :kdf_cost      => kdf.cost,
      :kdf_signature => signature
    )
  end

  private

  def _verify_context!(context = nil)
    raise ArgumentError, %{unrecognized context "#{self.context}"} unless
      Cryptography::Serializable::Context[self.context]

    raise ArgumentError, %{unable to use a #{self.context} key in #{context} context} unless
      context == self.context if context
  end

  def _verify_primitive!(primitive = nil)
    raise ArgumentError, %{unrecognized primitive "#{self.primitive}"} unless
      Cryptography::Serializable::Primitive[self.primitive]

    raise ArgumentError, %{unable to use a #{self.primitive} key for #{primitive} operations} unless
      primitive == self.primitive if primitive
  end

  def _verify_size!
    raise ArgumentError, %{key size must be positive} unless
      self.attributes[:bytes].bytesize > 0
  end

  def _verify_unlocked!
    raise ArgumentError, %{key must be unlocked with a password} if
      self.attributes[:locked]
  end

  def _verify_locked!
    raise ArgumentError, %{key must be unlocked with a password first} unless
      self.attributes[:locked]
  end

  def _verify_kdf!(kdf)
    raise ArgumentError, %{PBKDF is the only supported KDF} unless
      kdf == :pbkdf2
  end

  def _verify_signature!(signature)
    raise ArgumentError, %{incorrect password used to unlock the key} unless
      self.attributes[:kdf_signature] == signature
  end

  def _verify_serializable!
    raise ArgumentError, %{password-protected keys may not be serialized when unlocked} if
      self.attributes[:protected]
  end
end
