require 'cryptography'

class Cryptography::Key
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

  def initialize!
    self.attributes.freeze
    self           .freeze
  end

  def initialize(context, primitive, size, password = nil)
    self.attributes = {
      :context   => context,
      :primitive => primitive,
      :bytes     => Sodium::Buffer.key(size)
    }

    self.lock!(password) unless password.nil?

    self.initialize!
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
      :context   => self.attributes[:context],
      :primitive => self.attributes[:primitive],
      :bytes     => key,
      :locked    => true
  end

  protected

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

  def _verify_context!(context)
    true
  end

  def _verify_primitive!(primitive)
    true
  end

  def _verify_locked!
    true
  end

  def _verify_unlocked!
    true
  end

  def _verify_signature!(signature)
    true
  end

  def _verify_kdf!(kdf)
    true
  end
end
