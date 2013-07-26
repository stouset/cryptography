require 'cryptography'
require 'bcrypt'

class Cryptography::Password
  DEFAULT_SECONDS = 0.2
  DEFAULT_COST    = BCrypt::Engine.calibrate(DEFAULT_SECONDS * 1000)

  include Cryptography::Serializable

  serialize do
    required Cryptography::Serializable::Context,   :context,        0
    required Cryptography::Serializable::Primitive, :primitive,      1
    required Cryptography::Serializable::Context,   :hmac_context,   2
    required Cryptography::Serializable::Primitive, :hmac_primitive, 3
    required :bytes,                                :verifier,       4
  end

  def self.key
    Cryptography::Symmetric::AuthenticatedMessage.key
  end

  def on_initialize!
    _verify_context!
    _verify_primitive!
    _verify_hmac_context!
    _verify_hmac_primitive!

    self.attributes.freeze
    self           .freeze
  end

  def self.generate(key, options = {})
    self.new(key, 'xyz')
  end

  def initialize(key, password, options = {})
    self.attributes = {
      :context        => :password,
      :primitive      => :bcrypt,
      :hmac_context   => key.context,
      :hmac_primitive => key.primitive,
    }

    authenticator = self.hmac   key, password
    verifier      = self.bcrypt authenticator, :cost => options[:cost]

    self.attributes[:verifier] = verifier
  end

  def verify(key, password)
    self.verifier == self.hmac(key, password)
  end

  protected

  def hmac_context
    self.attributes[:hmac_context]
  end

  def hmac_primitive
    self.attributes[:hmac_primitive]
  end

  def hmac_implementation
    Sodium::Auth.implementation(self.hmac_primitive)
  end

  def hmac_authenticator(key)
    _verify_hmac_context!
    _verify_hmac_primitive!

    key.bytes(self.hmac_context, self.hmac_primitive) do |bytes|
      self.hmac_implementation.new(bytes)
    end
  end

  def verifier
    BCrypt::Password.new self.attributes[:verifier].to_s if
      self.attributes[:verifier]
  end

  def hmac(key, password)
    self.hmac_authenticator(key).auth(password)
  end

  def bcrypt(authenticator, options = {})
    cost = options[:cost] || DEFAULT_COST

    Sodium::Buffer.new BCrypt::Password.create(authenticator, :cost => cost)
  end

  private

  def _verify_context!
  end

  def _verify_primitive!
  end

  def _verify_hmac_context!
  end

  def _verify_hmac_primitive!
  end
end
