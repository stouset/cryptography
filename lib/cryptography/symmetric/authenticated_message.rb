require 'cryptography/symmetric'

class Cryptography::Symmetric::AuthenticatedMessage
  DEFAULT_IMPLEMENTATION = Sodium::Auth.implementation

  include Cryptography::Serializable

  serialize do
    required Cryptography::Serializable::Context,   :context,       0
    required Cryptography::Serializable::Primitive, :primitive,     1
    required :bytes,                                :message,       2
    required :bytes,                                :authenticator, 3
  end

  def self.key(password = nil)
    Cryptography::Symmetric::Key.new :authenticated_message,
      DEFAULT_IMPLEMENTATION.primitive,
      DEFAULT_IMPLEMENTATION[:KEYBYTES],
      password
  end

  def on_initialize!
    _verify_context!
    _verify_primitive!
    _verify_authenticator!

    self.attributes.freeze
    self.           freeze
  end

  def initialize(key, message)
    self.attributes = {
      :context       => :authenticated_message,
      :primitive     => key.primitive,
      :message       => Sodium::Buffer.new(message),
    }

    self.attributes[:authenticator] = self.authenticate(key)

    self.on_initialize!
  end

  def contents(key)
    _verify_authenticator!(key)

    self.attributes[:message]
  end

  protected

  def implementation
    Sodium::Auth.implementation(self.primitive)
  end

  def authenticator(key)
    key.bytes(self.context, self.primitive) do |bytes|
      self.implementation.new(bytes)
    end
  end

  def authenticate(key)
    self.authenticator(key).auth self.attributes[:message]
  end

  def context
    self.attributes[:context]
  end

  def primitive
    self.attributes[:primitive]
  end

  private

  def _verify_context!
    raise ArgumentError, %{can't use a #{self.context} as an authenticated message} unless
      self.context == :authenticated_message
  end

  def _verify_primitive!
    raise ArgumentError, %{unrecognized primitive #{self.primitive}} unless
      self.implementation
  end

  def _verify_authenticator!(key = nil)
    raise ArgumentError, %{either the key or the authenticated message has been tampered with} unless
      self.attributes[:authenticator].bytesize == self.implementation[:BYTES]

    raise ArgumentError, %{either the key or the authenticated message has been tampered with} if
      key && self.attributes[:authenticator] != self.authenticate(key)
  end
end
