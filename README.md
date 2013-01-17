# cryptography #

A Ruby library to provide abstractions for common use-cases of
cryptography.

## Description ##

Cryptography is hard. Really hard, and deceptively hard. There are a
million and one ways for a developer to screw up when implementing
cryptography, and non-cryptographers are exceedingly unlikely to get
it right.

Unfortunately, there's a common mentality in the developer community
that getting tiny details wrong doesn't matter, that it's still "good
enough" to defeat hackers, if not the NSA. This mentality is, frankly,
stupid and dangerous. Tiny flaws in implementation details almost
inevitably result in a *complete* breach of security: revealing the
contents of ciphertexts, allowing manipulation of the contents of
ciphertexts, forging signed messages, or discovering users'
passwords. Even weaknesses that seem tolerable can often be trivially
combined with non-cryptographic security weaknesses to accomplish the
same goals.

Despite this, there are relatively few high-level interfaces to hide
the details of cryptographic primitives and to automatically use safe
and secure defaults. This library strongly adopts the mentality that
[if you're typing the letters A-E-S into your code, you're doing it
wrong][a-e-s].

This library does not attempt to implement any cryptography on its
own. It simply provides a sane, high-level, secure frontend to
existing libraries developed and maintained by respected
cryptographers with proven track records in security. In particular,
cryptographic primitives are implemented with [DJB][djb]'s venerable
[NaCl][nacl] library and passwords are processed with [bcrypt][bcrypt].

## Installation ##

```sh
$ gem install cryptography
```

You can load either the entire library or only the components you wish
to use.

```ruby
require 'cryptography'         # load the entire library
require 'cryptography/vault'   # only load Cryptography::Vault
require 'cryptography/lockbox' # only load Cryptography::Lockbox
```

## Usage ##

Each supported use-case is broken down into its own class.

### Cryptography::Vault ###

The Cryptography::Vault API should be used to hide sensitive data from
unauthorized parties. Access to the vault's contents is granted only
to parties who know the key which was used to lock the box.

Cryptography::Vault is implemented using an
[authenticated symmetric cipher][nacl_secretbox]. It is a combination
of the [Salsa20][nacl-salsa20] stream cipher and the
[Poly1035][nacl-poly1305] message authentication code.

#### Cutting Keys ####

A key is required to lock and unlock the vault. Keys may be reused for
multiple vaults, but any party who knows the key can open any Vault
locked with the key.

```ruby
key = Cryptography::Vault.key
```

#### Protecting Data ####

Vaults must be locked with a key and a string containing data to be
kept secret. The string is interpreted merely as a sequence of bytes,
and details like the string's encoding are ignored.

The locked vault can safely be stored on an insecure medium, or
transmitted over an insecure channel.

Note, though, that a locked vault is a *sequence of bytes*, and not an
encoded string. If you need to transmit a vault over a plaintext
protocol, you may wish to encode it with something like Base64 or
Base32.

```ruby
vault = Cryptography::Vault.lock(key, "secret data")
vault # => "\xAB\xD8\xD3\x1E..."

contents = Cryptography::Vault.unlock(key, vault)
contents # => "secret data"
```

#### Serializing to Other Formats ####

If you wish to serialize a Vault to a format other than a byte string,
you can instantiate a Vault with the key and plaintext, and convert it
to whatever supported format you find most convenient.

```ruby
# serialize to bytes, string (equivalent to bytes), an array, or a hash
vault = Cryptography::Vault.new(key, "secret data")
vault.to_bytes # => "\xAB\xD8\xD3\x1E..." (equivalent to Vault::lock)
vault.to_s     # => "\xAB\xD8\xD3\x1E..." (equivalent to Vault::lock)
vault.to_a     # => [ "\xAB\xD8\xD3\x1E...", "\x9A\xEB\x19\x97..." ]
vault.to_h     # => { :iv         => "\xAB\xD8\xD3\x1E...",
               #      :ciphertext => "\x9A\xEB\x19\x97...", }

# serialize to plaintext-friendly formats
vault.to_base64 # => "q9jTHg...\n"
vault.to_base32 # => "VPMNGHQ..." (requires the 'base32' gem)

# serialize through the native Ruby marshaller
vault.dump          # => \x04\bU:\nVault..." (uses native Ruby [marshalling])
Marshal.dump(vault) # => \x04\bU:\nVault..." (equivalent to the above)
```

#### Restoring from Serialized Formats ####

You can later restore the Vault from the above formats, and use the
`#unlock` method to access the protected data inside.

```ruby
# restore a vault from bytes, string, array, or hash
vault = Cryptography::Vault.from_bytes(bytes)
vault = Cryptography::Vault.from_s(string)
vault = Cryptography::Vault.from_a(array)
vault = Cryptography::Vault.from_h(hash)

# restore a vault from plaintext-friendly formats
vault = Cryptography::Vault.from_base64(base64)
vault = Cryptography::Vault.from_base32(base32)

# restore a vault from a marshalled string
vault = Cryptography::Vault.load(dump)
vault = Marshal.load(dump)

# retrieve the data inside the vault
vault.unlock(key) # => "secret data"
```

[a-e-s]:          http://chargen.matasano.com/chargen/2009/7/22/if-youre-typing-the-letters-a-e-s-into-your-code-youre-doing.html
[djb]:            http://en.wikipedia.org/wiki/Daniel_J._Bernstein
[nacl]:           http://nacl.cr.yp.to
[bcrypt]:         https://github.com/codahale/bcrypt-ruby
[nacl_secretbox]: http://nacl.cr.yp.to/secretbox.html
[nacl-salsa20]:   http://cr.yp.to/salsa20.html
[nacl-poly1305]:  http://cr.yp.to/mac.html
[ruby-marshal]:   http://www.ruby-doc.org/core-1.9.3/Marshal.html
