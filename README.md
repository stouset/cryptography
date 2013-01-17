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

## Installation ##

```sh
$ gem install cryptography
```

[a-e-s]: http://chargen.matasano.com/chargen/2009/7/22/if-youre-typing-the-letters-a-e-s-into-your-code-youre-doing.html
