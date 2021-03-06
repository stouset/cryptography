Gem::Specification.new do |gem|
  gem.name    = 'cryptography'
  gem.version = '0.0.0'

  gem.author = 'Stephen Touset'
  gem.email  = 'stephen@touset.org'

  gem.homepage    = 'https://github.com/stouset/cryptography'
  gem.summary     = %{TBD}
  gem.description = %{TBD}

  gem.bindir      = 'script'
  gem.files       = `git ls-files`            .split("\n")
  gem.executables = `git ls-files -- script/*`.split("\n").map {|e| File.basename(e) }
  gem.test_files  = `git ls-files -- spec/*`  .split("\n")

  gem.add_dependency 'sodium',                '~> 0.7'
  gem.add_dependency 'ruby-protocol-buffers', '~> 1'

  gem.add_development_dependency 'rake',     '~> 10'
  gem.add_development_dependency 'minitest', '~> 5'

  # bundler tries to build the gem on load, so only sign if the key is
  # present; however, we still warn just in case we're legitimately
  # packaging the gem for release but they key isn't available
  if File.exist?('/Volumes/Sensitive/Keys/Gems/cryptography@touset.org.key')
    gem.signing_key = '/Volumes/Sensitive/Keys/Gems/cryptography@touset.org.key'
    gem.cert_chain  = [ 'certs/cryptography@touset.org.cert' ]
  else
    warn 'Building the cryptography gem without a signature...'
  end
end
