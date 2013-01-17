Gem::Specification.new do |gem|
  gem.name    = 'cryptography'
  gem.version = '0.0.0'

  gem.author = 'Stephen Touset'
  gem.email  = 'stephen@touset.org'

  gem.homepage    = 'https://github.com/stouset/cryptography'
  gem.summary     = %{TBD}
  gem.description = %{TBD}

  gem.bindir = 'script'
  gem.files       = `git ls-files`            .split("\n")
  gem.extensions  = `git ls-files -- ext/*.rb`.split("\n")
  gem.executables = `git ls-files -- script/*`.split("\n").map {|e| e.delete('script/') }
  gem.test_files  = `git ls-files -- spec/*`  .split("\n")
end
