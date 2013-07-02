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

  gem.add_dependency 'sodium', '~> 0.6'

  gem.add_development_dependency 'rake',     '~> 10'
  gem.add_development_dependency 'minitest', '~> 5'
end
