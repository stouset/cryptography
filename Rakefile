require 'rake/clean'

CLOBBER.include FileList[
  'ext/**/*.bundle',
  'ext/**/*.o',
  'lib/**/*.bundle',
]

task :compile do
  Dir.chdir('ext/cryptography/na_cl') do
    system %{ruby extconf.rb}
    system %{make}
    system %{cp na_cl.#{RbConfig::CONFIG['DLEXT']} ../../../lib/cryptography}
  end
end
