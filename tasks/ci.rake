LIBSODIUM_MIRROR  = ENV['LIBSODIUM_MIRROR']  || "https://github.com/jedisct1/libsodium/tarball/%s"
LIBSODIUM_VERSION = ENV['LIBSODIUM_VERSION'] || 'master'
LIBSODIUM_DIGEST  = ENV['LIBSODIUM_DIGEST']  || nil

LIBSODIUM_URL       = LIBSODIUM_MIRROR % LIBSODIUM_VERSION
LIBSODIUM_PATH      = "libsodium-#{LIBSODIUM_VERSION}"
LIBSODIUM_TARBALL   = "build/#{LIBSODIUM_PATH}.tar.gz"
LIBSODIUM_BUILD     = "build/#{LIBSODIUM_PATH}"

namespace :ci do
  task :dependencies => :'libsodium:install'
end

namespace :libsodium do
  directory LIBSODIUM_BUILD

  file LIBSODIUM_TARBALL => LIBSODIUM_BUILD do
    sh %{curl -L -o #{LIBSODIUM_TARBALL} #{LIBSODIUM_URL}}

    next if LIBSODIUM_DIGEST.nil?
    next if LIBSODIUM_DIGEST == Digest::SHA256.hexdigest(
      File.read(LIBSODIUM_TARBALL)
    )

    rm LIBSODIUM_TARBALL
    raise "#{LIBSODIUM_TARBALL} failed checksum"
  end

  file "#{LIBSODIUM_BUILD}/autogen.sh" => [
    LIBSODIUM_BUILD,
    LIBSODIUM_TARBALL,
  ] do
    sh %{tar -C #{LIBSODIUM_BUILD} --strip-components 1 -m -xf #{LIBSODIUM_TARBALL}}
  end

  file "#{LIBSODIUM_BUILD}/configure" => "#{LIBSODIUM_BUILD}/autogen.sh" do
    sh %{cd #{LIBSODIUM_BUILD} && ./autogen.sh}
  end

  file "#{LIBSODIUM_BUILD}/Makefile" => "#{LIBSODIUM_BUILD}/configure" do
    sh %{cd #{LIBSODIUM_BUILD} && ./configure}
  end

  task :install => "#{LIBSODIUM_BUILD}/Makefile" do
    sh %{cd #{LIBSODIUM_BUILD} && make && make install}
  end
end
