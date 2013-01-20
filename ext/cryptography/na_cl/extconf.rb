require 'mkmf'
require 'socket'

ARCH     = RbConfig::CONFIG['host_cpu'].sub 'x86_64', 'amd64'
HOSTNAME = Socket.gethostname[ %r{ [^.]+ }x ]

NACL_VERSION     = %{20110221}
NACL_DIR         = %{../../../vendor/nacl-#{NACL_VERSION}}
NACL_BUILD_DIR   = %{#{NACL_DIR}/build/#{HOSTNAME}}
NACL_INCLUDE_DIR = %{#{NACL_BUILD_DIR}/include/#{ARCH}}
NACL_LIB_DIR     = %{#{NACL_BUILD_DIR}/lib/#{ARCH}}
NACL_LIB         = %{#{NACL_LIB_DIR}/libnacl.a}

Dir.chdir(NACL_DIR) do
  warn <<-THIS_WILL_TAKE_FOREVER
+----------------------------------------------------------------------------+
| This gem needs to build DJB's NaCl cryptographic library to continue. The  |
| build process can take quite awhile: it builds several versions of needed  |
| functions and benchmarks them to choose the fastest one for your           |
| particular machine.                                                        |
|                                                                            |
| Please be patient. Your regularly scheduled programming will continue      |
| after this (not so) brief interruption.                                    |
+----------------------------------------------------------------------------+
  THIS_WILL_TAKE_FOREVER

  system('./do') or abort "NaCl failed to compile. Check #{NACL_BUILD_DIR}/log"
end unless File.exist?(NACL_LIB)

warn "NaCl compiled successfully."

dir_config('nacl', NACL_INCLUDE_DIR, NACL_LIB_DIR)
have_library('nacl', 'crypto_hash_sha512',    'crypto_hash.h')
have_library('nacl', 'crypto_secretbox',      'crypto_secretbox.h')
have_library('nacl', 'crypto_secretbox_open', 'crypto_secretbox.h')

create_makefile('cryptography/na_cl')
