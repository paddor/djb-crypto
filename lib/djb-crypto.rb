require 'securerandom'

# Pure Ruby implementations of some of Daniel J. Bernstein's cryptographic
# algorithms.
#
# @note Do not use in production. This is just an experiment.
# @author Patrik Wenger <paddor@gmail.com>
#
module DjbCrypto
  module FFI
  end
end

require_relative 'djb-crypto/stream_cipher'
require_relative 'djb-crypto/salsa20'
require_relative 'djb-crypto/xsalsa20'
require_relative 'djb-crypto/chacha'
require_relative 'djb-crypto/poly1305'
require_relative 'djb-crypto/ffi/salsa20'
require_relative 'djb-crypto/boxes'
