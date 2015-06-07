require 'securerandom'

# Pure Ruby implementations of some of Daniel J. Bernstein's cryptographic
# algorithms.
#
# @note Do not use in production. This is just an experiment.
# @author Patrik Wenger <paddor@gmail.com>
#
module DjbCrypto
end

require_relative 'djb-crypto/salsa20'
require_relative 'djb-crypto/xsalsa20'
require_relative 'djb-crypto/poly1305'
require_relative 'djb-crypto/boxes'
