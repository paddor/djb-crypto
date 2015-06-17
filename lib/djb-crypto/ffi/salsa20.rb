require 'ffi'

module DjbCrypto::FFI
  class Salsa20Core < DjbCrypto::Salsa20Core

    def initialize(key, nonce)
      raise "unsupported key size" if key.bytesize != self.class.key_size
      raise "unsupported nonce size" if nonce.bytesize != self.class.nonce_size
      @key = FFI::MemoryPointer.from_string(key)
      @nonce = nonce.unpack("Q<").first
    end

    def first_bytes(n)
      first_bytes_with_rounds(n).read_string(n)
    end

    # maximum message length in bytes (first block is used for MAC key
    # derivation)
    MAX_MSG_BYTES = (2**64-2) * 64

    def ^(msg)
      mlen = msg.bytesize
      raise "message too long" if mlen > MAX_MSG_BYTES
      c_msg = FFI::MemoryPointer.from_string(msg)
      c_ct = FFI::MemoryPointer.new(:uint8, mlen)
      xor_with_rounds(@key, @nonce, mlen, c_msg, c_ct)
      c_ct.read_string(mlen)
    end

    module C
      extend FFI::Library
      ffi_lib File.expand_path("../../../ext/c/salsa20.dylib",
                               File.dirname(__FILE__))

      # Salsa20/20
      attach_function :salsa20_first_bytes, [
         :pointer,  # key
         :uint64,   # nonce
         :size_t    # n
      ], :pointer   # ct bytes
      attach_function :salsa20_hash_xor, [
        :pointer, # key
        :uint64,  # nonce
        :size_t,  # mlen
        :pointer, # message
        :pointer  # ct
      ], :void

      # Salsa20/12
      attach_function :salsa2012_first_bytes, [
         :pointer,  # key
         :uint64,   # nonce
         :size_t    # n
      ], :pointer   # ct bytes
      attach_function :salsa2012_hash_xor, [
        :pointer, # key
        :uint64,  # nonce
        :size_t,  # mlen
        :pointer, # message
        :pointer  # ct
      ], :void

      # Salsa20/8
      attach_function :salsa208_first_bytes, [
         :pointer,  # key
         :uint64,   # nonce
         :size_t    # n
      ], :pointer   # ct bytes
      attach_function :salsa208_hash_xor, [
        :pointer, # key
        :uint64,  # nonce
        :size_t,  # mlen
        :pointer, # message
        :pointer  # ct
      ], :void
    end
  end

  # Salsa20/20. Security: High.
  class Salsa2020 < Salsa20Core
    def rounds() 20 end
    private
    def first_bytes_with_rounds(n)
      C.salsa20_first_bytes(@key, @nonce, n)
    end
    def xor_with_rounds(*args)
      C.salsa20_hash_xor(*args)
    end
  end

  # Salsa20/12. Security: Okay.
  class Salsa2012 < Salsa20Core
    def rounds() 12 end
    private
    def first_bytes_with_rounds(n)
      C.salsa2012_first_bytes(@key, @nonce, n)
    end
    def xor_with_rounds(*args)
      C.salsa2012_hash_xor(*args)
    end
  end

  # Salsa20/8. Security: Insufficient.
  class Salsa208 < Salsa20Core
    def rounds() 8 end
    private
    def first_bytes_with_rounds(n)
      C.salsa208_first_bytes(@key, @nonce, n)
    end
    def xor_with_rounds(*args)
      C.salsa208_hash_xor(*args)
    end
  end
end
