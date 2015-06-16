require 'ffi'

module DjbCrypto::FFI
  class Salsa20Core < DjbCrypto::Salsa20Core

    def initialize(*)
      super
      @c_in  = FFI::MemoryPointer.new(:uint32, 16)
      @c_in.write_array_of_uint32(new_input_block(doesnt_matter=0))
    end

    def first_bytes(n)
      cbytes = FFI::MemoryPointer.new(:uint8, n)
      C.salsa20_first_bytes(rounds, @c_in, n, cbytes)
      cbytes.read_string(n)
    end

    # maximum message length in bytes (first block is used for MAC key
    # derivation)
    MAX_MSG_BYTES = (2**64-2) * 64

    def ^(msg)
      mlen = msg.bytesize
      raise "message too long" if mlen > MAX_MSG_BYTES
      c_msg = FFI::MemoryPointer.from_string(msg)
      c_xor = FFI::MemoryPointer.new(:uint8, mlen)
      C.salsa20_hash_xor(rounds, @c_in, mlen, c_msg, c_xor)
      c_xor.read_string(mlen)
    end

    module C
      extend FFI::Library
      ffi_lib File.expand_path("../../../ext/c/salsa20.dylib",
                               File.dirname(__FILE__))
      attach_function :salsa20_hash_block,
        [:uint8, :uint64, :pointer, :pointer], :void
      attach_function :salsa20_hash_bytes,
        [:uint8, :uint64, :pointer, :pointer], :void
      attach_function :salsa20_first_bytes,
        [:uint8, :pointer, :size_t, :pointer], :void
      attach_function :salsa20_hash_xor,
        [:uint8, :pointer, :size_t, :pointer, :pointer], :void
    end
  end

  # Salsa20/20. Security: High.
  class Salsa2020 < Salsa20Core
    def rounds() 20 end
  end

  # Salsa20/12. Security: Okay.
  class Salsa2012 < Salsa20Core
    def rounds() 12 end
  end

  # Salsa20/8. Security: Insufficient.
  class Salsa208 < Salsa20Core
    def rounds() 8 end
  end
end
