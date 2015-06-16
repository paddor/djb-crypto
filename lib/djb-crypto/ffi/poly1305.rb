require 'ffi'

module DjbCrypto::FFI
  # @see {DjbCrypto::Poly1305}
  # @see http://tools.ietf.org/html/rfc7539#section-2.5
  # @see https://en.wikipedia.org/wiki/Authenticated_encryption
  class Poly1305
    # MAC key size in bytes
    KEY_BYTES = 32

    module C
      extend FFI::Library
      ffi_lib File.expand_path("../../../ext/c/poly1305.dylib",
                               File.dirname(__FILE__))
      attach_function :poly1305_tag,
        [:pointer, :uint64, :pointer, :uint64, :pointer, :pointer], :void
    end

    # @param key_stream [StreamCipher] key stream used to generate the key
    #   for {::poly1305}
    # @param aad [String] additional authenticated data
    # @param cipher_text [String] cipher text of the message
    def initialize(key_stream, aad, cipher_text)
      @key = key_stream.first_bytes(KEY_BYTES)
      @aad = aad
      @cipher_text = cipher_text
    end

    # @return [String] the 16 byte authenticator
    def tag
      @tag ||= calculate_tag
    end

    private

    def calculate_tag
      c_key = FFI::MemoryPointer.from_string(@key)
      c_aad = FFI::MemoryPointer.from_string(@aad)
      aad_len = @aad.bytesize
      c_ct = FFI::MemoryPointer.from_string(@cipher_text)
      ct_len = @cipher_text.bytesize
      c_tag = FFI::MemoryPointer.new(:uint8, 16)

      C.poly1305_tag(c_key, aad_len, c_aad, ct_len, c_ct, c_tag)
      c_tag.read_string(16)
    end
  end
end
