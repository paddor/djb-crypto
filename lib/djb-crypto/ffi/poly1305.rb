require 'ffi'

module DjbCrypto::FFI
  # @see {DjbCrypto::Poly1305}
  # @see http://tools.ietf.org/html/rfc7539#section-2.5
  # @see https://en.wikipedia.org/wiki/Authenticated_encryption
  class Poly1305
    # MAC key size in bytes
    KEY_SIZE = 32

    module C
      extend FFI::Library
      ffi_lib File.expand_path("../../../ext/c/poly1305.dylib",
                               File.dirname(__FILE__))
      attach_function :poly1305_tag,
        [:pointer, :pointer, :size_t, :pointer, :pointer], :void
    end

    # @param key_stream [StreamCipher] key stream used to generate the key
    #   for {::poly1305}
    # @param aad [String] additional authenticated data
    # @param cipher_text [String] cipher text of the message
    def initialize(key_stream, aad, cipher_text)
      @stream = key_stream
      @aad = aad
      @cipher_text = cipher_text
    end

    # @return [String] the 16 byte authenticator
    def tag
      @tag ||= calculate_tag
    end

    private

    def calculate_tag
      key = @stream.first_bytes(KEY_SIZE) # one-time key
      r = key.byteslice(0, KEY_SIZE/2)
      s = key.byteslice(KEY_SIZE/2, KEY_SIZE/2)

      c_r = FFI::MemoryPointer.from_string(r)
      c_s = FFI::MemoryPointer.from_string(s)

      mac_data = mac_data()
      c_mac_data = FFI::MemoryPointer.from_string(mac_data)

      c_tag = FFI::MemoryPointer.new(:uint8, 16)
      C.poly1305_tag(c_r, c_s, mac_data.bytesize, c_mac_data, c_tag)
      c_tag.read_string(16)
    end

    # MAC data, the input for the {::poly1305} function (besides the secret key).
    # @return [String] MAC data
    def mac_data
      s = ""
      s << @aad
      s << (?\0 * (s.bytesize % 16))
      s << @cipher_text
      s << (?\0 * (s.bytesize % 16))
      s << [@aad.bytesize].pack("Q<")
      s << [@cipher_text.bytesize].pack("Q<")
    end
  end
end
