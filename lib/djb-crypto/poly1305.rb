require 'securerandom'

module DjbCrypto
  # Used to generate the Poly1305 authenticator (MAC) for a cipher text and
  # additional authenticated data.
  #
  # My implementation uses the standard nonce size instead of the 96 bit
  # nonce suggested by this RFC. Actually I leave it up to the cipher that is
  # chosen to be used (as Poly1305 uses the cipher only to generate the MAC
  # key, and thus is cipher agnostic).
  #
  # I don't intend to use this code in TLS/IPsec connections. I'm more
  # interested in the general techniques involved in the generation of AEAD.
  #
  # @see http://tools.ietf.org/html/rfc7539#section-2.5
  # @see https://en.wikipedia.org/wiki/Authenticated_encryption
  class Poly1305
    # MAC key size in bytes
    KEY_SIZE = 32

    # the prime number used by the {::poly1305} function
    P = 2**130-5

    class << self
      # This is the raw Poly1305 function.
      # @param key [String] one-time key
      # @param mac_data [String] MAC data
      def tag(key, mac_data)
        if key.bytesize != KEY_SIZE
          raise "incorrect key length (#{key.bytesize} instead of #{KEY_SIZE} bytes)"
        end
        r = key.byteslice(0, KEY_SIZE/2).unpack("C*") # 16-octet LE
        s = key.byteslice(KEY_SIZE/2, KEY_SIZE/2).unpack("C*").reverse.
          inject(0) { |memo, byte| (memo << 8) | byte }
        clamp(r)
        r = r.reverse.inject(0) { |memo, byte| (memo << 8) | byte }
        acc = 0
        mac_data.bytes.each_slice(16) do |block|
          n = block.reverse.inject(0) { |memo, byte| (memo << 8) | byte }
          n += 2**(block.size*8)
          acc = ((acc + n) * r) % P
        end
        acc = (acc + s) & 2**128-1
        tag = [acc & 2**64-1, acc >> 64].pack("Q<*")
        tag
      end

      private

      def clamp(r)
       r[3]  &=  15
       r[7]  &=  15
       r[11] &=  15
       r[15] &=  15
       r[4]  &= 252
       r[8]  &= 252
       r[12] &= 252
      end
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
      @tag ||= self.class.tag(key, mac_data)
    end

    private

    # Generates a one-time key from the first block of the cipher stream.
    # @return [String] one-time key for {::poly1305}
    def key
      @stream.first_bytes(KEY_SIZE)
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
