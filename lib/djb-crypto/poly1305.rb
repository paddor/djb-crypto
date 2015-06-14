require 'securerandom'

module DjbCrypto
  class MAC
    def initialize(stream, aad, cipher_text)
      @key = stream.first_bytes(32).pack("C*")
      @aad = aad
      @cipher_text = cipher_text
    end

    def tag
      Poly1305.new(@key, mac_data).tag
    end

    private

    # MAC data, the input for the Poly1305 function (besides the secret key).
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

  # Used to generate a message authenticator.
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
  class Poly1305
    KEY_SIZE = 32 # bytes
    P = 2**130-5

    attr_reader :tag

    def initialize(key, mac_data)
      raise "unsupported key size" if key.bytesize != KEY_SIZE
      @key = key
      @data = mac_data
      @tag = calculate_tag
    end

    private

    def calculate_tag
      r = @key.byteslice(0, KEY_SIZE/2).unpack("C*") # 16-octet LE
      s = @key.byteslice(KEY_SIZE/2, KEY_SIZE/2).unpack("C*").reverse.
        inject(0) { |memo, byte| (memo << 8) | byte }
      clamp(r)
      r = r.reverse.inject(0) { |memo, byte| (memo << 8) | byte }
      acc = 0
      @data.bytes.each_slice(16) do |block|
        n = block.reverse.inject(0) { |memo, byte| (memo << 8) | byte }
        n += 2**(block.size*8)
        acc = ((acc + n) * r) % P
      end
      acc = (acc + s) & 2**128-1
      tag = [acc & 2**64-1, acc >> 64].pack("Q<*")
      tag
    end

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
end
