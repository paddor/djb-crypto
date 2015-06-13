require 'securerandom'

module DjbCrypto
  # Used to generate a message authenticator.
  class Poly1305
    KEY_SIZE = 32 # bytes
    P = 2**130-5

    attr_reader :tag

    def initialize(key=random_key, message)
      raise "unsupported key size" if key.bytesize != KEY_SIZE
      @key = key
      @message = message
      @tag = calculate_tag
    end

    private

    def calculate_tag
      r = @key.byteslice(0, KEY_SIZE/2).unpack("C*") # 16-octet LE
      s = @key.byteslice(KEY_SIZE/2, KEY_SIZE/2).unpack("C*").reverse.
        inject(0) { |memo, byte| (memo << 8) | byte }
      clamp(r)
      r = r.reverse.inject(0) { |memo, byte| (memo << 8) | byte } # number from 16-octet LE
      acc = 0
      @message.bytes.each_slice(16) do |block|
        n = block.reverse.inject(0) { |memo, byte| (memo << 8) | byte }
        n += 2**(block.size*8)
        acc = ((acc + n) * r) % P
      end
      acc = (acc + s) & 2**128-1
      tag = [acc & 2**64-1, acc >> 64].pack("Q<*")
      tag
    end

    def random_key
      SecureRandom.random_bytes(KEY_SIZE)
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
