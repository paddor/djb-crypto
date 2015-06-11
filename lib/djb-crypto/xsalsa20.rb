module DjbCrypto
  # XSalsa20.
  #
  # Basically Salsa20, but with a much bigger nonce.
  #
  # This is a "two-level generalized cascade": Using HSalsa20 one single block
  # is computed, part of which then is used as the key for subsequent blocks
  # computed using Salsa20.
  #
  # @see http://cr.yp.to/snuffle/xsalsa-20110204.pdf
  class XSalsa20Core < Salsa20Core
    def self.nonce_size
      24 # bytes
    end

    def initialize(key, nonce)
      super
      @cascade_key = cascade_key
    end

    private

    # This is basically computing one single HSalsa20 block, but returning
    # only the relevant 8 words (called "z-words" in the paper).
    def cascade_key
      k0, k1, k2, k3, k4, k5, k6, k7 = @key_words
      n0, n1, n2, n3 = @nonce_words
      c0, c1, c2, c3 = @constant
      @block = [
        c0, k0, k1, k2,
        k3, c1, n0, n1,
        n2, n3, c2, k4,
        k5, k6, k7, c3,
      ]
      diffuse
      z = @block
      return z[0], z[5], z[10], z[15], z[6], z[7], z[8], z[9]
    end

    def new_input_block(count)
      k0, k1, k2, k3, k4, k5, k6, k7 = @cascade_key
      *, n4, n5 = @nonce_words
      c0, c1, c2, c3 = @constant
      b0, b1 = count & WORD, (count >> WORD_WIDTH) & WORD # block counter words
      @block = [
        c0, k0, k1, k2,
        k3, c1, n4, n5,
        b0, b1, c2, k4,
        k5, k6, k7, c3,
      ]
    end
  end

  class XSalsa2020 < XSalsa20Core
    def rounds() 20 end
  end
  class XSalsa2012 < XSalsa20Core
    def rounds() 12 end
  end
  class XSalsa208 < XSalsa20Core
    def rounds() 8 end
  end
end
