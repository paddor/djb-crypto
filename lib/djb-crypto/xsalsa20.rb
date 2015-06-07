module DjbCrypto
  class HSalsa20 < Salsa20Core
    NONCE_SIZE = 16 # bytes

    def new_input_block(count)
      k = @key_words
      n = @nonce_words
      c = @salsa_constant
      @block = [
        c[0], k[0], k[1], k[2],
        k[3], c[1], n[0], n[1],
        n[2], n[3], c[2], k[4],
        k[5], k[6], k[7], c[3],
      ]
    end

    def hash
      (rounds/2).times { double_round }
      output_block.pack("V*")
      #.tap{|ob| puts "output block: #{ob.unpack("V*").map {|n| "0x%x" % n }}"}
    end

    private

    def output_block
      z = @block
      [
        z[0], z[5], z[10], z[15],
        z[6], z[7], z[ 8], z[ 9],
      ]
    end
  end

  # XSalsa20.
  #
  # Basically Salsa20 with a much bigger nonce.
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
      initialize_block
    end

    # This is basically computing one single HSalsa20 block.
    def initialize_block
      k = @key_words
      n = @nonce_words
      c = @salsa_constant
      @block = [
        c[0], k[0], k[1], k[2],
        k[3], c[1], n[0], n[1],
        n[2], n[3], c[2], k[4],
        k[5], k[6], k[7], c[3],
      ]
#      puts "first block: #{@block}"
      (rounds/2).times { double_round }
      @z_words = @block.dup
    end

    def new_input_block(count)
      z = @z_words
      n = @nonce_words
      c = @salsa_constant
      b = [ count & WORD, (count >> WORD_WIDTH) & WORD ] # block counter words
      @block = [
        c[0 ], z[ 0], z[ 5], z[10],
        z[15], c[ 1], n[ 4], n[ 5],
        b[0 ], b[ 1], c[ 2], z[ 6],
        z[7 ], z[ 8], z[ 9], c[ 3],
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
