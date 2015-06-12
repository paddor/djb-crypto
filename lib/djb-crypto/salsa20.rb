module DjbCrypto
  # Salsa20 hash function, also called Salsa20 core.
  #
  # @see http://cr.yp.to/snuffle/salsafamily-20071225.pdf
  #
  # @example Sample 16 byte input:
  # 0x61707865, 0x04030201, 0x08070605, 0x0c0b0a09,
  # 0x100f0e0d, 0x3320646e, 0x01040103, 0x06020905,
  # 0x00000007, 0x00000000, 0x79622d32, 0x14131211,
  # 0x18171615, 0x1c1b1a19, 0x201f1e1d, 0x6b206574.
  #
  # @example End of round 1:
  # 0x4dfdec95, 0xd3c83331, 0x71572c6d, 0xf3e4deb6,
  # 0xcc266b9b, 0xe78e794b, 0x91b3379b, 0xbb230990,
  # 0xdc64a31d, 0x95f3bcee, 0xf94fe453, 0x130804a0,
  # 0x95b0c8b6, 0xa45e5d04, 0xf0a45550, 0xa272317e.
  #
  # @example End of round 2:
  # 0xba2409b1, 0x1b7cce6a, 0x29115dcf, 0x5037e027,
  # 0x37b75378, 0x348d94c8, 0x3ea582b3, 0xc3a9a148,
  # 0x825bfcb9, 0x226ae9eb, 0x63dd7748, 0x7129a215,
  # 0x4effd1ec, 0x5f25dc72, 0xa6c3d164, 0x152a26d8.
  #
  # @example End of round 20:
  # 0x58318d3e, 0x0292df4f, 0xa28d8215, 0xa1aca723,
  # 0x697a34c7, 0xf2f00ba8, 0x63e9b0a1, 0x27250e3a,
  # 0xb1c7f1f3, 0x62066edc, 0x66d3ccf1, 0xb0365cf3,
  # 0x091ad09e, 0x64f0c40f, 0xd60d95ea, 0x00be78c9.
  #
  # @example Output block:
  # 0xb9a205a3, 0x0695e150, 0xaa94881a, 0xadb7b12c,
  # 0x798942d4, 0x26107016, 0x64edb1a4, 0x2d27173f,
  # 0xb1c7f1fa, 0x62066edc, 0xe035fa23, 0xc4496f04,
  # 0x2131e6b3, 0x810bde28, 0xf62cb407, 0x6bdede3d.
  class Salsa20Core
    WORD_WIDTH = 32 # bits
    WORD = 2**WORD_WIDTH - 1 # used to truncate bits

    # Salsa constant for 32-byte keys
    SALSA_CONST32 = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574].freeze

    # Salsa constant for 16-byte keys
    SALSA_CONST16 = [0x61707865, 0x3120646e, 0x79622d36, 0x6b206574].freeze

    # Salsa constant for 10-byte keys
    SALSA_CONST10 = [0x61707865, 0x3120646e, 0x79622d30, 0x6b206574].freeze

    # @return [Integer] key size in bytes
    def self.key_size() 32 end

    # @return [Integer] nonce size in bytes
    def self.nonce_size() 8 end

    attr_reader :key, :nonce, :block

    def initialize(key, nonce)
      @key_words = expand_key(key).unpack("V*")
      raise "unsupported nonce size" if nonce.bytesize != self.class.nonce_size
      @nonce_words = nonce.unpack("V*")
    end

    # Returns an output block.
    # @param count [Integer] block number
    # @return [Array<Integer>] output block
    def block(count)
      new_input_block(count)
      hash
    end

    # @abstract
    def rounds
      raise NotImplementedError
    end

    private

    # Expands 16-byte and 10-byte keys to a 32-byte key and sets the Salsa
    # constant accordingly.
    # @param key [String] key which is shorter than 32 byte
    # @return [String] expanded key
    def expand_key(key)
      case key.bytesize
      when 32
        @constant = SALSA_CONST32
        return key
      when 16
        @constant = SALSA_CONST16
        return key * 2
      when 10
        @constant = SALSA_CONST10
        return "#{key}\0\0\0\0\0\0" * 2
      else
        raise "unsupported key length"
      end
    end

    # Prepares the input block for the next output block.
    # @param count [Integer] block number
    def new_input_block(count)
      k0, k1, k2, k3, k4, k5, k6, k7 = @key_words
      *, n0, n1 = @nonce_words
      c0, c1, c2, c3 = @constant
      b0, b1 = count & WORD, (count >> WORD_WIDTH) & WORD # block counter words
      @block = [
        c0, k0, k1, k2,
        k3, c1, n0, n1,
        b0, b1, c2, k4,
        k5, k6, k7, c3,
      ]
    end

    # Calculates the output block for the current input block.
    # @return [Array<Integer>] output block
    def hash
      original_block = @block.dup
      diffuse
      add_block(@block, original_block)
    end

    # Diffuses the current block using {#rounds}/2 double rounds.
    def diffuse
      (rounds/2).times { double_round }
    end

    # Compute double round (two rounds in one go). This avoids having to
    # transpose the block.
    def double_round
      # first column
      @block[ 4] ^= rotate_left(add(@block[ 0], @block[12]), 7)
      @block[ 8] ^= rotate_left(add(@block[ 4], @block[ 0]), 9)
      @block[12] ^= rotate_left(add(@block[ 8], @block[ 4]),13)
      @block[ 0] ^= rotate_left(add(@block[12], @block[ 8]),18)

      # second column
      @block[ 9] ^= rotate_left(add(@block[ 5], @block[ 1]), 7)
      @block[13] ^= rotate_left(add(@block[ 9], @block[ 5]), 9)
      @block[ 1] ^= rotate_left(add(@block[13], @block[ 9]),13)
      @block[ 5] ^= rotate_left(add(@block[ 1], @block[13]),18)

      # third column
      @block[14] ^= rotate_left(add(@block[10], @block[ 6]), 7)
      @block[ 2] ^= rotate_left(add(@block[14], @block[10]), 9)
      @block[ 6] ^= rotate_left(add(@block[ 2], @block[14]),13)
      @block[10] ^= rotate_left(add(@block[ 6], @block[ 2]),18)

      # fourth column
      @block[ 3] ^= rotate_left(add(@block[15], @block[11]), 7)
      @block[ 7] ^= rotate_left(add(@block[ 3], @block[15]), 9)
      @block[11] ^= rotate_left(add(@block[ 7], @block[ 3]),13)
      @block[15] ^= rotate_left(add(@block[11], @block[ 7]),18)

      # first row
      @block[ 1] ^= rotate_left(add(@block[ 0], @block[ 3]), 7)
      @block[ 2] ^= rotate_left(add(@block[ 1], @block[ 0]), 9)
      @block[ 3] ^= rotate_left(add(@block[ 2], @block[ 1]),13)
      @block[ 0] ^= rotate_left(add(@block[ 3], @block[ 2]),18)

      # second row
      @block[ 6] ^= rotate_left(add(@block[ 5], @block[ 4]), 7)
      @block[ 7] ^= rotate_left(add(@block[ 6], @block[ 5]), 9)
      @block[ 4] ^= rotate_left(add(@block[ 7], @block[ 6]),13)
      @block[ 5] ^= rotate_left(add(@block[ 4], @block[ 7]),18)

      # third row
      @block[11] ^= rotate_left(add(@block[10], @block[ 9]), 7)
      @block[ 8] ^= rotate_left(add(@block[11], @block[10]), 9)
      @block[ 9] ^= rotate_left(add(@block[ 8], @block[11]),13)
      @block[10] ^= rotate_left(add(@block[ 9], @block[ 8]),18)

      # fourth row
      @block[12] ^= rotate_left(add(@block[15], @block[14]), 7)
      @block[13] ^= rotate_left(add(@block[12], @block[15]), 9)
      @block[14] ^= rotate_left(add(@block[13], @block[12]),13)
      @block[15] ^= rotate_left(add(@block[14], @block[13]),18)
    end

    # Adds each word of one block to each word of another block using {#add}.
    # @param a [Array<Integer>] first block
    # @param b [Array<Integer>] second block
    # @return [Array<Integer>] resulting block
    def add_block(a, b)
      a.zip(b).map { |a, b| add(a, b) }
    end

    # Modular addition of two words.
    # @param a [Integer] first word
    # @param b [Integer] second word
    # @return [Integer] (a+b) mod({WORD})
    def add(a, b)
      (a + b) & WORD
    end


    # Rotates the bits of a word to the left.
    # @param word [Integer] word
    # @param n [Integer] rotation distance
    # @result [Integer] rotated word
    def rotate_left(word, n)
      ((word << n) | (word >> (WORD_WIDTH - n))) & WORD
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
