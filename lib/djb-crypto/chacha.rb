module DjbCrypto
  # Chacha20
  #
  # @see http://cr.yp.to/chacha/chacha-20080128.pdf
  class ChaChaCore < Salsa20Core
    private

    def new_input_block(count)
      k0, k1, k2, k3, k4, k5, k6, k7 = @key_words
      n0, n1 = @nonce_words
      c0, c1, c2, c3 = @constant
      b0, b1 = count & WORD, (count >> 32) & WORD # block counter words
      [
        c0, c1, c2, c3,
        k0, k1, k2, k3,
        k4, k5, k6, k7,
        b0, b1, n0, n1,
      ]
    end

    # Compute double round (two rounds in one go).
    def double_round
      quarter_round( 0, 4, 8,12) # first column
      quarter_round( 1, 5, 9,13) # second column
      quarter_round( 2, 6,10,14) # third column
      quarter_round( 3, 7,11,15) # fourth column
      quarter_round( 0, 5,10,15) # first diagonal
      quarter_round( 1, 6,11,12) # second diagonal
      quarter_round( 2, 7, 8,13) # third diagonal
      quarter_round( 3, 4, 9,14) # fourth diagonal
    end

    # Does one quarter round, involving the 4 numbers of a column or a
    # diagonal. The numbers are given by index within the block. The results
    # are stored back in the block at the same indexes.
    #
    # @param a_i [Integer] array-index of number a
    # @param b_i [Integer] array-index of number b
    # @param c_i [Integer] array-index of number c
    # @param d_i [Integer] array-index of number d
    def quarter_round(a_i, b_i, c_i, d_i)
      # save many calls to #[] and #[]=
      a, b, c, d = @block[a_i], @block[b_i], @block[c_i], @block[d_i]

      a = (a+b) & WORD; d = (d^a) & WORD; d = rotate_left(d, 16)
      c = (c+d) & WORD; b = (b^c) & WORD; b = rotate_left(b, 12)
      a = (a+b) & WORD; d = (d^a) & WORD; d = rotate_left(d,  8)
      c = (c+d) & WORD; b = (b^c) & WORD; b = rotate_left(b,  7)

      @block[a_i], @block[b_i], @block[c_i], @block[d_i] = a, b, c, d
    end
  end

  # Chacha20. Security: High.
  class ChaCha20 < ChaChaCore
    def rounds() 20 end
  end

  # ChaCha12 Security: Good.
  class ChaCha12 < ChaChaCore
    def rounds() 12 end
  end

  # ChaCha8. Security: Barely okay.
  class ChaCha8 < ChaChaCore
    def rounds() 8 end
  end
end
