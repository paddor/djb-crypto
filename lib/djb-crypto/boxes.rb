require 'forwardable'

module DjbCrypto
  class Stream
    # number of usable blocks
    MAX = 2**64 - 1

    def initialize(hash_class, key, nonce)
      @hasher = hash_class.new(key, nonce)
      @enumerator = Enumerator.new(MAX) do |stream|
        0.upto(MAX) do |counter|
          @hasher.block(counter).each { |word| stream << word }
        end
      end
    end

    # Gets the given number of bytes in the key stream.
    # @return [Array<Integer>] next n bytes of key stream
    def next_bytes(n)
      # whole words
      bytes = (0...n/4).map{ @enumerator.next }.flatten.pack("V*").unpack("C*")

      # remaining bytes
      if (remaining = n % 4) != 0
        bytes << @enumerator.next.pack("V").byteslice(0, remaining).unpack("C*")
      end

      return bytes
    end

    # @param msg [String] message to XOR
    # @return [String] result of XOR-ing
    def ^(msg)
      # whole words (4 bytes each)
      x = msg.unpack("V*").map { |mb| mb ^ @enumerator.next }.pack("V*")

      # remaining bytes
      if (remaining = msg.bytesize % 4) != 0
        kstream_bytes = @enumerator.next.pack("V").unpack("C*")
        msg_bytes = msg.byteslice(-remaining .. -1).unpack("C*")
        x << msg_bytes.zip(kstream_bytes).map { |m,k| m ^ k }.pack("C*")
      end

      return x
    end
  end

  # Used for secret key encryption.
  class SecretBox
    extend Forwardable
    def_delegators :@hash_class, :key_size, :nonce_size

    attr_reader :key

    def initialize(key=random_key, hash_class=Salsa2020)
      @key = key
      @hash_class = hash_class
      raise "unsupported key size" if key.bytesize != key_size
    end

    def box(nonce, plain_text)
      new_stream(nonce) ^ plain_text
    end
    alias_method :encrypt, :box

    def open(nonce, cipher_text)
      new_stream(nonce) ^ cipher_text
    end
    alias_method :decrypt, :open

    private

    def new_stream(nonce)
      Stream.new(@hash_class, @key, nonce)
    end

    def random_key
      SecureRandom.random_bytes(key_size)
    end
  end

  # Provides sane defaults for users who have no croptography knowledge.
  class SimpleBox < SecretBox
    # Uses XSalsa20 as encryption algorithm, because we have to use random
    # nonces. Thanks to the large nonce size of XSalsa20, that's safe.
    def initialize
      super(random_key, XSalsa2020)
    end

    def box(msg)
      nonce = random_nonce
      cipher_text = super(nonce, msg)
      "#{nonce}#{cipher_text}"
    end

    def open(boxed_msg)
      nonce = boxed_msg.byteslice(0, nonce_size)
      cipher_text = boxed_msg.byteslice(nonce_size..-1)
      super(nonce, cipher_text)
    end

    private

    def random_nonce
      SecureRandom.random_bytes(nonce_size)
    end
  end
end
