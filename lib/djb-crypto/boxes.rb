module DjbCrypto
  class Stream
    # number of usable blocks
    MAX = 2**64 - 1

    def initialize(hash_class, key, nonce)
      @hasher = hash_class.new(key, nonce)
      @enumerator = Enumerator.new(MAX) do |stream|
        0.upto(MAX) do |counter|
          @hasher.block(counter).each_byte { |b| stream << b }
        end
      end
    end

    # Gets the given number of bytes in the key stream.
    # @return [Array<Integer>] next n bytes of key stream
    def next_bytes(n)
      (0...n).map { @enumerator.next }
    end

    # @param msg [String] message to XOR
    # @return [String] result of XOR-ing
    def xor(msg)
      msg.unpack("C*").map { |m_byte| m_byte ^ @enumerator.next }.pack("C*")
    end
  end

  # Used for secret key encryption.
  class SecretBox
    attr_reader :key

    def initialize(key=random_key, hash_class=Salsa2020)
      @key = key
      @hash_class = hash_class
      raise "unsupported key size" if key.bytesize != key_size
    end

    def box(plain_text, nonce=random_nonce)
      cipher_text = new_stream(nonce).xor(plain_text)
      "#{nonce}#{cipher_text}"
    end
    alias_method :encrypt, :box

    def open(boxed_msg)
      nonce = boxed_msg.byteslice(0, nonce_size)
      cipher_text = boxed_msg.byteslice(nonce_size..-1)
      new_stream(nonce).xor(cipher_text)
    end
    alias_method :decrypt, :open

    private

    def new_stream(nonce)
      Stream.new(@hash_class, @key, nonce)
    end

    def random_key
      SecureRandom.random_bytes(key_size)
    end

    def random_nonce
      SecureRandom.random_bytes(nonce_size)
    end

    def key_size
      @key_size ||= @hash_class.key_size
    end

    def nonce_size
      @nonce_size ||= @hash_class.nonce_size
    end
  end

  # Provides sane defaults for users who have no croptography knowledge.
  class SimpleBox < SecretBox
    def initialize
      super(random_key, Salsa2020)
    end

    def box(msg)
      super(msg)
    end
  end
end
