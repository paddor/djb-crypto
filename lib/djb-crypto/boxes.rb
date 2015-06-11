module DjbCrypto
  class Stream
    MAX = 2**64 - 1 # only first 2^64 blocks of the stream are usable

    def initialize(hash_class, key, nonce)
      @hasher = hash_class.new(key, nonce)
      @enumerator = Enumerator.new(MAX) do |stream|
        0.upto(MAX) do |counter|
          stream << @hasher.block(counter)
        end
      end
    end

    def next_block
      @enumerator.next
    end
  end

  class Box
    attr_reader :key

    def initialize(key=random_key, hash_class=Salsa2020)
      @key = key
      @hash_class = hash_class
      raise "unsupported key length" if key.bytesize != key_size
    end

    def encrypt(msg)
      nonce = random_nonce
      cipher_text = crypt(msg, new_stream(nonce))
      "#{nonce}#{cipher_text}"
    end

    def decrypt(msg)
      nonce = msg.byteslice(0, nonce_size)
      msg = msg.byteslice(nonce_size..-1)
      crypt(msg, new_stream(nonce))
    end

    private

    def crypt(msg, cipher_stream)
      msg.bytes.each_slice(64).map do |msg_block|
        cipher_block = cipher_stream.next_block.bytes
        msg_block.zip(cipher_block).map { |m,c| m ^ c }
      end.flatten.
      pack("C*")
    end

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
  class SimpleBox < Box
    def initialize
      super(random_key, Salsa2020)
    end
  end
end
