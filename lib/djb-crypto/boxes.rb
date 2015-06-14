require 'forwardable'

module DjbCrypto

  # Used internally to generate the keystream and XOR it with the
  # plaintext or ciphertext.
  class Stream

    # counter of the last usable block
    MAX = 2**64 - 1

    def initialize(hasher)
      @hasher = hasher
    end

    # Gets the first n bytes in the key stream.
    # @return [Array<Integer>] next n bytes of key stream
    def first_bytes(n)
      raise "keystream wrap-around" if n/4 + (n%4==0 ? 0 : 1) > MAX
      stream = stream_enumerator

      # whole words
      bytes = (n/4).times.map{ stream.next }.pack("V*").unpack("C*")

      # remaining bytes
      if (remaining = n % 4) != 0
        bytes << stream.next.pack("V").byteslice(0, remaining).unpack("C*")
      end

      return bytes
    end

    # we start XOR-ing at block 1 (not 0) because the very first block is used for key
    # generation for the authenticator
    XOR_OFFSET = 1

    # @param msg [String] message to XOR
    # @return [String] result of XOR-ing
    def ^(msg)
      stream = stream_enumerator(XOR_OFFSET)

      # whole words (4 bytes each)
      x = msg.unpack("V*").map { |mb| mb ^ stream.next }.pack("V*")

      # remaining bytes
      if (remaining = msg.bytesize % 4) != 0
        kstream_bytes = [stream.next].pack("V").unpack("C*")
        msg_bytes = msg.byteslice(-remaining .. -1).unpack("C*")
        x << msg_bytes.zip(kstream_bytes).map { |m,k| m ^ k }.pack("C*")
      end

      return x
    end

    private

    def stream_enumerator(offset = 0)
      Enumerator.new(MAX) do |stream|
        offset.upto(MAX) do |counter|
          @hasher.block(counter).each { |word| stream << word }
        end
      end
    end
  end

  # Used for secret key encryption.
  #
  # To use this box, you have to have your own nonce strategy. Unless you're
  # using XSalsa20, it's not considered safe to use randomly generated nonces.
  # If unsure about how to safely generate nonces, just use SimpleBox.
  class SecretBox
    extend Forwardable
    def_delegators :@hash_class, :key_size, :nonce_size

    attr_reader :key

    def initialize(key=random_key, hash_class=Salsa2020)
      @key = key
      @hash_class = hash_class
      raise "unsupported key size" if key.bytesize != key_size
    end

    # Boxes a message with an optional optional AAD.
    # @param nonce [String] the nonce used to seed the key stream
    # @param plain_text [String] the plain text
    # @param aad [String] additional authenticated data
    # @return [String] the cipher text with the authenticator tag appended
    def box(nonce, plain_text, aad = "")
      stream = new_stream(nonce)
      mac_key = stream.first_bytes(32).pack("C*")
      cipher_text = stream ^ plain_text
      mac = Poly1305.new(mac_key, Poly1305::Data.new(aad, cipher_text))
      "#{cipher_text}#{mac.tag}"
    end
    alias_method :encrypt, :box

    # Opens a boxed message with an optional optional AAD.
    # @param nonce [String] the nonce used to seed the key stream
    # @param cipher_text [String] the cipher text
    # @param aad [String] additional authenticated data
    # @return [String] the plain text, if it could be authenticated
    # @raise [RuntimeError] if cipher text couldn't be authenticated
    def open(nonce, cipher_text, aad = "")
      tag_is = cipher_text.byteslice(-16..-1)
      cipher_text = cipher_text.byteslice(0..-17)
      stream = new_stream(nonce)
      mac_key = stream.first_bytes(32).pack("C*")
      mac_should = Poly1305.new(mac_key, Poly1305::Data.new(aad, cipher_text))
      tag_should = mac_should.tag

      raise "authenticator mismatch" if tag_should != tag_is
      return plain_text = stream ^ cipher_text
    end
    alias_method :decrypt, :open

    private

    def new_stream(nonce)
      hasher = @hash_class.new(@key, nonce)
      Stream.new(hasher)
    end

    def random_key
      SecureRandom.random_bytes(key_size)
    end
  end

  # Provides sane defaults for users who have no croptography knowledge.
  #
  # Uses XSalsa20 as encryption algorithm, because we have to use random
  # nonces. Thanks to the large nonce size of XSalsa20, that's safe.
  #
  # {#box} prepends the nonce to the ciphertext. {#open} extracts it before
  # decrypting.
  class SimpleBox < SecretBox
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
