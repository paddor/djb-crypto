require 'forwardable'

module DjbCrypto

  # Used for secret key encryption.
  #
  # To use this box, you have to have your own nonce strategy. Unless you're
  # using XSalsa20, it's not considered safe to use randomly generated nonces.
  # If unsure about how to safely generate nonces, just use SimpleBox.
  class SecretBox
    extend Forwardable
    def_delegators :@cipher_class, :key_size, :nonce_size

    attr_reader :key

    def initialize(key=random_key, cipher_class=Salsa2020)
      @key = key
      @cipher_class = cipher_class
      raise "unsupported key size" if key.bytesize != key_size
    end

    # Boxes a message with an optional optional AAD.
    # @param nonce [String] the nonce used to seed the key stream
    # @param plain_text [String] the plain text
    # @param aad [String] additional authenticated data
    # @return [String] the cipher text with the authenticator tag appended
    def box(nonce, plain_text, aad = "")
      stream = @cipher_class.new(@key, nonce)
      cipher_text = stream ^ plain_text
      mac = MAC.new(stream, aad, cipher_text)
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
      stream = @cipher_class.new(@key, nonce)
      mac_should = MAC.new(stream, aad, cipher_text)
      tag_should = mac_should.tag

      raise "authenticator mismatch" if tag_should != tag_is
      return plain_text = stream ^ cipher_text
    end
    alias_method :decrypt, :open

    private

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
