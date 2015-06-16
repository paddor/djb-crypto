module DjbCrypto
  # Common functionality for all stream ciphers.
  class StreamCipher

    # counter of the last usable block
    MAX = 2**64 - 1

    # Gets the first n bytes of the key stream.
    # @return [String] first n bytes of key stream
    def first_bytes(n)
      raise "keystream wrap-around" if n/4 + (n%4==0 ? 0 : 1) > MAX
      stream = stream_enumerator

      # whole words
      bytes = (n/4).times.map{ stream.next }.pack("V*")

      # remaining bytes
      if (remaining = n % 4) != 0
        bytes << stream.next.pack("V").byteslice(0, remaining)
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
          block(counter).each { |word| stream << word }
        end
      end
    end
  end
end
