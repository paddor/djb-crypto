require_relative '../lib/djb-crypto'

## from http://cr.yp.to/snuffle/salsafamily-20071225.pdf
#TEST_KEY = (1..32).to_a.pack("C*")
#TEST_NONCE = [ 3,1,4,1,5,9,2,6 ].pack("C*")
#TEST_CTR = 7
##(1..32).to_a.pack("C*").unpack("V*").map {|n| "0x%x" % n }
##=> ["0x4030201", "0x8070605", "0xc0b0a09", "0x100f0e0d", "0x14131211", "0x18171615", "0x1c1b1a19", "0x201f1e1d"]
#
#TEST_MSG = "abcd efg hijkl foo bar baz 1234 5678"
#
#
##salsa20 = DjbCrypto::Core.new(TEST_KEY, TEST_NONCE)
##salsa20.hash
#puts "TEST_MSG: #{TEST_MSG.bytesize}"
#puts "TEST_MSG size: #{TEST_MSG}"
#box = DjbCrypto::Box.new(TEST_KEY)
#ctx = box.encrypt(TEST_MSG)
#puts "cipher text size: #{ctx.bytesize}"
#puts "cipher text: #{ctx.dump}"
#
#box2 = DjbCrypto::Box.new(TEST_KEY)
#ptx = box2.decrypt(ctx)
#
#if ptx == TEST_MSG
#  puts "Salsa20: SAME!"
#else
#  puts "Salsa20: not the same :("
#end


puts
puts "ChaCha tests"
puts "============"
# ChaCha
# from http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7
ChaChaVectors = [
{
   KEY:       "00000000000000000000000000000000000000000000000000000000"\
              "00000000",
   NONCE:     "0000000000000000",
   KEYSTREAM: "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc"\
              "8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11c"\
              "c387b669b2ee6586"
},
{
   KEY:       "00000000000000000000000000000000000000000000000000000000"\
              "00000001",
   NONCE:     "0000000000000000",
   KEYSTREAM: "4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952"\
              "ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea81"\
              "7e9ad275ae546963"
},


{
   KEY:       "00000000000000000000000000000000000000000000000000000000"\
              "00000000",
   NONCE:     "0000000000000001",
   KEYSTREAM: "de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df1"\
              "37821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e"\
              "445f41e3"
},
{
   KEY:       "00000000000000000000000000000000000000000000000000000000"\
              "00000000",
   NONCE:     "0100000000000000",
   KEYSTREAM: "ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd1"\
              "38e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d"\
              "6bbdb0041b2f586b"
}
]

class String
  def hex2bin() [self].pack("H*") end
  def bin2hex() unpack("H*").first end
end

ChaChaVectors.each do |v|
  key, nonce = v[:KEY].hex2bin, v[:NONCE].hex2bin
  kstream = v[:KEYSTREAM].hex2bin

  stream = DjbCrypto::Stream.new(DjbCrypto::ChaCha20, key, nonce)
  kstream_is = stream.next_bytes(kstream.bytesize)
  if kstream_is == kstream
    puts "matched"
  else
    puts "didn't match"
    puts "should: #{kstream.bin2hex} (#{kstream.bytesize} bytes)"
    puts "    is: #{kstream_is.bin2hex} (#{kstream_is.bytesize} bytes)"
  end
  puts "-" * 50
end
