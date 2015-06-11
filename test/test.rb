require_relative '../lib/djb-crypto'

## from http://cr.yp.to/snuffle/salsafamily-20071225.pdf
TEST_KEY = (1..32).to_a.pack("C*")
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
#
#
#
#box = DjbCrypto::Box.new(TEST_KEY, DjbCrypto::XSalsa2020)
#ctx = box.encrypt(TEST_MSG)
#puts "cipher text size: #{ctx.bytesize}"
#puts "cipher text: #{ctx.dump}"
#ptx = box.decrypt(ctx)
#if ptx == TEST_MSG
#  puts "XSalsa20: SAME!"
#else
#  puts "XSalsa20: not the same :("
#end



require 'benchmark/ips'

msg = "abcd efgh ijkl mnop qrst uvwx xyz 123456"
puts "original msg: #{msg}"

# Salsa20
box20 = DjbCrypto::Box.new(TEST_KEY, DjbCrypto::Salsa2020)
msg20 = box20.decrypt(box20.encrypt(msg))
msg20 == msg or raise "Salsa20/20 broken"

box12 = DjbCrypto::Box.new(TEST_KEY, DjbCrypto::Salsa2012)
msg12 = box12.decrypt(box12.encrypt(msg))
msg12 == msg or raise "Salsa20/12 broken"

box8 = DjbCrypto::Box.new(TEST_KEY, DjbCrypto::Salsa208)
msg8 = box8.decrypt(box8.encrypt(msg))
msg8 == msg or raise "Salsa20/8 broken"

# XSalsa20
boxx20 = DjbCrypto::Box.new(TEST_KEY, DjbCrypto::XSalsa2020)
msgx20 = boxx20.decrypt(boxx20.encrypt(msg))
msgx20 == msg or raise "XSalsa20/20 broken"

boxx12 = DjbCrypto::Box.new(TEST_KEY, DjbCrypto::XSalsa2012)
msgx12 = boxx12.decrypt(boxx12.encrypt(msg))
msgx12 == msg or raise "XSalsa20/12 broken"

boxx8 = DjbCrypto::Box.new(TEST_KEY, DjbCrypto::XSalsa208)
msgx8 = boxx8.decrypt(boxx8.encrypt(msg))
msgx8 == msg or raise "XSalsa20/8 broken"

# ChaCha
boxcha20 = DjbCrypto::Box.new(TEST_KEY, DjbCrypto::ChaCha20)
msgcha20 = boxcha20.decrypt(boxcha20.encrypt(msg))
msgcha20 == msg or raise "ChaCha20 broken"

boxcha12 = DjbCrypto::Box.new(TEST_KEY, DjbCrypto::ChaCha12)
msgcha12 = boxcha12.decrypt(boxcha12.encrypt(msg))
msgcha12 == msg or raise "ChaCha12 broken"

boxcha8 = DjbCrypto::Box.new(TEST_KEY, DjbCrypto::ChaCha8)
msgcha8 = boxcha8.decrypt(boxcha8.encrypt(msg))
msgcha8 == msg or raise "ChaCha8 broken"


puts
puts "SMALL MESSAGES"
puts "--------------"
puts "message size: #{msg.bytesize} bytes"
Benchmark.ips do |x|
  # Salsa20
  x.report("Salsa20/20") do
    box20.decrypt(box20.encrypt(msg))
  end
  x.report("Salsa20/12") do
    box12.decrypt(box12.encrypt(msg))
  end
  x.report("Salsa20/8") do
    box8.decrypt(box8.encrypt(msg))
  end

  # XSalsa20
  x.report("XSalsa20/20") do
    boxx20.decrypt(boxx20.encrypt(msg))
  end
  x.report("XSalsa20/12") do
    boxx12.decrypt(boxx12.encrypt(msg))
  end
  x.report("XSalsa20/8") do
    boxx8.decrypt(boxx8.encrypt(msg))
  end

  # ChaCha
  x.report("ChaCha20") do
    boxcha20.decrypt(boxcha20.encrypt(msg))
  end
  x.report("ChaCha12") do
    boxcha12.decrypt(boxcha12.encrypt(msg))
  end
  x.report("ChaCha8") do
    boxcha8.decrypt(boxcha8.encrypt(msg))
  end
end

msg *= 200
puts
puts "LARGE MESSAGES"
puts "--------------"
puts "message size: #{msg.bytesize} bytes"
Benchmark.ips do |x|
  x.report("Salsa20/20") do
    box20.decrypt(box20.encrypt(msg))
  end

  x.report("Salsa20/12") do
    box12.decrypt(box12.encrypt(msg))
  end

  x.report("Salsa20/8") do
    box8.decrypt(box8.encrypt(msg))
  end

  x.report("XSalsa20/20") do
    boxx20.decrypt(boxx20.encrypt(msg))
  end

  x.report("ChaCha20") do
    boxcha20.decrypt(boxcha20.encrypt(msg))
  end
end
