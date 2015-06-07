require_relative '../lib/djb-crypto'

TEST_KEY = (1..32).to_a.pack("C*")
TEST_NONCE = [ 3,1,4,1,5,9,2,6 ].pack("C*")
TEST_CTR = 7
#(1..32).to_a.pack("C*").unpack("V*").map {|n| "0x%x" % n }
#=> ["0x4030201", "0x8070605", "0xc0b0a09", "0x100f0e0d", "0x14131211", "0x18171615", "0x1c1b1a19", "0x201f1e1d"]

TEST_MSG = "abcd efg hijkl foo bar baz 1234 5678"


#salsa20 = DjbCrypto::Core.new(TEST_KEY, TEST_NONCE)
#salsa20.hash
puts "TEST_MSG: #{TEST_MSG.bytesize}"
puts "TEST_MSG size: #{TEST_MSG}"
box = DjbCrypto::Box.new(TEST_KEY)
ctx = box.encrypt(TEST_MSG)
puts "cipher text size: #{ctx.bytesize}"
puts "cipher text: #{ctx.dump}"

box2 = DjbCrypto::Box.new(TEST_KEY)
ptx = box2.decrypt(ctx)

if ptx == TEST_MSG
  puts "Salsa20: SAME!"
else
  puts "Salsa20: not the same :("
end



box = DjbCrypto::Box.new(TEST_KEY, DjbCrypto::XSalsa20)
ctx = box.encrypt(TEST_MSG)
puts "cipher text size: #{ctx.bytesize}"
puts "cipher text: #{ctx.dump}"
ptx = box.decrypt(ctx)
if ptx == TEST_MSG
  puts "XSalsa20: SAME!"
else
  puts "XSalsa20: not the same :("
end



require 'benchmark/ips'

msg = "abcd efgh ijkl mnop qrst uvwx xyz 123456"
puts "original msg: #{msg}"

# Salsa20
box20 = DjbCrypto::Box.new(TEST_KEY, DjbCrypto::Salsa2020)
msg20 = box20.decrypt(box20.encrypt(msg))
puts "msg20: #{msg20}"
msg20 == msg or raise "box20 broken"

box12 = DjbCrypto::Box.new(TEST_KEY, DjbCrypto::Salsa2012)
msg12 = box12.decrypt(box12.encrypt(msg))
puts "msg12: #{msg12}"
msg12 == msg or raise "box12 broken"

box8 = DjbCrypto::Box.new(TEST_KEY, DjbCrypto::Salsa208)
msg8 = box8.decrypt(box8.encrypt(msg))
puts "msg8: #{msg8}"
msg8 == msg or raise "box8 broken"

# XSalsa20
boxx20 = DjbCrypto::Box.new(TEST_KEY, DjbCrypto::XSalsa20)
msgx20 = boxx20.decrypt(boxx20.encrypt(msg))
puts "msg20: #{msgx20}"
msgx20 == msg or raise "box20 broken"

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
end
