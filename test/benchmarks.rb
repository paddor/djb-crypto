require 'benchmark/ips'
require_relative '../lib/djb-crypto'

## from http://cr.yp.to/snuffle/salsafamily-20071225.pdf
TEST_KEY = (1..32).to_a.pack("C*")

SMALL_MSG = "abcd efgh ijkl mnop qrst uvwx xyz 123456"

# Salsa20
box20 = DjbCrypto::Box.new(TEST_KEY, DjbCrypto::Salsa2020)
msg20 = box20.decrypt(box20.encrypt(SMALL_MSG))
msg20 == SMALL_MSG or raise "Salsa20/20 broken"

box12 = DjbCrypto::Box.new(TEST_KEY, DjbCrypto::Salsa2012)
msg12 = box12.decrypt(box12.encrypt(SMALL_MSG))
msg12 == SMALL_MSG or raise "Salsa20/12 broken"

box8 = DjbCrypto::Box.new(TEST_KEY, DjbCrypto::Salsa208)
msg8 = box8.decrypt(box8.encrypt(SMALL_MSG))
msg8 == SMALL_MSG or raise "Salsa20/8 broken"

# XSalsa20
boxx20 = DjbCrypto::Box.new(TEST_KEY, DjbCrypto::XSalsa2020)
msgx20 = boxx20.decrypt(boxx20.encrypt(SMALL_MSG))
msgx20 == SMALL_MSG or raise "XSalsa20/20 broken"

boxx12 = DjbCrypto::Box.new(TEST_KEY, DjbCrypto::XSalsa2012)
msgx12 = boxx12.decrypt(boxx12.encrypt(SMALL_MSG))
msgx12 == SMALL_MSG or raise "XSalsa20/12 broken"

boxx8 = DjbCrypto::Box.new(TEST_KEY, DjbCrypto::XSalsa208)
msgx8 = boxx8.decrypt(boxx8.encrypt(SMALL_MSG))
msgx8 == SMALL_MSG or raise "XSalsa20/8 broken"

# ChaCha
boxcha20 = DjbCrypto::Box.new(TEST_KEY, DjbCrypto::ChaCha20)
msgcha20 = boxcha20.decrypt(boxcha20.encrypt(SMALL_MSG))
msgcha20 == SMALL_MSG or raise "ChaCha20 broken"

boxcha12 = DjbCrypto::Box.new(TEST_KEY, DjbCrypto::ChaCha12)
msgcha12 = boxcha12.decrypt(boxcha12.encrypt(SMALL_MSG))
msgcha12 == SMALL_MSG or raise "ChaCha12 broken"

boxcha8 = DjbCrypto::Box.new(TEST_KEY, DjbCrypto::ChaCha8)
msgcha8 = boxcha8.decrypt(boxcha8.encrypt(SMALL_MSG))
msgcha8 == SMALL_MSG or raise "ChaCha8 broken"


puts "SMALL MESSAGES"
puts "--------------"
puts "message size: #{SMALL_MSG.bytesize} bytes"
Benchmark.ips do |x|
  # Salsa20
  x.report("Salsa20/20") do
    box20.decrypt(box20.encrypt(SMALL_MSG))
  end
  x.report("Salsa20/12") do
    box12.decrypt(box12.encrypt(SMALL_MSG))
  end
  x.report("Salsa20/8") do
    box8.decrypt(box8.encrypt(SMALL_MSG))
  end

  # XSalsa20
  x.report("XSalsa20/20") do
    boxx20.decrypt(boxx20.encrypt(SMALL_MSG))
  end
  x.report("XSalsa20/12") do
    boxx12.decrypt(boxx12.encrypt(SMALL_MSG))
  end
  x.report("XSalsa20/8") do
    boxx8.decrypt(boxx8.encrypt(SMALL_MSG))
  end

  # ChaCha
  x.report("ChaCha20") do
    boxcha20.decrypt(boxcha20.encrypt(SMALL_MSG))
  end
  x.report("ChaCha12") do
    boxcha12.decrypt(boxcha12.encrypt(SMALL_MSG))
  end
  x.report("ChaCha8") do
    boxcha8.decrypt(boxcha8.encrypt(SMALL_MSG))
  end
end

puts
puts "LARGE MESSAGES"
puts "--------------"
LARGE_MSG = SMALL_MSG * 200
puts "message size: #{LARGE_MSG.bytesize} bytes"

Benchmark.ips do |x|
  x.report("Salsa20/20") do
    box20.decrypt(box20.encrypt(LARGE_MSG))
  end

  x.report("Salsa20/12") do
    box12.decrypt(box12.encrypt(LARGE_MSG))
  end

  x.report("Salsa20/8") do
    box8.decrypt(box8.encrypt(LARGE_MSG))
  end

  x.report("XSalsa20/20") do
    boxx20.decrypt(boxx20.encrypt(LARGE_MSG))
  end

  x.report("ChaCha20") do
    boxcha20.decrypt(boxcha20.encrypt(LARGE_MSG))
  end
end
