require 'benchmark/ips'
require_relative '../lib/djb-crypto'

## from http://cr.yp.to/snuffle/salsafamily-20071225.pdf
TEST_KEY = (1..32).to_a.pack("C*")

SMALL_MSG = "abcd efgh ijkl mnop qrst uvwx xyz 123456"

# Salsa20
box20 = DjbCrypto::SecretBox.new(TEST_KEY, DjbCrypto::Salsa2020)
msg20 = box20.open(box20.box(SMALL_MSG))
msg20 == SMALL_MSG or raise "Salsa20/20 broken"

box12 = DjbCrypto::SecretBox.new(TEST_KEY, DjbCrypto::Salsa2012)
msg12 = box12.open(box12.box(SMALL_MSG))
msg12 == SMALL_MSG or raise "Salsa20/12 broken"

box8 = DjbCrypto::SecretBox.new(TEST_KEY, DjbCrypto::Salsa208)
msg8 = box8.open(box8.box(SMALL_MSG))
msg8 == SMALL_MSG or raise "Salsa20/8 broken"

# XSalsa20
boxx20 = DjbCrypto::SecretBox.new(TEST_KEY, DjbCrypto::XSalsa2020)
msgx20 = boxx20.open(boxx20.box(SMALL_MSG))
msgx20 == SMALL_MSG or raise "XSalsa20/20 broken"

boxx12 = DjbCrypto::SecretBox.new(TEST_KEY, DjbCrypto::XSalsa2012)
msgx12 = boxx12.open(boxx12.box(SMALL_MSG))
msgx12 == SMALL_MSG or raise "XSalsa20/12 broken"

boxx8 = DjbCrypto::SecretBox.new(TEST_KEY, DjbCrypto::XSalsa208)
msgx8 = boxx8.open(boxx8.box(SMALL_MSG))
msgx8 == SMALL_MSG or raise "XSalsa20/8 broken"

# ChaCha
boxcha20 = DjbCrypto::SecretBox.new(TEST_KEY, DjbCrypto::ChaCha20)
msgcha20 = boxcha20.open(boxcha20.box(SMALL_MSG))
msgcha20 == SMALL_MSG or raise "ChaCha20 broken"

boxcha12 = DjbCrypto::SecretBox.new(TEST_KEY, DjbCrypto::ChaCha12)
msgcha12 = boxcha12.open(boxcha12.box(SMALL_MSG))
msgcha12 == SMALL_MSG or raise "ChaCha12 broken"

boxcha8 = DjbCrypto::SecretBox.new(TEST_KEY, DjbCrypto::ChaCha8)
msgcha8 = boxcha8.open(boxcha8.box(SMALL_MSG))
msgcha8 == SMALL_MSG or raise "ChaCha8 broken"


puts "SMALL MESSAGES"
puts "=============="
puts "message size: #{SMALL_MSG.bytesize} bytes"
puts "encryption:"
puts "-----------"
Benchmark.ips do |x|
  # Salsa20
  x.report("Salsa20/20") do
    box20.box(SMALL_MSG)
  end
  x.report("Salsa20/12") do
    box12.box(SMALL_MSG)
  end
  x.report("Salsa20/8") do
    box8.box(SMALL_MSG)
  end

  # XSalsa20
  x.report("XSalsa20/20") do
    boxx20.box(SMALL_MSG)
  end
  x.report("XSalsa20/12") do
    boxx12.box(SMALL_MSG)
  end
  x.report("XSalsa20/8") do
    boxx8.box(SMALL_MSG)
  end

  # ChaCha
  x.report("ChaCha20") do
    boxcha20.box(SMALL_MSG)
  end
  x.report("ChaCha12") do
    boxcha12.box(SMALL_MSG)
  end
  x.report("ChaCha8") do
    boxcha8.box(SMALL_MSG)
  end
end

puts "decryption:"
puts "-----------"
Benchmark.ips do |x|
  # Salsa20
  msg = box20.box(SMALL_MSG)
  x.report("Salsa20/20") do
    box20.open(msg)
  end
  msg = box12.box(SMALL_MSG)
  x.report("Salsa20/12") do
    box12.open(msg)
  end
  msg = box8.box(SMALL_MSG)
  x.report("Salsa20/8") do
    box8.open(msg)
  end

  # XSalsa20
  msg = boxx20.box(SMALL_MSG)
  x.report("XSalsa20/20") do
    boxx20.open(msg)
  end
  msg = boxx12.box(SMALL_MSG)
  x.report("XSalsa20/12") do
    boxx12.open(msg)
  end
  msg = boxx8.box(SMALL_MSG)
  x.report("XSalsa20/8") do
    boxx8.open(msg)
  end

  # ChaCha
  msg = boxcha20.box(SMALL_MSG)
  x.report("ChaCha20") do
    boxcha20.open(msg)
  end
  msg = boxcha12.box(SMALL_MSG)
  x.report("ChaCha12") do
    boxcha12.open(msg)
  end
  msg = boxcha8.box(SMALL_MSG)
  x.report("ChaCha8") do
    boxcha8.open(msg)
  end
end

puts
puts "LARGE MESSAGES"
puts "=============="
LARGE_MSG = SMALL_MSG * 200
puts "message size: #{LARGE_MSG.bytesize} bytes"

puts "encryption:"
puts "-----------"
Benchmark.ips do |x|
  # Salsa20
  x.report("Salsa20/20") do
    box20.box(LARGE_MSG)
  end
  x.report("Salsa20/12") do
    box12.box(LARGE_MSG)
  end
  x.report("Salsa20/8") do
    box8.box(LARGE_MSG)
  end

  # XSalsa20
  x.report("XSalsa20/20") do
    boxx20.box(LARGE_MSG)
  end

  # ChaCha
  x.report("ChaCha20") do
    boxcha20.box(LARGE_MSG)
  end
end

puts "decryption:"
puts "-----------"
Benchmark.ips do |x|
  # Salsa20
  msg = box20.box(LARGE_MSG)
  x.report("Salsa20/20") do
    box20.open(msg)
  end
  msg = box12.box(LARGE_MSG)
  x.report("Salsa20/12") do
    box12.open(msg)
  end
  msg = box8.box(LARGE_MSG)
  x.report("Salsa20/8") do
    box8.open(msg)
  end

  # XSalsa20
  msg = boxx20.box(LARGE_MSG)
  x.report("XSalsa20/20") do
    boxx20.open(msg)
  end

  # ChaCha
  msg = boxcha20.box(LARGE_MSG)
  x.report("ChaCha20") do
    boxcha20.open(msg)
  end
end
