require 'benchmark/ips'
require 'securerandom'
require_relative '../lib/djb-crypto'

## from http://cr.yp.to/snuffle/salsafamily-20071225.pdf
TEST_KEY = (1..32).to_a.pack("C*")

SMALL_MSG = "abcd efgh ijkl mnop qrst uvwx xyz 123456"

# Salsa20
box20 = DjbCrypto::SecretBox.new(TEST_KEY, DjbCrypto::Salsa2020)
nonce = SecureRandom.random_bytes(8)
msg20 = box20.open(nonce, box20.box(nonce, SMALL_MSG))
msg20 == SMALL_MSG or raise "Salsa20/20 broken"

box12 = DjbCrypto::SecretBox.new(TEST_KEY, DjbCrypto::Salsa2012)
nonce = SecureRandom.random_bytes(8)
msg12 = box12.open(nonce, box12.box(nonce, SMALL_MSG))
msg12 == SMALL_MSG or raise "Salsa20/12 broken"

box8 = DjbCrypto::SecretBox.new(TEST_KEY, DjbCrypto::Salsa208)
nonce = SecureRandom.random_bytes(8)
msg8 = box8.open(nonce, box8.box(nonce, SMALL_MSG))
msg8 == SMALL_MSG or raise "Salsa20/8 broken"

# FFI:Salsa20
fbox20 = DjbCrypto::SecretBox.new(TEST_KEY, DjbCrypto::FFI::Salsa2020)
nonce = SecureRandom.random_bytes(8)
msg20 = fbox20.open(nonce, fbox20.box(nonce, SMALL_MSG))
msg20 == SMALL_MSG or raise "FFI::Salsa20/20 broken"

fbox12 = DjbCrypto::SecretBox.new(TEST_KEY, DjbCrypto::FFI::Salsa2012)
nonce = SecureRandom.random_bytes(8)
msg12 = fbox12.open(nonce, fbox12.box(nonce, SMALL_MSG))
msg12 == SMALL_MSG or raise "FFI::Salsa20/12 broken: message is #{msg12}"

fbox8 = DjbCrypto::SecretBox.new(TEST_KEY, DjbCrypto::FFI::Salsa208)
nonce = SecureRandom.random_bytes(8)
msg8 = fbox8.open(nonce, fbox8.box(nonce, SMALL_MSG))
msg8 == SMALL_MSG or raise "FFI::Salsa20/8 broken"

# interoperability check: Salsa20 and FFI::Salsa20
nonce = SecureRandom.random_bytes(8)
xmsg = fbox20.open(nonce, box20.box(nonce, SMALL_MSG))
xmsg == SMALL_MSG or raise "Salsa20<->FFI::Salsa20/20 interoperability broken"
xmsg = box20.open(nonce, fbox20.box(nonce, SMALL_MSG))
xmsg == SMALL_MSG or raise "Salsa20<->FFI::Salsa20/20 interoperability broken"

# XSalsa20
boxx20 = DjbCrypto::SecretBox.new(TEST_KEY, DjbCrypto::XSalsa2020)
nonce = SecureRandom.random_bytes(24)
msgx20 = boxx20.open(nonce, boxx20.box(nonce, SMALL_MSG))
msgx20 == SMALL_MSG or raise "XSalsa20/20 broken"

boxx12 = DjbCrypto::SecretBox.new(TEST_KEY, DjbCrypto::XSalsa2012)
nonce = SecureRandom.random_bytes(24)
msgx12 = boxx12.open(nonce, boxx12.box(nonce, SMALL_MSG))
msgx12 == SMALL_MSG or raise "XSalsa20/12 broken"

boxx8 = DjbCrypto::SecretBox.new(TEST_KEY, DjbCrypto::XSalsa208)
nonce = SecureRandom.random_bytes(24)
msgx8 = boxx8.open(nonce, boxx8.box(nonce, SMALL_MSG))
msgx8 == SMALL_MSG or raise "XSalsa20/8 broken"

# ChaCha
boxcha20 = DjbCrypto::SecretBox.new(TEST_KEY, DjbCrypto::ChaCha20)
nonce = SecureRandom.random_bytes(8)
msgcha20 = boxcha20.open(nonce, boxcha20.box(nonce, SMALL_MSG))
msgcha20 == SMALL_MSG or raise "ChaCha20 broken"

boxcha12 = DjbCrypto::SecretBox.new(TEST_KEY, DjbCrypto::ChaCha12)
nonce = SecureRandom.random_bytes(8)
msgcha12 = boxcha12.open(nonce, boxcha12.box(nonce, SMALL_MSG))
msgcha12 == SMALL_MSG or raise "ChaCha12 broken"

boxcha8 = DjbCrypto::SecretBox.new(TEST_KEY, DjbCrypto::ChaCha8)
nonce = SecureRandom.random_bytes(8)
msgcha8 = boxcha8.open(nonce, boxcha8.box(nonce, SMALL_MSG))
msgcha8 == SMALL_MSG or raise "ChaCha8 broken"


puts "SMALL MESSAGES"
puts "=============="
puts "message size: #{SMALL_MSG.bytesize} bytes"
puts "encryption:"
puts "-----------"
Benchmark.ips do |x|
  nonce8 = SecureRandom.random_bytes(8)
  nonce24 = SecureRandom.random_bytes(24)

  # FFI::Salsa20
  x.report("FFI::Salsa20/20") do
    fbox20.box(nonce8, SMALL_MSG)
  end
  x.report("FFI::Salsa20/12") do
    fbox12.box(nonce8, SMALL_MSG)
  end
  x.report("FFI::Salsa20/8") do
    fbox8.box(nonce8, SMALL_MSG)
  end

  # Salsa20
  nonce = SecureRandom.random_bytes(8)
  x.report("Salsa20/20") do
    box20.box(nonce8, SMALL_MSG)
  end
  x.report("Salsa20/12") do
    box12.box(nonce8, SMALL_MSG)
  end
  x.report("Salsa20/8") do
    box8.box(nonce8, SMALL_MSG)
  end

  # XSalsa20
  x.report("XSalsa20/20") do
    boxx20.box(nonce24, SMALL_MSG)
  end
  x.report("XSalsa20/12") do
    boxx12.box(nonce24, SMALL_MSG)
  end
  x.report("XSalsa20/8") do
    boxx8.box(nonce24, SMALL_MSG)
  end

  # ChaCha
  x.report("ChaCha20") do
    boxcha20.box(nonce8, SMALL_MSG)
  end
  x.report("ChaCha12") do
    boxcha12.box(nonce8, SMALL_MSG)
  end
  x.report("ChaCha8") do
    boxcha8.box(nonce8, SMALL_MSG)
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
  nonce8 = SecureRandom.random_bytes(8)
  nonce24 = SecureRandom.random_bytes(24)

  # Salsa20
  x.report("Salsa20/20") do
    box20.box(nonce8, LARGE_MSG)
  end
  x.report("Salsa20/12") do
    box12.box(nonce8, LARGE_MSG)
  end
  x.report("Salsa20/8") do
    box8.box(nonce8, LARGE_MSG)
  end

  # XSalsa20
  x.report("XSalsa20/20") do
    boxx20.box(nonce24, LARGE_MSG)
  end

  # ChaCha
  x.report("ChaCha20") do
    boxcha20.box(nonce8, LARGE_MSG)
  end
end
