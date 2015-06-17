#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>
#include <assert.h>

// Salsa20 constant for 32 byte keys
static const uint32_t salsa20_c32[] =
  { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

// Salsa20/20
void salsa20_hash_xor(
		const uint8_t key[32],
		const uint64_t nonce,
		size_t mlen,
		const uint8_t *msg,
		uint8_t *ct
		);

// Salsa20/12
void salsa2012_hash_xor(
		const uint8_t key[32],
		const uint64_t nonce,
		size_t mlen,
		const uint8_t *msg,
		uint8_t *ct
		);

// Salsa20/8
void salsa208_hash_xor(
		const uint8_t key[32],
		const uint64_t nonce,
		size_t mlen,
		const uint8_t *msg,
		uint8_t *ct
		);

// Salsa20/20
uint8_t* salsa20_first_bytes(
		const uint8_t key[32],
		const uint64_t nonce,
		size_t nbytes
		);

// Salsa20/12
uint8_t* salsa2012_first_bytes(
		const uint8_t key[32],
		const uint64_t nonce,
		size_t nbytes
		);

// Salsa20/8
uint8_t* salsa208_first_bytes(
		const uint8_t key[32],
		const uint64_t nonce,
		size_t nbytes
		);
