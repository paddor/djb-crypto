#include "salsa20.h"
#include <stdio.h>

// from http://cr.yp.to/salsa20.html
#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
void salsa20_hash_block_with_rounds(const uint8_t rounds,
		const uint32_t in[16], uint32_t out[16]) {

	uint8_t i;
	uint32_t x[16];
	for (i = 0; i < 16; ++i) x[i] = in[i];
	for (i = rounds; i > 0; i -= 2) {
		x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
		x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);
		x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
		x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);
		x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
		x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);
		x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
		x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);
		x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
		x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);
		x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
		x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);
		x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
		x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);
		x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
		x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
	}
	for (i = 0; i < 16; ++i) out[i] = x[i] + in[i];
}

void salsa20_hash_bytes_with_rounds(const uint8_t rounds,
		const uint32_t in[16], uint8_t out_bytes[64]) {

	uint32_t out_block[16];
	uint8_t i, j;
	salsa20_hash_block_with_rounds(rounds, in, out_block);
	i = 0;
	for(j=0; j<16; ++j) { // convert LE words to bytes
		out_bytes[i++] = out_block[j] >> 0;
		out_bytes[i++] = out_block[j] >> 8;
		out_bytes[i++] = out_block[j] >> 16;
		out_bytes[i++] = out_block[j] >> 24;
	}
}

// with rounds and initialized counter
void salsa20_hash_xor_with_rounds_ic(
		const uint8_t rounds,
		const uint8_t key[32],
		const uint64_t nonce,
		size_t mlen,
		const uint8_t *msg,
		uint8_t *ct,
		uint64_t counter) {

	uint32_t *k = (uint32_t*) key;
	uint32_t block[16] = {
	salsa20_c32[0],           k[0],           k[1],           k[2],
		  k[3], salsa20_c32[1],          nonce,      nonce>>32,
		     0,              0, salsa20_c32[2],           k[4],
		  k[5],           k[6],           k[7], salsa20_c32[3]
	};

	uint8_t i; // will only hold values 0..63
	uint8_t out[64];

	while(mlen > 64) {
		block[8] = counter & 0xffffffff;
		block[9] = counter >> 32;
		salsa20_hash_bytes_with_rounds(rounds, block, out);
		for(i=0; i<64; ++i) ct[i] = msg[i] ^ out[i];

		mlen -= 64;
		msg += 64;
		ct += 64;
		++counter;
	}


	if (mlen) {
		block[8] = counter & 0xffffffff;
		block[9] = counter >> 32;
		salsa20_hash_bytes_with_rounds(rounds, block, out);
		for(i=0; i < mlen; ++i) ct[i] = msg[i] ^ out[i];
	}
}

// starts at counter = 1
// useful because usually the very first block is used to derive the MAC key
void salsa20_hash_xor_with_rounds(
		const uint8_t rounds,
		const uint8_t key[32],
		const uint64_t nonce,
		size_t mlen,
		const uint8_t *msg,
		uint8_t *ct
		) {

	salsa20_hash_xor_with_rounds_ic(rounds, key, nonce, mlen, msg, ct, 1);
}

uint8_t* salsa20_first_bytes_with_rounds(
		uint8_t rounds,
		const uint8_t key[32],
		const uint64_t nonce,
		size_t nbytes
		) {

	uint8_t *ct = calloc(nbytes, sizeof(uint8_t));
	assert(ct);
	salsa20_hash_xor_with_rounds_ic(rounds, key, nonce, nbytes, ct, ct, 0);
	return ct;
}

// Salsa20/20
void salsa20_hash_xor(
		const uint8_t key[32],
		const uint64_t nonce,
		size_t mlen,
		const uint8_t *msg,
		uint8_t *ct
		) {
	salsa20_hash_xor_with_rounds(20, key, nonce, mlen, msg, ct);
}

// Salsa20/12
void salsa2012_hash_xor(
		const uint8_t key[32],
		const uint64_t nonce,
		size_t mlen,
		const uint8_t *msg,
		uint8_t *ct
		) {
	salsa20_hash_xor_with_rounds(12, key, nonce, mlen, msg, ct);
}

// Salsa20/8
void salsa208_hash_xor(
		const uint8_t key[32],
		const uint64_t nonce,
		size_t mlen,
		const uint8_t *msg,
		uint8_t *ct
		) {
	salsa20_hash_xor_with_rounds(8, key, nonce, mlen, msg, ct);
}

// Salsa20/20
uint8_t* salsa20_first_bytes(
		const uint8_t key[32],
		const uint64_t nonce,
		size_t nbytes
		) {
	return salsa20_first_bytes_with_rounds(20, key, nonce, nbytes);
}

// Salsa20/12
uint8_t* salsa2012_first_bytes(
		const uint8_t key[32],
		const uint64_t nonce,
		size_t nbytes
		) {
	return salsa20_first_bytes_with_rounds(12, key, nonce, nbytes);
}

// Salsa20/8
uint8_t* salsa208_first_bytes(
		const uint8_t key[32],
		const uint64_t nonce,
		size_t nbytes
		) {
	return salsa20_first_bytes_with_rounds(8, key, nonce, nbytes);
}
