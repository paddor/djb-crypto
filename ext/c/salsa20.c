#include "salsa20.h"

// from http://cr.yp.to/salsa20.html
#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
void salsa20_hash_block(uint8_t num_rounds, uint64_t counter,
		uint32_t in[16], uint32_t out[16]) {

	uint8_t i;
	uint32_t x[16];
	in[8] = counter & 0xffffffff;
	in[9] = counter >> 32;
	for (i = 0; i < 16; ++i) x[i] = in[i];
	for (i = num_rounds; i > 0; i -= 2) {
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

void salsa20_hash_bytes(uint8_t num_rounds, uint64_t counter,
		uint32_t in[16], uint8_t out_bytes[64]) {

	uint32_t out_block[16];
	uint8_t i, j;
	salsa20_hash_block(num_rounds, counter, in, out_block);
	i = 0;
	for(j=0; j<16; ++j) { // convert LE words to bytes
		out_bytes[i++] = out_block[j] >> 0;
		out_bytes[i++] = out_block[j] >> 8;
		out_bytes[i++] = out_block[j] >> 16;
		out_bytes[i++] = out_block[j] >> 24;
	}
}

void salsa20_hash_xor(uint8_t num_rounds, uint32_t in[16],
		size_t mlen, const uint8_t *msg, uint8_t *xor_msg) {

	uint8_t i; // will only hold values 0..63
	uint64_t counter = 1;
	uint8_t out[64];

	while(mlen > 64) {
		salsa20_hash_bytes(num_rounds, counter, in, out);
		for(i=0; i<64; ++i) xor_msg[i] = msg[i] ^ out[i];

		mlen -= 64;
		msg += 64;
		xor_msg += 64;
		++counter;
	}


	if (mlen) {
		salsa20_hash_bytes(num_rounds, counter, in, out);
		for(i=0; i < mlen; ++i) xor_msg[i] = msg[i] ^ out[i];
	}
}

void salsa20_first_bytes(uint8_t num_rounds, uint32_t in[16],
		size_t len, uint8_t *bytes) {

	uint64_t counter = 0;
	size_t i = 0;
	uint8_t out[64];

	while (len > 64) {
		salsa20_hash_bytes(num_rounds, counter, in, bytes);
		len -= 64;
		bytes += 64;
		++counter;
	}

	if (len) {
		salsa20_hash_bytes(num_rounds, counter, in, out);
		for(i=0; i < len; ++i) bytes[i] = out[i];
	}
}
