#include <inttypes.h>
#include <stddef.h>

void salsa20_hash_block(uint8_t num_rounds, uint64_t counter,
		uint32_t in[16], uint32_t out[16]);
void salsa20_hash_bytes(uint8_t num_rounds, uint64_t counter,
		uint32_t in[16], uint8_t out[64]);
void salsa20_hash_xor(uint8_t num_rounds, uint32_t in[16],
		size_t mlen, const uint8_t *msg, uint8_t *xor_msg);
void salsa20_first_bytes(uint8_t num_rounds, uint32_t in[16],
		size_t len, uint8_t *bytes);
