#define _XOPEN_SOURCE 700
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sodium.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <assert.h>


typedef struct bucket bucket_t;

typedef struct bucket bucket_t;
typedef uint64_t digest_t[(25 + sizeof(uint64_t) - 1) / sizeof(uint64_t)];


size_t equihash(uint32_t*, crypto_generichash_blake2b_state*);


int main(int argc, char** argv) {
    sodium_init();
    uint32_t t = strtoul(argv[1], NULL, 10);

    crypto_generichash_blake2b_state curr_state;
    crypto_generichash_blake2b_init(&curr_state, (const unsigned char*)"", 0, (512/200)*200/8);
    crypto_generichash_blake2b_update(&curr_state, (const uint8_t*)&t, 4);
    uint32_t indices[20*512];
    size_t n_solutions = equihash(indices, &curr_state);

    for(size_t i = 0; i < n_solutions; ++i) {
        for(size_t k = 0; k < 512; ++k) {
            printf("%u ", indices[i*512+k]);
        }

        printf("\n\n");
    }

    return 0;
}