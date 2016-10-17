#define _XOPEN_SOURCE 700
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sodium.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <assert.h>

/*
    gcc-5 equihash-time.c thpool/thpool.c equihash-opt.c --pedantic -Wall -std=c11 -o time-equihash -lsodium -lpthread -ffast-math -pthread -D_POSIX_SOURCE -ggdb -pg -Ofast -march=native
*/

#define EQUIHASH_N 200
#define EQUIHASH_K 9

#define NUM_COLLISION_BITS (EQUIHASH_N / (EQUIHASH_K + 1))
#define NUM_INDICES (1 << EQUIHASH_K)

#define NUM_COMPRESSED_INDICE_BITS 16
#define NUM_DECOMPRESSED_INDICE_BITS (NUM_COLLISION_BITS+1)

#define NUM_VALUES (1 << (NUM_COLLISION_BITS+1))
#define NUM_ELEMENTS_BYTES_PER_BUCKET (1 << 9)
#define NUM_BUCKETS (1 << NUM_COLLISION_BITS)/NUM_ELEMENTS_BYTES_PER_BUCKET
#define DIGEST_SIZE 32


typedef struct element_indice {
    uint32_t a;
    uint32_t b;
} element_indice_t;

typedef struct element {
    uint64_t digest[3];
    uint32_t a;
    uint32_t b;
} element_t;

typedef struct bucket {
    uint64_t size;
    element_t data[NUM_ELEMENTS_BYTES_PER_BUCKET*3];
} bucket_t;

void hexout(unsigned char* digest_result) {
	for(unsigned i = 0; i < 4; ++i) {
		for(int j = 0; j < 8; ++j) {
			int c = digest_result[i*8 + j];
			////fprintf(stderr, "%2X", c);
		}
	}
    ////fprintf(stderr, "\n");
}

inline uint32_t mask_collision_bits(uint8_t* data, size_t start) {
    size_t byte_index = start / 8;
    size_t bit_index = start % 8;
    uint32_t n = ((data[byte_index] << (bit_index)) & 0xff) << 12;
    n |= ((data[byte_index+1]) << (bit_index+4));
    n |= ((data[byte_index+2]) >> (4-bit_index));
    return n;
}

inline uint32_t mask_collision_byte_bits_even(uint8_t* data) {
    return (data[0] << 12) | (data[1] << 4) | (data[2] >> 4);
}

inline uint32_t mask_collision_byte_bits_odd(uint8_t* data) {
    return (((data[0] << 4) & 0xff) << 12) | (data[1] << 8) | (data[2]);
}

inline uint32_t mask_collision_byte_bits_even_sub_bucket(uint8_t* data) {
    return (data[1] << 4) | (data[2] >> 4);
}


inline uint32_t mask_collision_byte_bits_odd_sub_bucket(uint8_t* data) {
    return (data[1] << 8) | (data[2]);
}



inline uint32_t mask_collision_byte_bits(uint8_t* data, size_t byte_index, size_t bit_index) {
    return (((data[byte_index] << (bit_index)) & 0xff) << 12)
            | ((data[byte_index+1]) << (bit_index+4))
            | ((data[byte_index+2]) >> (4-bit_index));
}

inline uint32_t mask_collision_byte_bits_final(uint8_t* data, size_t byte_index, size_t bit_index) {
    return (((data[byte_index] << (bit_index)) & 0xff) << 12)
            | ((data[byte_index+1]) << (bit_index+4));
}


int compare_indices32(uint32_t* a, uint32_t* b, size_t n_current_indices) {
    for(size_t i = 0; i < n_current_indices; ++i, ++a, ++b) {
        if(*a < *b) {
            return -1;
        } else if(*a > *b) {
            return 1;
        } else {
            return 0;
        }
    }
    return 0;
}

void normalize_indices(uint32_t* indices) {
    for(size_t step_index = 0; step_index < EQUIHASH_K; ++step_index) {
        for(size_t i = 0; i < NUM_INDICES; i += (1 << (step_index+1))) {
            if(compare_indices32(indices+i, indices+i+(1 << step_index), (1 << step_index)) > 0) {
                uint32_t tmp_indices[(1 << step_index)];
                memcpy(tmp_indices, indices+i, (1 << step_index)*sizeof(uint32_t));
                memcpy(indices+i, indices+i+(1 << step_index), (1 << step_index)*sizeof(uint32_t));
                memcpy(indices+i+(1 << step_index), tmp_indices, (1 << step_index)*sizeof(uint32_t));
            }
        }
    }
}


inline void xor_elements(uint64_t* dst, uint64_t* a, uint64_t* b) {
    dst[0] = a[0] ^ b[0];
    dst[1] = a[1] ^ b[1];
    dst[2] = a[2] ^ b[2];
    //dst[3] = a[3] ^ b[3];
}

inline void xor_elements_4_7(uint64_t* dst, uint64_t* a, uint64_t* b) {
    dst[1] = a[1] ^ b[1];
    dst[2] = a[2] ^ b[2];
    //dst[3] = a[3] ^ b[3];
}

inline void xor_elements_8(uint64_t* dst, uint64_t* a, uint64_t* b) {
    dst[2] = a[2] ^ b[2];
    //dst[3] = a[3] ^ b[3];
}


void hash(uint8_t* dst, uint32_t in, const crypto_generichash_blake2b_state* digest) {
    uint32_t tmp_in = in/2;
    crypto_generichash_blake2b_state new_digest = *digest;
    crypto_generichash_blake2b_update(&new_digest, (uint8_t*)&tmp_in, sizeof(uint32_t));
    crypto_generichash_blake2b_final(&new_digest, (uint8_t*)dst, 2*DIGEST_SIZE);
}


int is_indices_valid(uint32_t* indices, const crypto_generichash_blake2b_state* digest) {
    uint8_t digest_results[NUM_INDICES][DIGEST_SIZE];
    memset(digest_results, '\0', NUM_INDICES*DIGEST_SIZE);

    for(size_t i = 0; i < NUM_INDICES; ++i) {
        uint8_t digest_tmp[2*DIGEST_SIZE];
        hash(digest_tmp, indices[i], digest);
        memcpy(digest_results[i], digest_tmp+((indices[i] % 2)*EQUIHASH_N/8), DIGEST_SIZE);
    }

    for(size_t step_index = 0; step_index < EQUIHASH_K; ++step_index) {
        for(size_t i = 0; i < (NUM_INDICES >> step_index); i += 2) {
            uint8_t digest_tmp[DIGEST_SIZE];
            xor_elements(digest_tmp, digest_results[i], digest_results[i+1]);

            size_t start_bit = step_index*NUM_COLLISION_BITS;
            size_t byte_index = start_bit / 8;
            size_t bit_index = start_bit % 8;

            if(!mask_collision_bits(((uint8_t*)digest_tmp) + byte_index, bit_index) == 0) {
                return 0;
            }

            memcpy(digest_results[i / 2], digest_tmp, DIGEST_SIZE);
        }
    }

    size_t start_bit = EQUIHASH_K*NUM_COLLISION_BITS;
    size_t byte_index = start_bit / 8;
    size_t bit_index = start_bit % 8;
    return mask_collision_bits(((uint8_t*)digest_results[0]) + byte_index, bit_index) == 0;
}



uint32_t decompress_indices(uint32_t* dst_uncompressed_indices, element_indice_t** indices, uint32_t a, uint32_t b) {
    element_indice_t elements[EQUIHASH_K][NUM_INDICES];
    elements[0][0].a = a;
    elements[0][0].b = b;

    for(size_t i = 0; i < EQUIHASH_K-1; ++i) {
        for(size_t j = 0; j < (1 << i); ++j) {
            element_indice_t* src = elements[i] + j;
            elements[i+1][2*j] = indices[EQUIHASH_K-2-i][src->a];
            elements[i+1][2*j+1] = indices[EQUIHASH_K-2-i][src->b];
        }
    }

    uint32_t last_collision = 0;
    for(size_t j = 0; j < NUM_INDICES/2; ++j) {
        element_indice_t* src = elements[EQUIHASH_K-1] + j;
        *dst_uncompressed_indices = src->a;
        last_collision ^= src->b;
        dst_uncompressed_indices++;
    }
    return last_collision;
}

double get_tttime() {
    struct timeval ts;
    gettimeofday(&ts, NULL);
    return ts.tv_sec + ts.tv_usec / 1000000.0;
}


void initial_bucket_hashing(bucket_t* dst, const crypto_generichash_blake2b_state* digest) {
    size_t last_bit = ((EQUIHASH_K)*NUM_COLLISION_BITS);
    size_t last_byte = last_bit / 8;
    size_t last_rel_bit = last_bit % 8;

    double t = get_tttime();
    uint8_t new_digest[2*DIGEST_SIZE];
    memset(new_digest, '\0', 2*DIGEST_SIZE);
    element_t* tmp_dst_buckets[NUM_BUCKETS];
    for(uint32_t i = 0; i < NUM_BUCKETS; ++i) {
        tmp_dst_buckets[i] = (dst + i)->data;
    }



    for(uint32_t i = 0, c = 0; i < NUM_VALUES/2; ++i, c += 2) {
        crypto_generichash_blake2b_state current_digest = *digest;
        crypto_generichash_blake2b_update(&current_digest, (uint8_t*)&i, sizeof(uint32_t));
        crypto_generichash_blake2b_final(&current_digest, (uint8_t*)(new_digest), 50);

        {
            uint32_t new_index = mask_collision_byte_bits_even(new_digest+0) / NUM_ELEMENTS_BYTES_PER_BUCKET;
            element_t* new_el = tmp_dst_buckets[new_index]++;
            new_el->a = c;
            new_el->b = mask_collision_byte_bits(new_digest, last_byte, last_rel_bit);
            memcpy(new_el->digest, new_digest, 24);
        }

        {
            uint32_t new_index = mask_collision_byte_bits_even(new_digest+25+0) / NUM_ELEMENTS_BYTES_PER_BUCKET;
            element_t* new_el = tmp_dst_buckets[new_index]++;
            new_el->a = c+1;
            new_el->b = mask_collision_byte_bits(new_digest+25, last_byte, last_rel_bit);
            memcpy(new_el->digest, new_digest+25, 24);
        }
    }
    for(uint32_t i = 0; i < NUM_BUCKETS; ++i) {
        dst[i].size = ((uintptr_t)tmp_dst_buckets[i] - (uintptr_t)dst[i].data) / sizeof(element_t);
    }
    //fprintf(stderr, "init: %f\n", get_tttime()-t);
}

void collide_1_3(bucket_t* dst, bucket_t* src, element_indice_t* old_indices, size_t step_index) {
    size_t start_bit = ((step_index-1)*NUM_COLLISION_BITS);
    size_t start_byte = start_bit / 8;

    size_t last_bit = (step_index*NUM_COLLISION_BITS);
    size_t last_byte = last_bit / 8;

    size_t indice_index = 0;
    //double //tsort = 0;
    //double //tcollide = 0;
    double t3 = get_tttime();


    element_t* tmp_dst_buckets[NUM_BUCKETS];
    for(uint32_t i = 0; i < NUM_BUCKETS; ++i) {
        tmp_dst_buckets[i] = (dst + i)->data;
    }


    for(uint32_t i = 0; i < NUM_BUCKETS; ++i) {
        bucket_t* bucket = src + i;
        //double t1 = get_tttime();
        uint32_t sub_bucket_sizes[NUM_ELEMENTS_BYTES_PER_BUCKET];
        uint32_t sub_buckets[NUM_ELEMENTS_BYTES_PER_BUCKET][17][2];
        memset(sub_bucket_sizes, '\0', NUM_ELEMENTS_BYTES_PER_BUCKET*sizeof(uint32_t));
        element_t* bucket_data = ((uint8_t*)bucket->data) + start_byte;
        element_t* next_bucket_data = ((uint8_t*)bucket->data) + last_byte;


        if(step_index % 2 == 1) {
            for(uint32_t j = 0; j < bucket->size; ++j) {
                uint32_t sub_index = mask_collision_byte_bits_even_sub_bucket(bucket_data) % NUM_ELEMENTS_BYTES_PER_BUCKET;
                sub_buckets[sub_index][sub_bucket_sizes[sub_index]][0] = mask_collision_byte_bits_odd(next_bucket_data);
                sub_buckets[sub_index][sub_bucket_sizes[sub_index]][1] = j;
                bucket_data++;
                next_bucket_data++;
                sub_bucket_sizes[sub_index]++;
            }
        } else {
            for(uint32_t j = 0; j < bucket->size; ++j) {
                uint32_t sub_index = mask_collision_byte_bits_odd(bucket_data) % NUM_ELEMENTS_BYTES_PER_BUCKET;
                sub_buckets[sub_index][sub_bucket_sizes[sub_index]][0] = mask_collision_byte_bits_even(next_bucket_data);
                sub_buckets[sub_index][sub_bucket_sizes[sub_index]][1] = j;
                bucket_data++;
                next_bucket_data++;
                sub_bucket_sizes[sub_index]++;
            }
        }

        //double t2 = get_tttime();
        //////fprintf(stderr, "%u bucket->size: %u\n", step_index, bucket->size);
        //tsort += t2 - t1;
        for(uint32_t o = 0; o < NUM_ELEMENTS_BYTES_PER_BUCKET; ++o) {
            uint32_t sub_bucket_size = sub_bucket_sizes[o]*2;
            //////fprintf(stderr, "size: %u - %u\n", bucket->size, sub_bucket_size);

            if(sub_bucket_size <= 2) {
                continue;
            }

            uint32_t* sub_bucket_indices = sub_buckets[o];
            for(uint32_t j = 0; j < sub_bucket_size; j += 2) {
                uint32_t base_bits = sub_bucket_indices[j+0]; //mask_collision_bits(base->digest, last_bit);
                element_t* base = bucket->data + sub_bucket_indices[j+1];
                old_indices->a = base->a;
                old_indices->b = base->b;

                for(uint32_t k = j+2; k < sub_bucket_size; k += 2) {
                    uint32_t new_index = base_bits ^ sub_bucket_indices[k+0]; //mask_collision_bits(el->digest, last_bit);
                    if(__builtin_expect(new_index == 0, 0)) continue;

                    element_t* new_el = tmp_dst_buckets[new_index/NUM_ELEMENTS_BYTES_PER_BUCKET]++;
                    xor_elements(new_el->digest, base->digest, (bucket->data + sub_bucket_indices[k+1])->digest);
                    new_el->a = indice_index;
                    new_el->b = indice_index + (k-j)/2;
                }
                indice_index++;
                old_indices++;
            }
        }
        //return;
        //tcollide += (get_tttime()-t2);
    }
    //printf("here2\n");

    for(uint32_t i = 0; i < NUM_BUCKETS; ++i) {
        src[i].size = 0;
        dst[i].size = ((uintptr_t)tmp_dst_buckets[i] - (uintptr_t)dst[i].data) / sizeof(element_t); //tmp_dst_bucket_sizes[i];
    }

    double ttot = get_tttime() - t3;
    fprintf(stderr, "colliding %u: %f %u\n", 3, ttot, indice_index);
}


// idea: copy in segments of 2 at first then the rest
void collide_4_7(bucket_t* dst, bucket_t* src, element_indice_t* old_indices, size_t step_index) {
    size_t start_bit = ((step_index-1)*NUM_COLLISION_BITS);
    size_t start_byte = start_bit / 8;
    size_t start_rel_bit = start_bit % 8;

    size_t last_bit = ((step_index)*NUM_COLLISION_BITS);
    size_t last_byte = last_bit / 8;
    size_t last_rel_bit = last_bit % 8;

    size_t indice_index = 0;
    double tsort = 0;
    double tcollide = 0;
    double t3 = get_tttime();


    element_t* tmp_dst_buckets[NUM_BUCKETS];
    for(uint32_t i = 0; i < NUM_BUCKETS; ++i) {
        tmp_dst_buckets[i] = (dst + i)->data;
    }


    for(uint32_t i = 0; i < NUM_BUCKETS; ++i) {
        bucket_t* bucket = src + i;
        double t1 = get_tttime();
        uint32_t sub_bucket_sizes[NUM_ELEMENTS_BYTES_PER_BUCKET];
        uint32_t sub_buckets[NUM_ELEMENTS_BYTES_PER_BUCKET][17][2];
        memset(sub_bucket_sizes, '\0', NUM_ELEMENTS_BYTES_PER_BUCKET*sizeof(uint32_t));
        element_t* bucket_data = ((uint8_t*)bucket->data) + start_byte;
        element_t* next_bucket_data = ((uint8_t*)bucket->data) + last_byte;


        if(step_index % 2 == 1) {
            for(uint32_t j = 0; j < bucket->size; ++j) {
                uint32_t sub_index = mask_collision_byte_bits_even_sub_bucket(bucket_data) % NUM_ELEMENTS_BYTES_PER_BUCKET;
                sub_buckets[sub_index][sub_bucket_sizes[sub_index]][0] = mask_collision_byte_bits_odd(next_bucket_data);
                sub_buckets[sub_index][sub_bucket_sizes[sub_index]][1] = j;
                bucket_data++;
                next_bucket_data++;
                sub_bucket_sizes[sub_index]++;
            }
        } else {
            for(uint32_t j = 0; j < bucket->size; ++j) {
                uint32_t sub_index = mask_collision_byte_bits_odd(bucket_data) % NUM_ELEMENTS_BYTES_PER_BUCKET;
                sub_buckets[sub_index][sub_bucket_sizes[sub_index]][0] = mask_collision_byte_bits_even(next_bucket_data);
                sub_buckets[sub_index][sub_bucket_sizes[sub_index]][1] = j;
                bucket_data++;
                next_bucket_data++;
                sub_bucket_sizes[sub_index]++;
            }
        }

        double t2 = get_tttime();
        ////fprintf(stderr, "%u bucket->size: %u\n", step_index, bucket->size);
        tsort += t2 - t1;
        for(uint32_t o = 0; o < NUM_ELEMENTS_BYTES_PER_BUCKET; ++o) {
            uint32_t sub_bucket_size = sub_bucket_sizes[o]*2;
            if(sub_bucket_size <= 2) {
                continue;
            }
 
            uint32_t* sub_bucket_indices = sub_buckets[o];
            for(uint32_t j = 0; j < sub_bucket_size; j += 2) {
                uint32_t base_bits = sub_bucket_indices[j]; //mask_collision_bits(base->digest, last_bit);
                element_t* base = bucket->data + sub_bucket_indices[j+1];
                old_indices->a = base->a;
                old_indices->b = base->b;

                for(uint32_t k = j+2; k < sub_bucket_size; k += 2) {
                    uint32_t new_index = base_bits ^ sub_bucket_indices[k]; //mask_collision_bits(el->digest, last_bit);
                    if(__builtin_expect(new_index == 0, 0)) continue;
                    element_t* new_el = tmp_dst_buckets[new_index/NUM_ELEMENTS_BYTES_PER_BUCKET]++;
                    xor_elements_4_7(new_el->digest, base->digest, (bucket->data + sub_bucket_indices[k+1])->digest);
                    new_el->a = indice_index;
                    new_el->b = indice_index + (k-j)/2;
                }
                indice_index++;
                old_indices++;
            }
        }
        //return;
        tcollide += (get_tttime()-t2);
    }
    //printf("here2\n");

    for(uint32_t i = 0; i < NUM_BUCKETS; ++i) {
        src[i].size = 0;
        dst[i].size = ((uintptr_t)tmp_dst_buckets[i] - (uintptr_t)dst[i].data) / sizeof(element_t); //tmp_dst_bucket_sizes[i];
    }

    double ttot = get_tttime() - t3;
    fprintf(stderr, "colliding %u: %f %f %f %u\n", step_index, tsort, tcollide, ttot, indice_index);
}

// idea: copy in segments of 2 at first then the rest
void collide_8(bucket_t* dst, bucket_t* src, element_indice_t* old_indices, size_t step_index) {
    size_t start_bit = ((step_index-1)*NUM_COLLISION_BITS);
    size_t start_byte = start_bit / 8;
    size_t start_rel_bit = start_bit % 8;

    size_t last_bit = ((step_index)*NUM_COLLISION_BITS);
    size_t last_byte = last_bit / 8;
    size_t last_rel_bit = last_bit % 8;

    size_t indice_index = 0;
    //double //tsort = 0;
    //double //tcollide = 0;
    double t3 = get_tttime();


    element_t* tmp_dst_buckets[NUM_BUCKETS];
    for(uint32_t i = 0; i < NUM_BUCKETS; ++i) {
        tmp_dst_buckets[i] = (dst + i)->data;
    }


    for(uint32_t i = 0; i < NUM_BUCKETS; ++i) {
        bucket_t* bucket = src + i;
        //double t1 = get_tttime();
        uint32_t sub_bucket_sizes[NUM_ELEMENTS_BYTES_PER_BUCKET];
        uint32_t sub_buckets[NUM_ELEMENTS_BYTES_PER_BUCKET][17][2];
        memset(sub_bucket_sizes, '\0', NUM_ELEMENTS_BYTES_PER_BUCKET*sizeof(uint32_t));
        element_t* bucket_data = ((uint8_t*)bucket->data) + start_byte;
        element_t* next_bucket_data = ((uint8_t*)bucket->data) + last_byte;

        for(uint32_t j = 0; j < bucket->size; ++j) {
            uint32_t sub_index = mask_collision_byte_bits_odd_sub_bucket(bucket_data) % NUM_ELEMENTS_BYTES_PER_BUCKET;
            sub_buckets[sub_index][sub_bucket_sizes[sub_index]][0] = mask_collision_byte_bits_even(next_bucket_data);
            sub_buckets[sub_index][sub_bucket_sizes[sub_index]][1] = j;
            bucket_data++;
            next_bucket_data++;
            sub_bucket_sizes[sub_index]++;
        }

        //double t2 = get_tttime();
        //////fprintf(stderr, "%u bucket->size: %u\n", step_index, bucket->size);
        //tsort += t2 - t1;
        for(uint32_t o = 0; o < NUM_ELEMENTS_BYTES_PER_BUCKET; ++o) {
            uint32_t sub_bucket_size = sub_bucket_sizes[o]*2;
            if(sub_bucket_size <= 2) {
                continue;
            }

            uint32_t* sub_bucket_indices = sub_buckets[o];
            for(uint32_t j = 0; j < sub_bucket_size; j += 2) {
                uint32_t base_bits = sub_bucket_indices[j]; //mask_collision_bits(base->digest, last_bit);
                element_t* base = bucket->data + sub_bucket_indices[j+1];
                old_indices->a = base->a;
                old_indices->b = base->b;

                for(uint32_t k = j+2; k < sub_bucket_size; k += 2) {
                    uint32_t new_index = base_bits ^ sub_bucket_indices[k]; //mask_collision_bits(el->digest, last_bit);
                    if(__builtin_expect(new_index == 0, 0)) continue;

                    element_t* new_el = tmp_dst_buckets[new_index/NUM_ELEMENTS_BYTES_PER_BUCKET]++;
                    xor_elements_8(new_el->digest, base->digest, (bucket->data + sub_bucket_indices[k+1])->digest);
                    new_el->a = indice_index;
                    new_el->b = indice_index + (k-j)/2;
                }
                indice_index++;
                old_indices++;
            }
        }
        //tcollide += (get_tttime()-t2);
    }
    //printf("here2\n");

    for(uint32_t i = 0; i < NUM_BUCKETS; ++i) {
        src[i].size = 0;
        dst[i].size = ((uintptr_t)tmp_dst_buckets[i] - (uintptr_t)dst[i].data) / sizeof(element_t); //tmp_dst_bucket_sizes[i];
    }

    double ttot = get_tttime() - t3;
    fprintf(stderr, "colliding 8: %f %zu\n", ttot, indice_index);
}


size_t produce_solutions(uint32_t** solutions, bucket_t* src, element_indice_t** indices, size_t n_src_elements, const crypto_generichash_blake2b_state* digest) {
    size_t n_solutions = 0;
    size_t start_bit = ((EQUIHASH_K-1)*NUM_COLLISION_BITS);
    size_t start_byte = start_bit / 8;
    size_t start_rel_bit = start_bit % 8;

    size_t last_bit = ((EQUIHASH_K)*NUM_COLLISION_BITS);
    size_t last_byte = last_bit / 8;
    size_t last_rel_bit = last_bit % 8;

    size_t n_invalids = 0;
    //double //tsort = 0;
    //double //tcollide = 0;
    double t3 = get_tttime();

    uint8_t dupes[1 << NUM_COLLISION_BITS];
    memset(dupes, '\0', 1 << NUM_COLLISION_BITS);


    for(uint32_t i = 0; i < NUM_BUCKETS; ++i) {
        bucket_t* bucket = src + i;
        //double t1 = get_tttime();
        uint32_t sub_bucket_sizes[NUM_ELEMENTS_BYTES_PER_BUCKET];
        uint32_t sub_buckets[NUM_ELEMENTS_BYTES_PER_BUCKET][17][2];
        memset(sub_bucket_sizes, '\0', NUM_ELEMENTS_BYTES_PER_BUCKET*sizeof(uint32_t));
        element_t* bucket_data = bucket->data;
        for(uint16_t j = 0; j < bucket->size; ++j) {
            uint32_t sub_index = mask_collision_byte_bits(bucket_data->digest, start_byte, start_rel_bit) % NUM_ELEMENTS_BYTES_PER_BUCKET;
            sub_buckets[sub_index][sub_bucket_sizes[sub_index]][0] = mask_collision_byte_bits_final(bucket_data->digest, last_byte, last_rel_bit);
            sub_buckets[sub_index][sub_bucket_sizes[sub_index]][1] = j;
            bucket_data++;
            sub_bucket_sizes[sub_index]++;
        }

        //double t2 = get_tttime();
        //tsort += t2 - t1;
        for(uint32_t o = 0; o < NUM_ELEMENTS_BYTES_PER_BUCKET; ++o) {
            uint32_t sub_bucket_size = sub_bucket_sizes[o]*2;
            if(sub_bucket_size <= 2) {
                continue;
            }

            uint32_t* sub_bucket_indices = sub_buckets[o];

            int has_dupe = 0;
            for(uint32_t j = 0; j < sub_bucket_size && !has_dupe; j += 2) {
                uint32_t a1 = sub_bucket_indices[j]; //mask_collision_bits(base->digest, last_bit);
                
                for(uint32_t k = j+2; k < sub_bucket_size; k += 2) {

                    if(__builtin_expect(a1 == sub_bucket_indices[k] && a1 != 0, 0)) {
                        uint32_t b1 = sub_bucket_indices[k]; //mask_collision_bits(el->digest, last_bit);

                        // dupes usually appear more than once for some reason, so simply check if this has a duplicate if so skip all
                        if(__builtin_expect(k < sub_bucket_size-1, 1)) {
                            uint32_t c1 = sub_bucket_indices[k+2];
                            if(__builtin_expect(b1 == c1, 1)) {
                                //printf("skip dupe\n");
                                has_dupe = 1;
                                break;
                            }
                        }

                        uint32_t uncompressed_indices[NUM_INDICES];
                        memset(uncompressed_indices, '\0', NUM_INDICES);
                        element_t* base = bucket->data + sub_bucket_indices[j+1];
                        element_t* el = bucket->data + sub_bucket_indices[k+1];
                        uint32_t last_collision = decompress_indices(uncompressed_indices, indices, base->a, base->b);
                        last_collision ^= decompress_indices(uncompressed_indices + NUM_INDICES/2, indices, el->a, el->b);

                        if(__builtin_expect(last_collision != 0, 1)) {
                            continue;
                        }

                        // a simple heuristic for finding duplicates with high probability to avoid having to check the order of all of the indices
                        uint8_t dupes[1 << 8];
                        memset(dupes, '\0', (1 << 8)*sizeof(uint8_t));
                        uint32_t total_potential_dupes = 0;
                        for(size_t d = 0; d < NUM_INDICES && !has_dupe; ++d) {
                            uint32_t index = uncompressed_indices[d];
                            total_potential_dupes += ++dupes[index >> 13];
                        }

                        if(total_potential_dupes > 1100) {
                            has_dupe = 1;
                            break;
                        }


                        for(size_t d = 0; d < NUM_INDICES && !has_dupe; ++d) {
                            for(size_t o = d+1; o < NUM_INDICES && !has_dupe; ++o) {
                                if(uncompressed_indices[d] == uncompressed_indices[o]) {
                                    has_dupe = 1;
                                }
                            }
                        }

                        if(__builtin_expect(has_dupe, 1)) {
                        //    printf("%u\n", total_potential_dupes);
                        //    for(size_t d = 0; d < NUM_INDICES; ++d) {
                        //        printf("%u ", uncompressed_indices[d]);
                        //    }

                        //    printf("\n\n");
                            break;
                        }

                        normalize_indices(uncompressed_indices);

                        //printf("valid: %u\n", total_potential_dupes);

                        /*if(!is_indices_valid(uncompressed_indices, digest)) {
                            //fprintf(stderr, "INDICES NOT VALID!!! THIS INDICATES A SERIOUS BUG!\n");
                            continue;
                        }*/

                        n_solutions++;
                    }
                }
            }
        }
        bucket->size = 0;
        //tcollide += get_tttime() - t2;
	}
    double ttot = get_tttime() - t3;
    //fprintf(stderr, "final: %f\n", ttot);
    return n_solutions;
}

void equihash_init_buckets(bucket_t** src, bucket_t** dst, element_indice_t*** indices) {
    (*indices) = calloc(EQUIHASH_K-1, sizeof(element_indice_t*));
    for(size_t i = 0; i < EQUIHASH_K-1; ++i) {
        (*indices)[i] = calloc(NUM_VALUES + (NUM_VALUES >> 2), sizeof(element_indice_t));
    }
    (*src) = calloc(NUM_BUCKETS, sizeof(bucket_t));
    (*dst) = calloc(NUM_BUCKETS, sizeof(bucket_t));
}

size_t equihash(uint32_t** solutions, const crypto_generichash_blake2b_state* digest, bucket_t* src, bucket_t* dst, element_indice_t** indices) {
    //double t = get_tttime();
    initial_bucket_hashing(src, digest);
    //////fprintf(stderr, "init: %f\n", get_tttime() - t);
    size_t n_current_values = NUM_VALUES;

    for(size_t i = 1; i < 4; ++i) {
        collide_1_3(dst, src, indices[i-1], i);
        bucket_t* tmp = src;
        src = dst;
        dst = tmp;
    }

    for(size_t i = 4; i < 8; ++i) {
        collide_4_7(dst, src, indices[i-1], i);
        bucket_t* tmp = src;
        src = dst;
        dst = tmp;
    }

    for(size_t i = 8; i < 9; ++i) {
        collide_8(dst, src, indices[i-1], i);
        bucket_t* tmp = src;
        src = dst;
        dst = tmp;
    }
    
    size_t n_solutions = produce_solutions(solutions, src, indices, n_current_values, digest);
    //////fprintf(stderr, "final: %f\n", get_tttime() - t);
    return n_solutions;
}