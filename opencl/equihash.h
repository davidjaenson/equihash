#ifndef DJAEN_OPENCL_EQUIHASH_H
#define DJAEN_OPENCL_EQUIHASH_H
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sodium.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <assert.h>
#include <CL/cl.h>


#define EQUIHASH_N 200
#define EQUIHASH_K 9

#define NUM_COLLISION_BITS (EQUIHASH_N / (EQUIHASH_K + 1))
#define NUM_INDICES (1 << EQUIHASH_K)

#define NUM_VALUES (1 << (NUM_COLLISION_BITS+1))
#define NUM_INDICES_PER_BUCKET (1 << 10)
#define NUM_STEP_INDICES (8*NUM_VALUES)
#define NUM_BUCKETS (1 << NUM_COLLISION_BITS)/NUM_INDICES_PER_BUCKET
#define DIGEST_SIZE 32

typedef uint64_t digest_t[(DIGEST_SIZE + sizeof (uint64_t) - 1) /
			  sizeof (uint64_t)];

typedef struct gpu_config
{
  unsigned flags;

  char *program_source_code;
  size_t program_source_code_size;

  cl_program program;

  cl_platform_id platform_ids;
  cl_uint n_platforms;

  cl_device_id device_ids;
  cl_uint n_devices;

  cl_context context;
  cl_command_queue command_queue;


  cl_kernel initial_bucket_hashing_kernel;

  cl_kernel bucket_collide_and_hash_kernel;

  cl_kernel produce_candidates_kernel;

  cl_kernel produce_solutions_kernel;



  // gpu variables below
  cl_mem digests[2];
  cl_mem new_digest_index;
  cl_mem buckets;
  cl_mem src_local_buckets;
  //cl_mem dst_local_buckets;
  cl_mem blake2b_digest;
  cl_mem n_candidates;
  cl_mem dst_candidates;
  cl_mem n_solutions;
  cl_mem dst_solutions;
  cl_mem elements;
} gpu_config_t;


typedef struct element
{
  uint32_t digest_index;
  uint32_t parent_bucket_data;
  uint32_t a;
  uint32_t b;
} element_t;

typedef struct bucket
{
  element_t data[NUM_INDICES_PER_BUCKET / 8 * 28];
  volatile unsigned size;
} bucket_t;

typedef struct src_local_bucket
{
  element_t data[17];
} src_local_bucket_t;

typedef struct dst_local_bucket
{
  element_t data[128];
} dst_local_bucket_t;


size_t equihash (uint32_t *, crypto_generichash_blake2b_state *,
		 gpu_config_t * base_config);
void equihash_init (gpu_config_t * config);
void equihash_cleanup (gpu_config_t * config);


#endif
