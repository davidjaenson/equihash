#define _XOPEN_SOURCE 700
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>
#include <float.h>
#include <signal.h>
#include "blake/blake2.h"
#include "thpool/thpool.h"

double
get_time ()
{
  //struct timespec ts;
  //clock_gettime(CLOCK_MONOTONIC, &ts);
  struct timeval ts;
  gettimeofday (&ts, NULL);
  return ts.tv_sec + ts.tv_usec / 1000000.0;
}


typedef struct element_indice element_indice_t;
typedef struct element element_t;
typedef struct bucket bucket_t;

void equihash_init_buckets (bucket_t **, bucket_t **,
			    element_indice_t *** indices);

size_t equihash (uint32_t dst_solutions[20][512], const blake2b_state *,
		 bucket_t *, bucket_t *, element_indice_t ** indices);


/*
    FROM JOHN TROMP's implementation
*/
void
create_header (blake2b_state * ctx, const char *header, size_t header_size,
	       uint32_t nce)
{
  uint32_t le_N = 200;
  uint32_t le_K = 9;
  uint8_t personal[] = "ZcashPoW01230123";
  memcpy (personal + 8, &le_N, 4);
  memcpy (personal + 12, &le_K, 4);
  blake2b_param P[1];
  P->digest_length = (512 / 200) * 200 / 8;
  P->key_length = 0;
  P->fanout = 1;
  P->depth = 1;
  P->leaf_length = 0;
  P->node_offset = 0;
  P->node_depth = 0;
  P->inner_length = 0;
  memset (P->reserved, 0, sizeof (P->reserved));
  memset (P->salt, 0, sizeof (P->salt));
  memcpy (P->personal, (const uint8_t *) personal, 16);
  blake2b_init_param (ctx, P);
  blake2b_update (ctx, (const uint8_t *) header, header_size);
  uint8_t nonce[32];
  memset (nonce, 0, 32);
  uint32_t le_nonce = nce;
  memcpy (nonce, &le_nonce, 4);
  blake2b_update (ctx, nonce, 32);
}


typedef struct equihash_thread_arg
{
  blake2b_state state;
  bucket_t *src;
  bucket_t *dst;
  element_indice_t **indices;
} equihash_thread_arg_t;

static size_t n_solutions = 0;
static pthread_mutex_t mutex;
static double start_time = 0;
static double min_time = 0xfffffff;
static double max_time = 0;

void
threaded_equihash (void *targ)
{
  uint32_t solutions[20][512];
  equihash_thread_arg_t *arg = targ;
  double st = get_time ();
  size_t tmp =
    equihash (solutions, &arg->state, arg->src, arg->dst, arg->indices);
  double t = get_time () - st;
  pthread_mutex_lock (&mutex);
  //printf("!!!num solutions: %u\n", tmp);
  min_time = t < min_time ? t : min_time;
  max_time = t > max_time ? t : max_time;
  n_solutions += tmp;
  pthread_mutex_unlock (&mutex);
}

int
main (int argc, char **argv)
{
  uint32_t t = 1000;

  if (argc < 3)
    {
      fprintf (stderr, "%s <iterations> <number of threads>\n", argv[0]);
      exit (1);
    }

  size_t iterations = strtoul (argv[1], NULL, 10);
  size_t num_threads = strtoul (argv[2], NULL, 10);

  printf ("running %zu threads\n", num_threads);
  threadpool thpool = thpool_init (num_threads);
  double total_time = 0;
  n_solutions = 0;
  equihash_thread_arg_t thread_args[num_threads * iterations];
  for (size_t i = 0; i < num_threads * 2; ++i)
    {
      equihash_init_buckets (&thread_args[i].src, &thread_args[i].dst,
			     &thread_args[i].indices);
    }

  start_time = get_time ();
  for (size_t i = 0; i < num_threads * iterations; ++i)
    {
      blake2b_state curr_state;
      create_header (&curr_state, "", 0, t);
      t++;
      thread_args[i].state = curr_state;
      thread_args[i].src = thread_args[i % (2 * num_threads)].src;
      thread_args[i].dst = thread_args[i % (2 * num_threads)].dst;
      thread_args[i].indices = thread_args[i % (2 * num_threads)].indices;

      thpool_add_work (thpool, threaded_equihash, &thread_args[i]);
    }

  thpool_wait (thpool);
  total_time = get_time () - start_time;

  fprintf (stdout, "num concurrent threads: %u\n", num_threads);
  fprintf (stdout, "min. time: %lf\n", min_time);
  fprintf (stdout, "max. time: %lf\n", max_time);
  fprintf (stdout, "avg. time: %lf\n", total_time / iterations);
  fprintf (stdout, "tot. time: %lf\n", total_time);
  fprintf (stdout, "%lf sol/s\n", n_solutions / total_time);
  fprintf (stdout, "total solutions: %zu\n", n_solutions);

  for (size_t i = 0; i < num_threads * 2; ++i)
    {
      free (thread_args[i].src);
      free (thread_args[i].dst);
      for (size_t j = 0; j < 9; ++j)
	{
	  free (thread_args[i].indices[j]);
	}
      free (thread_args[i].indices);
    }
  thpool_destroy (thpool);

  return 0;
}
