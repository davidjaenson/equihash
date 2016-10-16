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
#include <pthread.h>
#include <float.h>
#include <signal.h>
#include "thpool/thpool.h"

double get_time() {
    //struct timespec ts;
    //clock_gettime(CLOCK_MONOTONIC, &ts);
    struct timeval ts;
    gettimeofday(&ts, NULL);
    return ts.tv_sec + ts.tv_usec / 1000000.0;
}


typedef struct element_indice element_indice_t;
typedef struct element element_t;
typedef struct bucket bucket_t;

void equihash_init_buckets(bucket_t**, bucket_t**, element_indice_t*** indices);

size_t equihash(uint32_t dst_solutions[20][512], const crypto_generichash_blake2b_state*, bucket_t*, bucket_t*, element_indice_t** indices);


typedef struct equihash_thread_arg {
    crypto_generichash_blake2b_state state;
    bucket_t* src;
    bucket_t* dst;
    element_indice_t** indices;
} equihash_thread_arg_t;

static size_t n_solutions = 0;
static pthread_mutex_t mutex;
static double start_time = 0;
static double min_time = 0xfffffff;
static double max_time = 0;

void threaded_equihash(void* targ) {
    uint32_t solutions[20][512];
    equihash_thread_arg_t* arg = targ;
    double st = get_time();
    size_t tmp = equihash(solutions, &arg->state, arg->src, arg->dst, arg->indices);
    double t = get_time() - st;
    pthread_mutex_lock(&mutex);
    //printf("!!!num solutions: %u\n", tmp);
    min_time = t < min_time ? t : min_time;
    max_time = t > max_time ? t : max_time;
    n_solutions += tmp;
    pthread_mutex_unlock(&mutex);
}

int main(int argc, char** argv) {
    sodium_init();
    uint32_t t = 100;

    //srand(time(NULL));
    srand(0); // we fix the seed for now so that testing is comparable

    size_t iterations = strtoul(argv[1], NULL, 10);
    size_t start_num_threads = strtoul(argv[2], NULL, 10);
    size_t max_num_threads = strtoul(argv[3], NULL, 10);
    size_t n_runs = 100;
    
    for(size_t num_threads = start_num_threads; num_threads <= max_num_threads; ++num_threads) {
        //uint64_t thread_ids[num_threads];
        printf("running %zu threads\n", num_threads);
        threadpool thpool = thpool_init(num_threads);
        double total_time = 0;
        n_solutions = 0;
        equihash_thread_arg_t thread_args[num_threads*iterations];
        for(size_t i = 0; i < num_threads*2; ++i) {
            equihash_init_buckets(&thread_args[i].src, &thread_args[i].dst, &thread_args[i].indices);
        }

        start_time = get_time();
        //for(size_t run_i = 0; run_i < n_runs; ++run_i) {
        for(size_t i = 0; i < num_threads*iterations; ++i) {
            t = rand();
            crypto_generichash_blake2b_state curr_state;
            crypto_generichash_blake2b_init(&curr_state, (const unsigned char*)"", 0, (512/200)*200/8);
            crypto_generichash_blake2b_update(&curr_state, (const uint8_t*)&t, 4);
            thread_args[i].state = curr_state;
            thread_args[i].src = thread_args[i % (2*num_threads)].src;
            thread_args[i].dst = thread_args[i % (2*num_threads)].dst;
            thread_args[i].indices = thread_args[i % (2*num_threads)].indices;

            thpool_add_work(thpool, threaded_equihash, &thread_args[i]);
        }

        thpool_wait(thpool);
        //}
        total_time = get_time() - start_time;

        fprintf(stderr, "num concurrent threads: %u\n", num_threads);
        fprintf(stderr, "min. time: %lf\n", min_time);
        fprintf(stderr, "max. time: %lf\n", max_time);
        fprintf(stderr, "avg. time: %lf\n", total_time / iterations);
        fprintf(stderr, "tot. time: %lf\n", total_time);
        fprintf(stderr, "%lf sol/s\n", n_solutions / total_time);
        fprintf(stderr, "total solutions: %zu\n", n_solutions);

        for(size_t i = 0; i < num_threads*2; ++i) {
            free(thread_args[i].src);
            free(thread_args[i].dst);
            for(size_t j = 0; j < 9; ++j) {
                free(thread_args[i].indices[j]);
            }
            free(thread_args[i].indices);
        }
        thpool_destroy(thpool);
    }
    return 0;
}