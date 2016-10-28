Oct 20, 2016: The cpu solver is close to 3.4 sol/s per thread on a i7-2640M CPU @ 2.80GHz

Oct 28, 2016: The opencl solver achieves ~15 sol/s on a gtx-970

Acknowledgements:
    Oct 20, 2016: The CPU-version uses the Tromp's modified blake2b code and his method for initializing the blake2b state.


### CPU equihash API
Initiate the buckets and the indice tree structure by calling "equihash_init_buckets".
```c
void equihash_init_buckets(bucket_t** src, bucket_t** dst, element_indice_t*** indices)
```

Then call "equihash" which returns the number of solutions found, and places these solutions uncompressed in dst_solutions (512 indices each one 32 bits).
The blake2b state should be initialized with the header data before calling this function. The src buckets, dst buckets and indices refer to the same ones as were mentioned above in the "equihash_init_buckets" function.
```c
size_t equihash(uint32_t* dst_solutions, const blake2b_state* state, bucket_t* src, bucket_t* dst, element_indice_t** indices)
```

When you're done finding equihash solutions, call "equihash_cleanup_buckets". The same params as "equihash_init_buckets".  
```c
void equihash_cleanup_buckets(bucket_t* src, bucket_t* dst, element_indice_t** indices);
```

### OpenCL equihash API:
Initiate the gpu configuration data and the related variables using the "equihash_init" function passing a gpu_config_t struct. 
```c
void equihash_init(gpu_config_t* config);
```

Then call "equihash" which returns the number of solutions found, and places these solutions uncompressed in dst_solutions (512 indices each one 32 bits).
The blake2b state should be initialized with the header data before calling this function.
```c
size_t equihash(uint32_t* dst_solutions, crypto_generichash_blake2b_state* state, gpu_config_t* base_config);
```

When you're done finding equihash solutions, call "equihash_cleanup". The same param as "equihash_init".  
```c
void equihash_cleanup(gpu_config_t* config);
```

### Future improvements
* A lot of microoptimizations
* The opencl code currently calculates the produce_solutions step from the candidate solutions very inefficiently. Proper parallelization of this kernel can increase performance by a lot. 
* Each slot "element_t" in a bucket uses 128 bit of memory. This can the very least be reduced to 64 bits.
* Proper selection of the number of buckets and slots per bucket. Currently 1024 buckets are used.
