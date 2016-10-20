The cpu solver is close to 3.4 sol/s per thread on a i7-2640M CPU @ 2.80GHz

The opencl solver has a lot of room for improvement (~9 sol/sec on a gtx-970)

Acknowledgements:
    The CPU-version uses the Tromp's modified blake2b code and his method for initializing the blake2b state.