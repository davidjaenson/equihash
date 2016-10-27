GCC   = gcc $(FLAGS)
FLAGS = -lsodium -lpthread -ffast-math -pthread -D_POSIX_SOURCE -Ofast -march=native --pedantic -Wall -std=c11

all: time-equihash

time-equihash:
	$(GCC) blake/blake2b.c thpool/thpool.c equihash-time.c equihash-opt.c -o time-equihash

clean:  
	rm time-equihash
