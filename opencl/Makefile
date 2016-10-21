all: test-equihash

test-equihash:
	gcc test-equihash.c equihash.c --pedantic -Wall -std=c11 -o test-equihash -lsodium -lpthread -ggdb -pg -Ofast -lOpenCL

clean:  
	rm test-equihash
