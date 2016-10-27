all: test-equihash

test-equihash:
	gcc test-equihash.c equihash.c --pedantic -Wall -std=c11 -o test-equihash -lsodium -lpthread -Ofast -lOpenCL


clean:  
	rm test-equihash
