all: test-equihash working-test-equihash

test-equihash:
	gcc test-equihash.c equihash.c --pedantic -Wall -std=c11 -o test-equihash -lsodium -lpthread -ggdb -pg -Ofast -lOpenCL

working-test-equihash:
	gcc test-equihash.c equihash-old-working.c --pedantic -Wall -std=c11 -o working-test-equihash -lsodium -lpthread -ggdb -pg -Ofast -lOpenCL


clean:  
	rm test-equihash working-test-equihash
