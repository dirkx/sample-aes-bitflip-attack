all: tests

tiny-AES-c/aes.c:
	git clone https://github.com/kokke/tiny-AES-c.git

tests: test test-crc24
	./test
	./test-crc24

test: test.c tiny-AES-c/aes.c
	gcc -Wall -o test test.c

test-crc24: test-crc24.c tiny-AES-c/aes.c
	gcc -Wall -o test-crc24 test-crc24.c

clean:	 
	rm -rf test *.o *.core tiny-AES-c test-crc24
