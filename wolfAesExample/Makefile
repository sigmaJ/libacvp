LDFLAGS+=-L/usr/lib/openssl-1.0
INCDIRS+=-I. -Isrc -I/usr/include/openssl-1.0

w_aes: w_aes.o
	gcc -Wall -g $(INCDIRS) -o w_aes w_aes.c $(LDFLAGS) -lssl -lcrypto -lwolfssl

clean:
  rm w_aes
  
