LDFLAGS+=-L/usr/lib/openssl-1.0
INCDIRS+=-I. -Isrc -I/usr/include/openssl-1.0

all: upower_o_aes w_aes upower_w_aes

upower_o_aes: upower_o_aes.o
	gcc -Wall -g $(INCDIRS) -o upower_o_aes upower_o_aes.c $(LDFLAGS) -lssl -lcrypto -lwolfssl

upower_w_aes: upower_w_aes.o
	gcc -Wall -g $(INCDIRS) -o upower_w_aes upower_w_aes.c $(LDFLAGS) -lssl -lcrypto -lwolfssl

w_aes: w_aes.o
	gcc -Wall -g $(INCDIRS) -o w_aes w_aes.c $(LDFLAGS) -lssl -lcrypto -lwolfssl

o_aes: o_aes.o
	gcc -Wall -g $(INCDIRS) -o o_aes o_aes.c $(LDFLAGS) -lssl -lcrypto

clean:
	rm o_aes
	rm w_aes
