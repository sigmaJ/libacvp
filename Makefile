CC = gcc
CFLAGS+=-g -DUSE_MURL -O0 -fPIC -Wall
LDFLAGS+=-Lmurl -L/usr/lib/openssl-1.0
INCDIRS+=-I. -Isrc -I/usr/include/openssl-1.0

SOURCES=src/acvp.c src/acvp_aes.c src/acvp_des.c src/acvp_hash.c src/acvp_drbg.c src/acvp_transport.c src/acvp_util.c src/parson.c src/acvp_hmac.c src/acvp_cmac.c src/acvp_rsa.c src/acvp_dsa.c src/acvp_kdf135_tls.c src/acvp_kdf135_snmp.c src/acvp_kdf135_ssh.c
OBJECTS=$(SOURCES:.c=.o)

all: libacvp.a acvp_app wolf_app

.PHONY: test testcpp

libacvp.a: $(OBJECTS)
	ar rcs libacvp.a $(OBJECTS)

.c.o:
	$(CC) $(INCDIRS) $(CFLAGS) -c $< -o $@

libacvp.so: $(OBJECTS)
	$(CC) $(INCDIRS) $(CFLAGS) -shared -Wl,-soname,libacvp.so.1.0.0 -o libacvp.so.1.0.0 $(OBJECTS)
	ln -fs libacvp.so.1.0.0 libacvp.so

acvp_app: app/app_main.c libacvp.a
	$(CC) $(INCDIRS) $(CFLAGS) -o $@ app/app_main.c -L. $(LDFLAGS) -lacvp -lcrypto -lssl -lmurl -ldl -lwolfssl

wolf_app: app/app_main_wolf.c libacvp.a
	$(CC) $(INCDIRS) $(CFLAGS) -o $@ app/app_main_wolf.c -L. $(LDFLAGS) -lacvp -lcrypto -lssl -lmurl -ldl -lwolfssl

clean:
	rm -f *.[ao]
	rm -f src/*.[ao]
	rm -f app/*.[ao]
	rm -f libacvp.so.1.0.0
	rm -f acvp_app
	rm -f wolf_app
	rm -f testgcm

