#include <wolfssl/wolfcrypt/aes.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {

	unsigned char bms[] = "I want to ride my bicycle, I want to ride my bike.";
	int bms_len = strlen(bms)*sizeof(char);
	if (wolfCrypt_Init() != 0) {
		printf("Wolfcrypt initialization error");
	}
	Aes aes;
	word32 len = 16;
	const byte iv[] = {0x7a, 0x22, 0x6a, 0x44, 0x48, 0x44, 0x36, 0x10, 0xb4, 0x6b, 0xe6, 0x22, 0x7e, 0x70, 0x7d, 0xc3};
	byte key[] = {0x02, 0x7b, 0xec, 0xe9, 0x2b, 0x4c, 0xab, 0x9c, 0x33, 0xcc, 0xd6, 0x86, 0x25, 0xad, 0x39, 0xe3};
	byte *ct = (byte *)malloc(bms_len * sizeof(byte)+16);
	byte *pt = (byte *)malloc(bms_len * sizeof(byte)+16);
	int padding = len - (bms_len % len);
	wc_AesSetKey(&aes, key, len, iv, AES_ENCRYPTION);
	wc_AesCbcEncrypt(&aes, ct, bms, bms_len+padding);
	printf("cipher text: %s\n", ct);
	wc_AesSetKey(&aes, key, len, iv, AES_DECRYPTION);
	//printf("bms len: %d", bms_len);
	wc_AesCbcDecrypt(&aes, pt, ct, bms_len+padding);
	printf("decrypt text: %s\n", pt);
}
