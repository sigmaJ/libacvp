#include <wolfssl/wolfcrypt/sha256.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rand.h>



int main(int argc, char **argv)
{
    char* str = "message";
    char* wolfdigest = malloc(32);
    char* opendigest = malloc(32);
    
    Sha256 sha[1]; 
    
    if (wc_InitSha256(sha)){
        printf("wc_InitSha256 failed\n");
        exit(1);
    }
    if (wc_Sha256Update(sha, str, strlen(str))){
        printf("wc_Sha256Update failed\n");
    }
    if (wc_Sha256Final(sha, wolfdigest)){
        printf("wc_Sha256Final failed\n");
    }
    
    printf("WolfSSL Sha256:\n");
    printf("%s\n", str);
    printf(wolfdigest);
    printf("\n");
    
    
    
    const EVP_MD *md;
    EVP_MD_CTX *md_ctx;
    md_ctx = EVP_MD_CTX_new();
//     printf("md_ctx\n");
    EVP_MD_CTX_init(md_ctx);
//     printf("init\n");
    md = EVP_sha256();
//     printf("sha\n");
    int *size = malloc(sizeof(int));
    *size = 32;
    
    if (!EVP_DigestInit_ex(md_ctx, md, NULL)) {
        printf("\nCrypto module error, EVP_DigestInit_ex failed\n");
        exit(1);
    }
//     printf("digestinit\n");
    if (!EVP_DigestUpdate(md_ctx, str, strlen(str))) {
        printf("\nCrypto module error, EVP_DigestUpdate failed\n");
        exit(0);
    }
//     printf("update\n");
    if (!EVP_DigestFinal(md_ctx, opendigest, size)) {
        printf("\nCrypto module error, EVP_DigestFinal failed\n");
    }
    
    printf("OpenSSL Sha256:\n");
    printf("%s\n", str);
    printf(opendigest);
    printf("\n");
    
    if (strncmp(wolfdigest, opendigest, 32) == 0){
        printf("Digests are the same\n");
    }
    
    
}
