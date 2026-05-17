#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>





int main() {
    
    if (OPENSSL_init_crypto(0, NULL) != 1) {
        printf("Ошибка инициализации OpenSSl\n");
        return 1;
    }

    printf("Версия OpenSSL: %s\n", OpenSSL_version(OPENSSL_VERSION));

    EVP_PKEY_CTX *ctx;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        printf("Ошибка генерации ключа\n");
        return 1;
    }

    if (EVP_PKEY_CTX_set_group_name(ctx, "secp256k1") == 0) {
        printf("Ошибка генерации\n");
        return 1;
    }

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_keygen(ctx, &pkey);
    
    
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    OPENSSL_cleanup();
    return 0;
}