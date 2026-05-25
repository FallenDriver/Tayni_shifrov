#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>


EVP_PKEY* generate_key() {

    EVP_PKEY_CTX *ctx;
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        printf("Ошибка генерации ключа\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_group_name(ctx, "secp256k1") == 0) {
        printf("Ошибка генерации\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        printf("Ошибка генерации\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

unsigned char *secret_generation(EVP_PKEY *private_key, EVP_PKEY *public_key, int *len_result) {
    EVP_PKEY_CTX *ctx;
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, private_key, NULL);

    size_t len = 0;

    EVP_PKEY_derive_init(ctx);

    EVP_PKEY_derive_set_peer(ctx, public_key);

    EVP_PKEY_derive(ctx, NULL, &len);

    unsigned char *secret = malloc(len);

    EVP_PKEY_derive(ctx, secret, &len);

    *len_result = len;
    EVP_PKEY_CTX_free(ctx);

    return secret;
}

void key_derive(unsigned char *secret, size_t secret_len, unsigned char *enc_key, unsigned char *sig_key) {

    char *salt_str = "protocol-salt";
    unsigned char *salt = (unsigned char *)salt_str;
    size_t salt_len = strlen(salt_str);

    unsigned char prk[32];
    unsigned int prk_len = 32;

    HMAC(EVP_sha256(), salt, salt_len, secret, secret_len, prk, &prk_len);

    char *info_enc = "enc";
    size_t info_enc_len = strlen(info_enc);

    char *info_sig = "sig";
    size_t info_sig_len = strlen(info_sig);

    char input_enc[33];
    memcpy(input_enc, info_enc, info_enc_len);
    input_enc[info_enc_len] = 0x01;

    unsigned int len_out = 32;
    HMAC(EVP_sha256(), prk, prk_len, input_enc, info_enc_len + 1, enc_key, &len_out);



    char input_sig[33];
    memcpy(input_sig, info_sig, info_sig_len);
    input_sig[info_sig_len] = 0x01;

    HMAC(EVP_sha256(), prk, prk_len, input_sig, info_sig_len + 1, sig_key, &len_out);
}
    
void encrypt_message(unsigned char *enc_key, unsigned char *text, int text_len, unsigned char *aad, int aad_len, unsigned char *IV, unsigned char *ciphertext, unsigned char *tag) {
    int len = 0;

    RAND_bytes(IV, 12);

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, enc_key, IV);

    EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);

    EVP_EncryptUpdate(ctx, ciphertext, &len, text, text_len);

    EVP_EncryptFinal_ex(ctx, NULL, &len);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

    EVP_CIPHER_CTX_free(ctx);
}

unsigned char *sign_message(EVP_PKEY *private_key, unsigned char *data, int data_len, int *res) {
    size_t len = 0;

    EVP_MD_CTX *ctx;
    ctx = EVP_MD_CTX_new();

    EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, private_key);

    EVP_DigestSignUpdate(ctx, data, data_len);

    EVP_DigestSignFinal(ctx, NULL, &len);

    unsigned char *signature = malloc(len);
    *res = (int)len;

    EVP_DigestSignFinal(ctx, signature, &len);

    EVP_MD_CTX_free(ctx);

    return signature;
}

typedef struct Pack {
    unsigned char IV[12];
    unsigned char tag[16];
    unsigned char *ciphertext;
    int ciphertext_len;
    unsigned char *signature;
    int signature_len;
    unsigned char *aad;
    int aad_len;
    unsigned char *sender_pub_key;
    int pub_key_len;

} Pack;

int decrypt(Pack message, unsigned char *enc_key) {
    EVP_PKEY_CTX *ctx;
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);

    EVP_PKEY_fromdata_init(ctx);

    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "secp256k1", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, message.sender_pub_key, message.pub_key_len);
    params[2] = OSSL_PARAM_construct_end();

    EVP_PKEY *received_pub_key = NULL;
    EVP_PKEY_fromdata(ctx, &received_pub_key, EVP_PKEY_PUBLIC_KEY, params);

    EVP_PKEY_CTX_free(ctx);

    
    int len = 0;
    int text_len = 0;
    int data_len = 12 + message.ciphertext_len + 16;
    unsigned char *decrypted_text = malloc(message.ciphertext_len + 1);
    unsigned char *data = malloc(data_len);

    memcpy(data, message.IV, 12);
    memcpy(data + 12, message.ciphertext, message.ciphertext_len);
    memcpy(data + 12 + message.ciphertext_len, message.tag, 16);

    EVP_MD_CTX *md_ctx;
    md_ctx = EVP_MD_CTX_new();

    EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, received_pub_key);
    EVP_DigestVerifyUpdate(md_ctx, data, data_len);
    int res = EVP_DigestVerifyFinal(md_ctx, message.signature, message.signature_len);

    if (res == 1) {
        printf("Подпись верна!\n");
    }

    EVP_CIPHER_CTX *cipher_ctx;
    cipher_ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);

    EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);

    EVP_DecryptInit_ex(cipher_ctx, NULL, NULL, enc_key, message.IV);

    EVP_DecryptUpdate(cipher_ctx, NULL, &len, message.aad, message.aad_len);

    EVP_DecryptUpdate(cipher_ctx, decrypted_text, &text_len, message.ciphertext, message.ciphertext_len);

    EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_TAG, 16, message.tag);

    EVP_DecryptFinal_ex(cipher_ctx, NULL, &len);

    decrypted_text[text_len] = '\0';
    printf("Расшифрованное сообщение: %s\n", decrypted_text);

    free(data);
    free(decrypted_text);
    EVP_PKEY_free(received_pub_key);
    EVP_MD_CTX_free(md_ctx);
    EVP_CIPHER_CTX_free(cipher_ctx);
    return 1;
}

int main() {
    
    if (OPENSSL_init_crypto(0, NULL) != 1) {
        printf("Ошибка инициализации OpenSSl\n");
        return 1;
    }

    printf("Версия OpenSSL: %s\n", OpenSSL_version(OPENSSL_VERSION));

    
    EVP_PKEY *mikhail_key = generate_key();
    EVP_PKEY *alexandra_key = generate_key();

    if (mikhail_key != NULL && alexandra_key != NULL) {
        printf("Ключи сгенерированы успешно!\n");
    }

    int m_len, a_len;

    unsigned char *mikhail_secret = secret_generation(mikhail_key, alexandra_key, &m_len);
    unsigned char *alexandra_secret = secret_generation(alexandra_key, mikhail_key, &a_len);


    if (m_len == a_len && memcmp(mikhail_secret, alexandra_secret, m_len) == 0) {
        printf("Секреты совпадают!\n");
    } else {
        printf("Ошибка: секреты не совпадают!\n");
    }


    unsigned char enc_key[32];
    unsigned char sig_key[32];

    key_derive(mikhail_secret, m_len, enc_key, sig_key);

    printf("Enc-ключ: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", enc_key[i]);
    }

    printf("\nSig-ключ: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", sig_key[i]);
    }
    printf("\n");

    unsigned char IV[12];
    unsigned char tag[16];
    unsigned char *text = (unsigned char *)"Здарова!";
    int text_len = strlen((char *)text);

    unsigned char *aad = (unsigned char *)"Михаил->Александра";
    int aad_len = strlen((char *)aad);

    unsigned char ciphertext[text_len];

    encrypt_message(enc_key, text, text_len, aad, aad_len, IV, ciphertext, tag);

    printf("IV: ");
    for (int i = 0; i < 12; i++) {
        printf("%02x", IV[i]);
    }
    printf("\nCiphertext: ");
    for (int i = 0; i < text_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\nTag: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", tag[i]);
    }
    printf("\n");

    int data_len = 12 + text_len + 16;

    unsigned char *data = malloc(data_len);

    memcpy(data, IV, 12);
    memcpy(data + 12, ciphertext, text_len);
    memcpy(data + 12 + text_len, tag, 16);

    int sig_len = 0;
    unsigned char *signature = sign_message(mikhail_key, data, data_len, &sig_len);

    printf("Длинна подписи: %d\n", sig_len);

    size_t pub_key_len;
    EVP_PKEY_get_octet_string_param(mikhail_key, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pub_key_len);
    unsigned char *sender_pub_key = malloc(pub_key_len);
    EVP_PKEY_get_octet_string_param(mikhail_key, OSSL_PKEY_PARAM_PUB_KEY, sender_pub_key, pub_key_len, &pub_key_len);
    
    Pack packet;

    memcpy(packet.IV, IV, 12);
    memcpy(packet.tag, tag, 16);
    packet.ciphertext_len = text_len;
    packet.ciphertext = malloc(text_len);
    memcpy(packet.ciphertext, ciphertext, text_len);

    packet.signature_len = sig_len;
    packet.signature = malloc(sig_len);
    memcpy(packet.signature, signature, sig_len);

    packet.aad_len = aad_len;
    packet.aad = malloc(aad_len);
    memcpy(packet.aad, aad, aad_len);

    packet.pub_key_len = pub_key_len;
    packet.sender_pub_key = malloc(pub_key_len);
    memcpy(packet.sender_pub_key, sender_pub_key, pub_key_len);

    printf("%d\n", packet.pub_key_len);

    if (decrypt(packet, enc_key) == 1) {
        printf("Успешный результат!\n");
    } else {
        printf("Где то прячется ошибка..\n");
    }




    free(data);
    free(signature);
    EVP_PKEY_free(mikhail_key);
    EVP_PKEY_free(alexandra_key);
    free(mikhail_secret);
    free(alexandra_secret);
    free(packet.ciphertext);
    free(packet.signature);
    free(packet.aad);
    free(packet.sender_pub_key);

    OPENSSL_cleanup();
    return 0;
}