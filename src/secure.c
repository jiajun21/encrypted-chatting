#include "protocol.h"
#include "secure.h"
#include <pthread.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

static pthread_mutex_t openssl_mutex;
static char * dh_parameter_p;

int secure_send(int channel, const void * buf, size_t len, int flags,
                const unsigned char * key, const unsigned char * iv)
{
    EVP_CIPHER_CTX * ctx;
    unsigned char * enc_buf;
    int align_len, total_enc_len, this_enc_len, send_len;
    int ret;

    align_len = len - len % 16 + 16;
    enc_buf = (unsigned char *)malloc(align_len);

    pthread_mutex_lock(&openssl_mutex);

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, enc_buf, &this_enc_len, buf, len);
    total_enc_len = this_enc_len;
    EVP_EncryptFinal_ex(ctx, enc_buf + total_enc_len, &this_enc_len);
    total_enc_len += this_enc_len;
    EVP_CIPHER_CTX_free(ctx);

    pthread_mutex_unlock(&openssl_mutex);

    send_len = 0;
    while (1)
    {
        ret = send(channel, enc_buf + send_len, total_enc_len - send_len, flags);
        if (ret >= 0)
        {
            send_len += ret;
            if (send_len == total_enc_len)
            {
                ret = send_len;
                break;
            }
        }
        else
        {
            if (errno != EINTR)
            {
                ret = -1;
                break;
            }
        }
    }

    free(enc_buf);

    return ret;
}

int secure_recv(int channel, void * buf, size_t len, int flags,
                const unsigned char * key, const unsigned char * iv)
{
    EVP_CIPHER_CTX * ctx;
    unsigned char * recv_buf;
    unsigned char * dec_buf;
    int align_len, total_dec_len, this_dec_len, recv_len;
    int ret;

    align_len = len - len % 16 + 16;
    recv_buf = (unsigned char *)malloc(align_len);
    /* "if padding is enabled the decrypted data buffer 'out'
       passed to EVP_DecryptUpdate() should have sufficient
       room for (inl + cipher_block_size) bytes", from manpage */
    dec_buf = (unsigned char *)malloc(align_len + 16);

    recv_len = 0;
    while (1)
    {
        ret = recv(channel, recv_buf + recv_len, align_len - recv_len, flags);
        if (ret > 0)
        {
            recv_len += ret;
            if (recv_len == align_len)
            {
                ret = recv_len;
                break;
            }
        }
        else if (ret == 0)
        {
            ret = -1;
            goto clean;
        }
        else
        {
            if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
            {
                ret = -1;
                goto clean;
            }
        }
    }

    pthread_mutex_lock(&openssl_mutex);

    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, dec_buf, &this_dec_len, recv_buf, ret);
    total_dec_len = this_dec_len;
    EVP_DecryptFinal_ex(ctx, dec_buf + total_dec_len, &this_dec_len);
    total_dec_len += this_dec_len;
    EVP_CIPHER_CTX_free(ctx);

    pthread_mutex_unlock(&openssl_mutex);

    memcpy(buf, dec_buf, total_dec_len);

clean:
    free(dec_buf);
    free(recv_buf);

    return ret;
}

int secure_init_server(void)
{
    DH * dh;

    RAND_poll();
    dh = DH_new();
    DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, NULL);
    dh_parameter_p = BN_bn2hex(DH_get0_p(dh));
    DH_free(dh);

    pthread_mutex_init(&openssl_mutex, NULL);

    return 0;
}

int secure_build_key_server(int channel, unsigned char * key, unsigned char * iv)
{
    DH * dh;
    BIGNUM * p = NULL;
    BIGNUM * g = NULL;
    char * pub_key;
    BIGNUM * peer_pub_key = NULL;
    unsigned char * shared_key;
    char buf[1024];

    pthread_mutex_lock(&openssl_mutex);

    buf[0] = PROTO_BUILD_KEY_P;
    memcpy(&(buf[1]), dh_parameter_p, 512);
    send(channel, buf, 513, 0);

    dh = DH_new();
    BN_hex2bn(&p, dh_parameter_p);
    g = BN_new();
    BN_set_word(g, DH_GENERATOR_2);
    DH_set0_pqg(dh, p, NULL, g);
    DH_generate_key(dh);

    pub_key = BN_bn2hex(DH_get0_pub_key(dh));
    buf[0] = PROTO_BUILD_KEY_PUBK;
    memcpy(&(buf[1]), pub_key, 512);
    send(channel, buf, 513, 0);

    recv(channel, buf, 513, 0);
    buf[513] = '\0';
    BN_hex2bn(&peer_pub_key, &(buf[1]));

    /* shared_key is 256 bytes */
    shared_key = (unsigned char *)OPENSSL_malloc(DH_size(dh));
    DH_compute_key(shared_key, peer_pub_key, dh);

    memcpy(key, shared_key, 32);
    memcpy(iv, shared_key + 32, 16);

    OPENSSL_free(shared_key);
    BN_free(peer_pub_key);
    OPENSSL_free(pub_key);
    DH_free(dh);

    pthread_mutex_unlock(&openssl_mutex);

    return 0;
}

void secure_finish_server(void)
{
    pthread_mutex_destroy(&openssl_mutex);
    OPENSSL_free(dh_parameter_p);
}

int secure_init_client(void)
{
    pthread_mutex_init(&openssl_mutex, NULL);

    return 0;
}

int secure_build_key_client(int channel, unsigned char * key, unsigned char * iv)
{
    DH * dh;
    BIGNUM * p = NULL;
    BIGNUM * g = NULL;
    BIGNUM * peer_pub_key = NULL;
    char * pub_key;
    unsigned char * shared_key;
    char buf[1024];

    pthread_mutex_lock(&openssl_mutex);

    recv(channel, buf, 513, 0);
    buf[513] = '\0';
    BN_hex2bn(&p, &(buf[1]));

    dh = DH_new();
    g = BN_new();
    BN_set_word(g, DH_GENERATOR_2);
    DH_set0_pqg(dh, p, NULL, g);
    DH_generate_key(dh);

    recv(channel, buf, 513, 0);
    buf[513] = '\0';
    BN_hex2bn(&peer_pub_key, &(buf[1]));

    pub_key = BN_bn2hex(DH_get0_pub_key(dh));
    buf[0] = PROTO_BUILD_KEY_PUBK;
    memcpy(&(buf[1]), pub_key, 512);
    send(channel, buf, 513, 0);

    /* shared_key is 256 bytes */
    shared_key = (unsigned char *)OPENSSL_malloc(DH_size(dh));
    DH_compute_key(shared_key, peer_pub_key, dh);

    memcpy(key, shared_key, 32);
    memcpy(iv, shared_key + 32, 16);

    OPENSSL_free(shared_key);
    OPENSSL_free(pub_key);
    BN_free(peer_pub_key);
    DH_free(dh);

    pthread_mutex_unlock(&openssl_mutex);

    return 0;
}

void secure_finish_client(void)
{
    pthread_mutex_destroy(&openssl_mutex);
}
