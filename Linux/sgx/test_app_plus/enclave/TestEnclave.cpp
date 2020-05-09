/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdio.h>      /* vsnprintf */
#include <stdarg.h>
#include <string.h>

#include "TestEnclave.h"
#include "TestEnclave_t.h"  /* print_string */
#include "tSgxSSL_api.h"
#include "RawBase.h"
#include "SampleFilters.h"

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define ADD_ENTROPY_SIZE	32

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    uprint(buf);
}

typedef void CRYPTO_RWLOCK;

struct evp_pkey_st {
    int type;
    int save_type;
    int references;
    const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *engine;
    union {
        char *ptr;
# ifndef OPENSSL_NO_RSA
        struct rsa_st *rsa;     /* RSA */
# endif
# ifndef OPENSSL_NO_DSA
        struct dsa_st *dsa;     /* DSA */
# endif
# ifndef OPENSSL_NO_DH
        struct dh_st *dh;       /* DH */
# endif
# ifndef OPENSSL_NO_EC
        struct ec_key_st *ec;   /* ECC */
# endif
    } pkey;
    int save_parameters;
    STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
    CRYPTO_RWLOCK *lock;
} /* EVP_PKEY */ ;

EVP_PKEY *evp_pkey;
RSA *keypair;

void rsa_key_gen()
{
	BIGNUM *bn = BN_new();
	if (bn == NULL) {
		printf("BN_new failure: %ld\n", ERR_get_error());
	    return;
	}
	int ret = BN_set_word(bn, RSA_F4);
    if (!ret) {
       	printf("BN_set_word failure\n");
	    return;
	}
	
	keypair = RSA_new();
	if (keypair == NULL) {
		printf("RSA_new failure: %ld\n", ERR_get_error());
	    return;
	}
	ret = RSA_generate_key_ex(keypair, 4096, bn, NULL);
	if (!ret) {
        printf("RSA_generate_key_ex failure: %ld\n", ERR_get_error());
	    return;
	}

	evp_pkey = EVP_PKEY_new();
	if (evp_pkey == NULL) {
		printf("EVP_PKEY_new failure: %ld\n", ERR_get_error());
		return;
	}
	EVP_PKEY_assign_RSA(evp_pkey, keypair);

	/*

	// public key - string
	int len = i2d_PublicKey(evp_pkey, NULL);
	printf("For publickey, the size of buf is: %d\n", len);
	unsigned char *buf = (unsigned char *) malloc (len + 1);
	unsigned char *tbuf = buf;
	i2d_PublicKey(evp_pkey, &tbuf);

	// print public key
	printf ("{\"public\":\"");
	int i;
	for (i = 0; i < len; i++) {
	    printf("%02x", (unsigned char) buf[i]);
	}
	printf("\"}\n");

	free(buf);

	// private key - string
	len = i2d_PrivateKey(evp_pkey, NULL);
	buf = (unsigned char *) malloc (len + 1);
	tbuf = buf;
	i2d_PrivateKey(evp_pkey, &tbuf);

	// print private key
	printf ("{\"private\":\"");
	for (i = 0; i < len; i++) {
	    printf("%02x", (unsigned char) buf[i]);
	}
	printf("\"}\n");

	free(buf);
	*/

	BN_free(bn);

    /*
	EVP_PKEY_free(evp_pkey);

	if (evp_pkey->pkey.ptr != NULL) {
	  RSA_free(keypair);
	}
    */
}

int freeEverthing(){
	EVP_PKEY_free(evp_pkey);

	if (evp_pkey->pkey.ptr != NULL) {
	  RSA_free(keypair);
	}
    return 0;
}

int vprintf_cb(Stream_t stream, const char * fmt, va_list arg)
{
	char buf[BUFSIZ] = {'\0'};

	int res = vsnprintf(buf, BUFSIZ, fmt, arg);
	if (res >=0) {
		sgx_status_t sgx_ret = uprint((const char *) buf);
		TEST_CHECK(sgx_ret);
	}
	return res;
}

int sign_hash(void *hash_of_contract, size_t len_of_hash, void *signature, void *size_of_actual_signature){
	
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;

	md = EVP_sha256();
	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, md, NULL);

	int ret;
	ret = EVP_SignInit_ex(mdctx, md, NULL);
	if(ret != 1){
		printf("EVP_SignInit_ex error. \n");
        exit(1);
	}

	ret = EVP_SignUpdate(mdctx, hash_of_contract, len_of_hash);
	if(ret != 1){
		printf("EVP_SignUpdate error. \n");
        exit(1);
	}

	//printf("The size of pkey is: %d\n", EVP_PKEY_size(evp_pkey));
	//printf("The len of pkey is: %d\n", i2d_PrivateKey(evp_pkey, NULL));

	unsigned int sizeOfSignature = -1;

	ret = EVP_SignFinal(mdctx, (unsigned char*)signature, &sizeOfSignature, evp_pkey);
	if(ret != 1){
		printf("EVP_SignFinal error. \n");
        exit(1);
	}
	*(int*)size_of_actual_signature = sizeOfSignature;

	return 0;
}

void t_sgxver_call_apis(void *image_pixels, size_t size_of_image_pixels, int image_width, int image_height, 
						void *signature, int size_of_actual_signature,
						void *public_key, size_t len_of_pukey, void *size_of_actual_pukey, size_t size_of_soap, void* processed_pixels)
{
	// In: image_pixels, size_of_image_pixels, image_width, image_height, signature, size_of_actual_signature, public_key
	// Out: processed_pixels

	// rsa_key_gen();
	// sign_hash(hash_of_contract, len_of_hash, signature, size_of_actual_signature);
    printf("Hello from enclave!\n");
	pixel* img_pixels = (pixel*) image_pixels;
	printf("The very first pixel: R: %d; G: %d; B: %d\n", (int)img_pixels[0].r, (int)img_pixels[0].g, (int)img_pixels[0].b);
	blur(img_pixels, (pixel*)processed_pixels, image_width, image_width * image_height, 9);
	printf("The very first pixel(After processed by filter): R: %d; G: %d; B: %d\n", (int)((pixel*)processed_pixels)[0].r, (int)((pixel*)processed_pixels)[0].g, (int)((pixel*)processed_pixels)[0].b);

	/* call the API for verification here */
	/* FIXME */

	// Assign publicKey
	// int len = i2d_PublicKey(evp_pkey, NULL);
	// *(int*)size_of_actual_pukey = len;
	// i2d_PublicKey(evp_pkey, (unsigned char**)&public_key);

	// freeEverthing();
}

void t_sgxssl_call_apis(void* evp_pkey_v)
{
	/*
    int ret = 0;
	EVP_PKEY* evp_pkey = (EVP_PKEY*)evp_pkey_v;
    
    printf("Start tests\n");

	// public key - string
	int len = i2d_PublicKey(evp_pkey, NULL);
	unsigned char *buf = (unsigned char *) malloc (len + 1);
	unsigned char *tbuf = buf;
	i2d_PublicKey(evp_pkey, &tbuf);

	// print public key
	printf ("{\"public\":\"");
	int i;
	for (i = 0; i < len; i++) {
	    printf("%02x", (unsigned char) buf[i]);
	}
	printf("\"}\n");

	free(buf);
	*/
}

