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

#include <errno.h>
#include <limits.h>

#include "TestEnclave.h"
#ifndef ENABLE_DCAP
#include "TestEnclave_t.h"
#else
#include "TestEnclave_dcap_t.h"
#endif
#include "tSgxSSL_api.h"
#include "RawBase.h"
#include "SampleFilters.h"
#include "ra-attester.h"
#include "ra-challenger.h"

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include "metadata.h"

void exit(int status)
{
	usgx_exit(status);
	// Calling to abort function to eliminate warning: ‘noreturn’ function does return [enabled by default]
	abort();
}

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

void sprintf_s(char* buf, size_t size_of_buf, const char *fmt, ...)
{
	// Need to make sure if this function call is secure or not
	// Need to calculate padding for buf yourself
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, size_of_buf, fmt, ap);
    va_end(ap);
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

EVP_PKEY *enc_priv_key;
EVP_PKEY *ias_pubkey;
char* mrenclave;
size_t mrenclave_len;

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

int sign(EVP_PKEY* priKey, void *data_to_be_signed, size_t len_of_data, unsigned char *signature, size_t *size_of_actual_signature){

	EVP_MD_CTX *mdctx = NULL;
	int ret = 0;
	
	do {
		/* Create the Message Digest Context */
		if(!(mdctx = EVP_MD_CTX_create())){
			printf("EVP_MD_CTX_create error: %ld. \n", ERR_get_error());
			ret = 1;
			break;
		}
	
		/* Initialise the DigestSign operation - SHA-256 has been selected as the message digest function in this example */
		if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, priKey)){
			printf("EVP_DigestSignInit error: %ld. \n", ERR_get_error());
			ret = 1;
			break;
		}
	
		/* Call update with the message */
		if(1 != EVP_DigestSignUpdate(mdctx, data_to_be_signed, len_of_data)){
			printf("EVP_DigestSignUpdate error: %ld. \n", ERR_get_error());
			ret = 1;
			break;
		}
	
		if (!signature) {
			/* Obtain signature size */
			if(1 != EVP_DigestSignFinal(mdctx, NULL, size_of_actual_signature)){
				printf("EVP_DigestSignFinal error: %s. \n", ERR_error_string(ERR_get_error(), NULL));
				ret = 1;
				break;
			}
			break;
		}
	
		/* Finalise the DigestSign operation */
		if(1 != EVP_DigestSignFinal(mdctx, signature, size_of_actual_signature)){
			printf("EVP_DigestSignFinal error: %s. \n", ERR_error_string(ERR_get_error(), NULL));
			ret = 1;
			break;
		}
	} while(0);
	
	/* Clean up */
	if(mdctx) EVP_MD_CTX_destroy(mdctx);

	return ret;
}

bool verify_hash(void* hash_of_file, size_t size_of_hash, unsigned char* signature, size_t size_of_siganture, EVP_PKEY* public_key){
	// Return true on success; otherwise, return false
	EVP_MD_CTX *mdctx = NULL;
	const EVP_MD *md = NULL;
	int ret = 1;

	OpenSSL_add_all_digests();

	do {
		md = EVP_get_digestbyname("SHA256");

		if (md == NULL) {
			printf("Unknown message digest %s\n", "SHA256");
			ret = 0;
			break;
		}

		mdctx = EVP_MD_CTX_new();
		EVP_DigestInit_ex(mdctx, md, NULL);

		ret = EVP_VerifyInit_ex(mdctx, EVP_sha256(), NULL);
		if(ret != 1){
			printf("EVP_VerifyInit_ex error: %s. \n", ERR_error_string(ERR_get_error(), NULL));
			break;
		}

 	    // printf("hash_of_file to be verified: %s (len: %i)\n", hash_of_file, size_of_hash);

		ret = EVP_VerifyUpdate(mdctx, hash_of_file, size_of_hash);
		if(ret != 1){
			printf("EVP_VerifyUpdate error: %s. \n", ERR_error_string(ERR_get_error(), NULL));
			break;
		}

		ret = EVP_VerifyFinal(mdctx, signature, (unsigned int)size_of_siganture, public_key);
		if(ret != 1){
			printf("EVP_VerifyFinal error: %s. \n", ERR_error_string(ERR_get_error(), NULL));
			break;
		}
		// printf("EVP_VerifyFinal result: %d\n", ret);
	} while(0);

	// Below part is for freeing data
	// For freeing evp_md_ctx
	if (mdctx) EVP_MD_CTX_free(mdctx);

    return ret;
}

void print_unsigned_chars(unsigned char* chars_to_print, int len){
	printf ("{\"unsigned_chars\":\"");
	int i;
	for (i = 0; i < len; i++) {
	    printf("%02x", (unsigned char) chars_to_print[i]);
	}
	printf("\"}\n");
}

void print_public_key(EVP_PKEY* enc_priv_key){
	// public key - string
	int len = i2d_PublicKey(enc_priv_key, NULL);
	printf("For publickey, the size of buf is: %d\n", len);
	unsigned char *buf = (unsigned char *) malloc (len + 1);
	unsigned char *tbuf = buf;
	i2d_PublicKey(enc_priv_key, &tbuf);

	// print public key
	printf ("{\"public\":\"");
	int i;
	for (i = 0; i < len; i++) {
	    printf("%02x", (unsigned char) buf[i]);
	}
	printf("\"}\n");

	free(buf);
}

int get_filter_idx(metadata* md, char* filter_name)
{
	for (int i = 0; i < md->total_filters; i++) {
		if (strcmp(md->filters[i], filter_name) == 0)
			return i;
	}
	return -1;
}

int t_verify_cert(void* ias_cert, size_t size_of_ias_cert)
{
	int ret = 1;
	X509 *crt = NULL;
	do {
		// Verify IAS certificate
		ret = verify_sgx_cert_extensions((uint8_t*)ias_cert, (uint32_t)size_of_ias_cert);
		if (ret) {
			printf("IAS cert verification failed\n");
			break;
		}

		// Extract public key from IAS certificate
		ias_pubkey = EVP_PKEY_new();
 	    const unsigned char* p = (unsigned char*)ias_cert;
 	    crt = d2i_X509(NULL, &p, size_of_ias_cert);
 	    assert(crt != NULL);
 	    ias_pubkey = X509_get_pubkey(crt);
		if(!ias_pubkey){
			ret = 1;
			printf("Failed to retreive public key\n");
			break;
		}
	} while(0);

	// Clean up
    X509_free(crt);
	return ret;
}

// Return 0 if success, 1 otherwise
int t_sgxver_call_apis(void* img_pixels, size_t size_of_img_pixels,
					   void* md_json, size_t size_of_md_json,
					   void* img_sig, size_t size_of_img_sig,
					   void* out_pixels,
					   void* out_md_json, size_t size_of_out_md_json,
					   void* out_img_sig, size_t size_of_out_img_sig)
{
	int ret = 1;
	char* filter_name = "blur";
	if (!img_pixels) {
		printf("Holy sh*t, this should never happen!!!!!!!!!\n");
		return ret;
	}

	// Verify signature
	unsigned char* buf = (unsigned char*)malloc(size_of_img_pixels + size_of_md_json);
	if (!buf) {
		printf("No memory left\n");
		ret = 1;
		return ret;
	}
	memset(buf, 0, size_of_img_pixels + size_of_md_json);
	memcpy(buf, img_pixels, size_of_img_pixels);
	memcpy(buf + size_of_img_pixels, md_json, size_of_md_json);
	// printf("Going to call verify signature with size_of_img_pixels: %d, size_of_md_json: %d, size_of_img_sig: %d\n", size_of_img_pixels, size_of_md_json, size_of_img_sig);
	// printf("Here is the md_json(%d): [%s]\n", size_of_md_json, md_json);
	// print_public_key(ias_pubkey);
	ret = verify_hash(buf, size_of_img_pixels + size_of_md_json, (unsigned char*)img_sig, size_of_img_sig, ias_pubkey);
	free(buf);
	if (ret != 1) {
		ret = 1;
		printf("Failed to verify signature\n");
		return ret;
	}

	// Parse metadata
	metadata* tmp = json_2_metadata((char*)md_json, size_of_md_json);
	if (!tmp) {
		printf("Failed to parse metadata\n");
		ret = 1;
		return ret;
	}

	// Process image
    pixel* processed_pixels;
	size_t processed_pixels_size = sizeof(pixel) * tmp->height * tmp->width;
    processed_pixels = (pixel*)malloc(processed_pixels_size);
	blur_5((pixel*)img_pixels, processed_pixels, tmp->width, tmp->width * tmp->height, 1.0 / 25.0);

	// Generate metadata
	int tmp_total_digests = tmp->total_digests;
	tmp->total_digests = tmp_total_digests + 1;
	int filter_idx = get_filter_idx(tmp, filter_name);
	tmp->digests = (char**)realloc(tmp->digests, sizeof(char*) * (/*decoder*/1 + /*filter*/filter_idx + 1));
	tmp->digests[filter_idx + 1] = (char*)malloc(mrenclave_len);
	memset(tmp->digests[filter_idx + 1], 0, mrenclave_len);
	memcpy(tmp->digests[filter_idx + 1], mrenclave, mrenclave_len);
	char* output_json = metadata_2_json(tmp);
	free(tmp);

	// Create buffer for signing
	// printf("processed_pixels_size: %d, size of output_json: %d\n", processed_pixels_size, strlen(output_json));
	unsigned char* data_buf = (unsigned char*)malloc(processed_pixels_size + strlen(output_json));
	memset(data_buf, 0, processed_pixels_size + strlen(output_json));
	memcpy(data_buf, processed_pixels, processed_pixels_size);
	// printf("Going to sign output_buffer with metadata(%d): [%s]\n", strlen(output_json), output_json);
	memcpy(data_buf + processed_pixels_size, output_json, strlen(output_json));

	// Generate signature
	size_t sig_size = 384;
	unsigned char* sig = (unsigned char*)malloc(sig_size);
	ret = sign(enc_priv_key, (void*)data_buf, processed_pixels_size + strlen(output_json), sig, &sig_size);
	if(ret != 0){
		free(processed_pixels);
		free(sig);
		free(data_buf);
		printf("Failed to generate signature\n");
		return ret;
	}

	// Copy processed pixels to output buffer
	memset(out_pixels, 0, processed_pixels_size);
	memcpy(out_pixels, processed_pixels, processed_pixels_size);
	memset(out_img_sig, 0, sig_size);
	memcpy(out_img_sig, sig, sig_size);
	size_of_out_img_sig = sig_size;
	memset(out_md_json, 0, strlen(output_json));
	memcpy(out_md_json, output_json, strlen(output_json));
	size_of_out_md_json = strlen(output_json);

	// Clean up
	free(processed_pixels);
	free(sig);
	free(data_buf);
	return 0;
}

#ifndef ENABLE_DCAP
extern struct ra_tls_options my_ra_tls_options;
#else
extern struct ecdsa_ra_tls_options my_ecdsa_ra_tls_options;
#endif

void t_create_key_and_x509(void* cert, size_t size_of_cert, void* actual_size_of_cert, size_t asoc)
{
    uint8_t der_key[2048];
    uint8_t der_cert[4 * 4096];
    int32_t der_key_len = sizeof(der_key);
    int32_t der_cert_len = sizeof(der_cert);

#ifndef ENABLE_DCAP
    	create_key_and_x509(der_key, &der_key_len,
    	                    der_cert, &der_cert_len,
    	                    &my_ra_tls_options);
#else
    	ecdsa_create_key_and_x509(der_key, &der_key_len,
    	                          der_cert, &der_cert_len,
    	                          &my_ecdsa_ra_tls_options);
#endif

    // Get private key
	enc_priv_key = 0;
	const unsigned char *key = (const unsigned char*)der_key;
    enc_priv_key = d2i_AutoPrivateKey(&enc_priv_key, &key, der_key_len);

	// Copy certificate to output
	memcpy(cert, der_cert, der_cert_len);
	size_of_cert = der_cert_len;
	*(size_t*)actual_size_of_cert = der_cert_len;

	// Get MRENCLAVE value from cert
#ifndef ENABLE_DCAP
		get_mrenclave(der_cert, der_cert_len, &mrenclave, &mrenclave_len);
#else
		ecdsa_get_mrenclave(der_cert, der_cert_len, &mrenclave, &mrenclave_len);
#endif
}

void t_free(void)
{
	EVP_PKEY_free(enc_priv_key);

	if(ias_pubkey)
		EVP_PKEY_free(ias_pubkey);
}
