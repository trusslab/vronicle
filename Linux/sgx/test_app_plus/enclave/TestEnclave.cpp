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
#include <openssl/bio.h>
#include <openssl/pem.h>

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

	BN_free(bn);
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



int sign_hash(EVP_PKEY* priKey, void *hash_to_be_signed, size_t len_of_hash, void *signature, void *size_of_actual_signature){
	
	// EVP_MD_CTX *mdctx;
	// const EVP_MD *md;

	// md = EVP_sha256();
	// mdctx = EVP_MD_CTX_new();
	// EVP_DigestInit_ex(mdctx, md, NULL);

	// int ret;
	// ret = EVP_SignInit_ex(mdctx, md, NULL);
	// if(ret != 1){
	// 	printf("EVP_SignInit_ex error. \n");
    //     exit(1);
	// }

	// printf("In filter signing, len_of_hash is: %d\n", len_of_hash);

	// ret = EVP_SignUpdate(mdctx, hash_to_be_signed, len_of_hash);
	// if(ret != 1){
	// 	printf("EVP_SignUpdate error. \n");
    //     exit(1);
	// }

	// unsigned int sizeOfSignature = -1;

	// ret = EVP_SignFinal(mdctx, (unsigned char*)signature, &sizeOfSignature, priKey);
	// if(ret != 1){
	// 	printf("EVP_SignFinal error : %ld. \n",  ERR_get_error());
    //     exit(1);
	// }
	// *(int*)size_of_actual_signature = sizeOfSignature;

	EVP_MD_CTX *mdctx = NULL;
	int ret = 0;
	
	// (unsigned char*)signature = NULL;
	
	/* Create the Message Digest Context */
	if(!(mdctx = EVP_MD_CTX_create())){
		printf("EVP_MD_CTX_create error: %ld. \n", ERR_get_error());
		exit(1);
	}
	
	/* Initialise the DigestSign operation - SHA-256 has been selected as the message digest function in this example */
	if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, priKey)){
		printf("EVP_DigestSignInit error: %ld. \n", ERR_get_error());
		exit(1);
	}
	
	/* Call update with the message */
	if(1 != EVP_DigestSignUpdate(mdctx, hash_to_be_signed, len_of_hash)){
		printf("EVP_DigestSignUpdate error: %ld. \n", ERR_get_error());
		exit(1);
	}
	
	/* Finalise the DigestSign operation */
	/* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
	* signature. Length is returned in slen */
	// if(1 != EVP_DigestSignFinal(mdctx, NULL, slen)) goto err;
	/* Allocate memory for the signature based on size in slen */
	// if(!(*sig = OPENSSL_malloc(sizeof(unsigned char) * (*slen)))) goto err;
	/* Obtain the signature */
	// printf("Before passing in (size_t*)size_of_actual_signature, it is: %zu\n", *(size_t*)size_of_actual_signature);
	if(1 != EVP_DigestSignFinal(mdctx, (unsigned char*)signature, (size_t*)size_of_actual_signature)){
		printf("EVP_DigestSignFinal error: %s. \n", ERR_error_string(ERR_get_error(), NULL));
		exit(1);
	};
	
	/* Success */
	ret = 1;
	
	/* Clean up */
	if(mdctx) EVP_MD_CTX_destroy(mdctx);

	// Return 0 on success, otherwise, return 1
    // EVP_MD_CTX *mdctx;
	// const EVP_MD *md;
	// unsigned char md_value[EVP_MAX_MD_SIZE];
	// unsigned int md_len, i;

	// OpenSSL_add_all_digests();

	// md = EVP_get_digestbyname("SHA256");

	// if (md == NULL) {
    //      printf("Unknown message digest %s\n", "SHA256");
    //      exit(1);
    // }

	// mdctx = EVP_MD_CTX_new();
	// EVP_DigestInit_ex(mdctx, md, NULL);

	// int ret;
	// ret = EVP_SignInit_ex(mdctx, EVP_sha256(), NULL);
	// if(ret != 1){
	// 	printf("EVP_SignInit_ex error. \n");
    //     exit(1);
	// }

	// printf("hash_to_be_signed (length = %d): {%s}\n", strlen((char*)hash_to_be_signed), (char*)hash_to_be_signed);

	// ret = EVP_SignUpdate(mdctx, (void*)hash_to_be_signed, strlen((char*)hash_to_be_signed));
	// if(ret != 1){
	// 	printf("EVP_SignUpdate error. \n");
    //     exit(1);
	// }

	// //printf("The size of pkey is: %d\n", EVP_PKEY_size(key_for_sign));
	// //printf("The len of pkey is: %d\n", i2d_PrivateKey(key_for_sign, NULL));

	// unsigned int sizeOfSignature = -1;

	// print_private_key(priKey);

	// printf("signature for filter signing before passing in (pre sizeOfSignature = %u): {%s}\n", sizeOfSignature, (unsigned char*)signature);

	// ret = EVP_SignFinal(mdctx, (unsigned char*)signature, &sizeOfSignature, priKey);
	// if(ret != 1){
	// 	printf("EVP_SignFinal error with code: %lu. \n", ERR_get_error());
    //     exit(1);
	// }
	// *(int*)size_of_actual_signature = sizeOfSignature;

	// printf("The size of signature is: %d\n", *(int*)size_of_actual_signature);

	return 0;
}

bool verify_hash(char* hash_of_file, int size_of_hash, unsigned char* signature, size_t size_of_siganture, EVP_PKEY* public_key){
	// Return true on success; otherwise, return false
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len, i;
	int ret;

	OpenSSL_add_all_digests();

    md = EVP_get_digestbyname("SHA256");

	if (md == NULL) {
         printf("Unknown message digest %s\n", "SHA256");
         exit(1);
    }

	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, md, NULL);

	ret = EVP_VerifyInit_ex(mdctx, EVP_sha256(), NULL);
	if(ret != 1){
		printf("EVP_VerifyInit_ex error. \n");
        exit(1);
	}

    // printf("hash_of_file to be verified: %s\n", hash_of_file);

	ret = EVP_VerifyUpdate(mdctx, (void*)hash_of_file, size_of_hash);
	if(ret != 1){
		printf("EVP_VerifyUpdate error. \n");
        exit(1);
	}

	ret = EVP_VerifyFinal(mdctx, signature, (unsigned int)size_of_siganture, public_key);
	// printf("EVP_VerifyFinal result: %d\n", ret);

	// Below part is for freeing data
	// For freeing evp_md_ctx
	EVP_MD_CTX_free(mdctx);

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

EVP_PKEY* unsigned_chars_to_pub_key(const unsigned char* pub_key_str, int len_of_key){
    EVP_PKEY* result_evp_key;
    result_evp_key = d2i_PublicKey(EVP_PKEY_RSA, &result_evp_key, &pub_key_str, len_of_key);
    return result_evp_key;
}

void sha256_hash_string (unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65])
{
    int i = 0;

    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf_s(outputBuffer + (i * 2), 65, "%02x", hash[i]);
    }

    outputBuffer[64] = 0;
}

int unsigned_chars_to_hash(unsigned char* data, int size_of_data, char* hash_out){
    // Return 0 on success, otherwise, return 1

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, size_of_data);
    SHA256_Final(hash, &sha256);

    sha256_hash_string(hash, hash_out);
    return 0;
}

int str_to_hash(char* str_for_hashing, size_t size_of_str_for_hashing, char* hash_out){
    // Return 0 on success, otherwise, return 1

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str_for_hashing, size_of_str_for_hashing);
    SHA256_Final(hash, &sha256);

    sha256_hash_string(hash, hash_out);
    return 0;
}

void pixels_to_raw_str(pixel* pixels_to_be_converted, int image_width, int image_height, char* output_str, int size_of_output_str){

    int total_number_of_rgb_values = image_width * image_height;

	char* temp_output_str = output_str;

    sprintf_s(temp_output_str, (size_t)size_of_output_str, "%07d,%07d,", image_width, image_height);
	temp_output_str += 16;	// For above padding
    for(int i = 0; i < total_number_of_rgb_values - 1; ++i){
        sprintf_s(temp_output_str, (size_t)size_of_output_str, "%03d,%03d,%03d,", pixels_to_be_converted[i].r, pixels_to_be_converted[i].g, pixels_to_be_converted[i].b);
		temp_output_str += 12;	// For above padding
	}
    sprintf_s(temp_output_str, (size_t)size_of_output_str, "%03d,%03d,%03d", pixels_to_be_converted[total_number_of_rgb_values - 1].r, 
				pixels_to_be_converted[total_number_of_rgb_values - 1].g, pixels_to_be_converted[total_number_of_rgb_values - 1].b);
}

size_t pixels_to_linked_pure_str(pixel* pixels_to_be_converted, int total_number_of_rgb_values, char* output_str){
	// Return the len of (fake) str
	char* temp_output_str = output_str;
	size_t len_of_str = 0;
	for(int i = 0; i < total_number_of_rgb_values - 1; ++i){
        memcpy(temp_output_str++, &pixels_to_be_converted[i].r, 1);
        memcpy(temp_output_str++, &pixels_to_be_converted[i].g, 1);
        memcpy(temp_output_str++, &pixels_to_be_converted[i].b, 1);
		len_of_str += 3;
	}
	// printf("Testing if we copy it successfully: %s\n", &(output_str[7692]));
	return len_of_str;
}

void t_sgxver_call_apis(void *image_pixels, size_t size_of_image_pixels, int image_width, int image_height, 
						void* hash_of_original_image, int size_of_hooi, void *signature, size_t size_of_actual_signature,
						void *original_pub_key_str, long original_pub_key_str_len, 
						void* processed_pixels, void* runtime_result, int size_of_runtime_result, 
						void* char_array_for_processed_img_sign, int size_of_cafpis, 
						void* hash_of_processed_image, int size_of_hopi,
						void* filter_pri_key_str, long filter_pri_key_str_len, 
						void* processed_img_signautre, size_t size_of_pis, 
						void* size_of_actual_processed_img_signature, size_t sizeof_soapis)
{

	// In: image_pixels, size_of_image_pixels, image_width, image_height, signature, size_of_actual_signature, original_pub_key_str, original_pub_key_str_len,
	// size_of_runtime_result, size_of_cafpis, size_of_pis, size_of_hopi, filter_pri_key_str, filter_pri_key_str_len, sizeof_soapis, 
	// ===========================================
	// Out: processed_pixels, runtime_result, char_array_for_processed_img_sign, processed_img_signautre, hash_of_processed_image, 
	// size_of_actual_processed_img_signature, 
	// ===========================================

	// rsa_key_gen();
	// char* mKey = "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAopF5nggjEqgP3INF663t\n8+HPt90WZ8z5g6NYr228TfKGywfnmpmLuzt+rc2zMK229lXSNYCnKMvF0ge4gYHI\nv1rjsQiDIZmGVGNsudIMm02qlBLeLtegFjVNTc5562D561pV96t4dIPHsykpzjZO\nAMXP8BUuHJeeNdPZFekbfID0ec5NTumLnZGrSxh/PngHEkmWhn6mjUmooVxvliyn\n1dqbgwOiLSpxf+xmIFPCgXPBJDGhX3jc/j6jEh6ydR3nYw9q4LdC18REmHl6EUmD\nTBW6KyTHCS1RKEXpWtGgR17o4ahqfELIQKXyQEcOhyOBy8HdIdLsHA4gxVPXYq07\nLj8M4RZbtFdtlJlMZuqY1b7wm3GpUGpcPelGaYfeftneQh9VTAfEr3Mx4XbNCCqc\n3y6YRJacaZcZHaF7hAz/lRPCXIQIE3nG8fQq5wcCkvAJ8hqVxbU6YNe0MswSO72b\nyG0h6gC/epbiJSUEcPZY5bgoOkcEgveH+u7mC0NCfPh5IrxTGTXmi5qs/vZ/f3nV\nSLD/oGCuA6Vhe1dt4Ws5e+fVG+0mNI7RZRty2rAY0AYeQOzMEyjKhp9cl6HaHF2c\nHUaxu/wSQ3D8HFyYmeVjXi0VFTDpu/qmiH36ryncqilBCeeju75Vm4UqH3/0vRto\n0/89p9eFt0wh+1y+BaN/slcCAwEAAQ==\n-----END PUBLIC KEY-----\n";
	
	// Convert str to public key
	BIO* bo = BIO_new( BIO_s_mem() );
	BIO_write(bo, (char*)original_pub_key_str, original_pub_key_str_len);
	// BIO_write(bo, (char*)mKey, strlen(mKey));
	EVP_PKEY* pukey = 0;
	PEM_read_bio_PUBKEY(bo, &pukey, 0, 0);
	BIO_free(bo);
    // printf("Hello from enclave!\n");


	// // Verify signature
	// bool result_of_verification = verify_hash((char*)hash_of_original_image, size_of_hooi, (unsigned char*)signature, size_of_actual_signature, (EVP_PKEY*)pukey);
	// // printf("(Inside Enclave)result_of_verification: %d\n", result_of_verification);
	// if(result_of_verification != 1){
	// 	*(int*)runtime_result = 1;
	// 	return;
	// }

	// // Process image
	// pixel* img_pixels = (pixel*) image_pixels;
	// printf("The very first pixel(Before processed by filter): R: %d; G: %d; B: %d\n", (int)img_pixels[0].r, (int)img_pixels[0].g, (int)img_pixels[0].b);
	// // blur(img_pixels, (pixel*)processed_pixels, image_width, image_width * image_height, 5);
	// blur_5(img_pixels, (pixel*)processed_pixels, image_width, image_width * image_height, 1.0 / 25.0);
	// printf("The very first pixel(After processed by filter): R: %d; G: %d; B: %d\n", (int)((pixel*)processed_pixels)[0].r, (int)((pixel*)processed_pixels)[0].g, (int)((pixel*)processed_pixels)[0].b);

	// // Prepare for output processed image file str
	// //pixels_to_raw_str((pixel*)processed_pixels, image_width, image_height, (char*)char_array_for_processed_img_sign, size_of_cafpis);
	// size_t len_of_processed_image_str = pixels_to_linked_pure_str((pixel*)processed_pixels, image_width * image_height, (char*)char_array_for_processed_img_sign);

	// // Generate hash of processed image
	// // printf("The len of char_array_for_processed_img_sign is: %d\n", len_of_processed_image_str);
	// // str_to_hash((char*)char_array_for_processed_img_sign, strlen((char*)char_array_for_processed_img_sign), (char*)hash_of_processed_image);
	// str_to_hash((char*)char_array_for_processed_img_sign, len_of_processed_image_str, (char*)hash_of_processed_image);
	// // str_to_hash((char*)processed_pixels, strlen((char*)processed_pixels), (char*)hash_of_processed_image);
	// // printf("hash_of_processed_image(new!): %s\n", (char*)hash_of_processed_image);

	// Convert str to filter private key
	BIO* filter_pri_key_bo = BIO_new( BIO_s_mem() );
	BIO_write(filter_pri_key_bo, (char*)filter_pri_key_str, filter_pri_key_str_len);
	// BIO_write(bo, (char*)mKey, strlen(mKey));
	EVP_PKEY* filter_private_key = 0;
	PEM_read_bio_PrivateKey(filter_pri_key_bo, &filter_private_key, 0, 0);
	BIO_free(filter_pri_key_bo);

	// // Generate signature
	// *(size_t*)size_of_actual_processed_img_signature = size_of_pis;
	// int result_of_filter_signing = sign_hash(filter_private_key, hash_of_processed_image, (size_t)size_of_hopi, processed_img_signautre, size_of_actual_processed_img_signature);
	// if(result_of_filter_signing != 0){
	// 	*(int*)runtime_result = 2;
	// 	EVP_PKEY_free(pukey);
	// 	return;
	// }

	// Free Memory
	EVP_PKEY_free(pukey);
	EVP_PKEY_free(filter_private_key);

	*(int*)runtime_result = 0;

	// freeEverthing();
}

void t_sgxssl_call_apis(void* evp_pkey_v)
{
	return;
}

