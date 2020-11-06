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

// Include for Decoder
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>

#include "metadata.h"

#include "decoder/src/h264bsd_decoder.h"
#include "decoder/src/h264bsd_util.h"

#include "yuvconverter.h"

#define ADD_ENTROPY_SIZE	32

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
    char buf[BUFSIZ] = {"[decoder:TestEnclave]: \0"};
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
char* mrenclave;
size_t mrenclave_len;

int freeEverthing(){
	EVP_PKEY_free(enc_priv_key);
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

bool verify_hash(void* hash_of_file, int size_of_hash, unsigned char* signature, size_t size_of_siganture, EVP_PKEY* public_key){
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
			printf("EVP_VerifyInit_ex error. \n");
			break;
		}

 	    // printf("hash_of_file to be verified: %s (len: %i)\n", hash_of_file, size_of_hash);

		ret = EVP_VerifyUpdate(mdctx, hash_of_file, size_of_hash);
		if(ret != 1){
			printf("EVP_VerifyUpdate error. \n");
			break;
		}

		ret = EVP_VerifyFinal(mdctx, signature, (unsigned int)size_of_siganture, public_key);
		if(ret != 1){
			printf("EVP_VerifyFinal error. \n");
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

int verify_cert(X509* cert_to_verify, EVP_PKEY* pubkey_for_verify)
{
    int r = X509_verify(cert_to_verify, pubkey_for_verify);
    return r;
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

int t_sgxver_decode_content(
	void* input_content_buffer, long size_of_input_content_buffer, 
	void* md_json, long md_json_len,
	void* vendor_pub, long vendor_pub_len,
	void* camera_cert, long camera_cert_len,
	void* vid_sig, size_t vid_sig_len,
	u32* frame_width, u32* frame_height, int* num_of_frames, 
	void* output_rgb_buffer, void* output_sig_buffer, void* output_md_buffer) {

    int res = -1;
	// In: void* input_content_buffer
	// Out: void* frame_width, void* frame_height, void* num_of_frames, void* output_rgb_buffer
	// Common: long size_of_input_content_buffer, size_t size_of_u32, size_t size_of_int, size_of_u8

	// Verify certificate
	BIO* bo_pub = BIO_new( BIO_s_mem() );
	BIO_write(bo_pub, (char*)vendor_pub, vendor_pub_len);

	EVP_PKEY* vendor_pubkey = EVP_PKEY_new();
	vendor_pubkey = PEM_read_bio_PUBKEY(bo_pub, &vendor_pubkey, 0, 0);
	BIO_free(bo_pub);

	BIO* bo = BIO_new( BIO_s_mem() );
	BIO_write(bo, (char*)camera_cert, camera_cert_len);
    X509* cam_cert;
    cam_cert = X509_new();
	cam_cert = PEM_read_bio_X509(bo, &cam_cert, 0, NULL);
	BIO_free(bo);

	res = verify_cert(cam_cert, vendor_pubkey);

	if(res != 1){
		printf("Verify certificate failed\n");
		return 1;
	}

	// Verify signature
	EVP_PKEY* pukey = EVP_PKEY_new();
	pukey = X509_get_pubkey(cam_cert);
	unsigned char* buf = (unsigned char*)malloc(size_of_input_content_buffer + md_json_len);
	if (!buf) {
		printf("No memory left\n");
		return 1;
	}
	memset(buf, 0, size_of_input_content_buffer + md_json_len);
	memcpy(buf, input_content_buffer, size_of_input_content_buffer);
	memcpy(buf + size_of_input_content_buffer, md_json, md_json_len);
	// printf("Size of input_content_buffer is: %ld, size of md_json is: %ld, size of vid_sig: %d\n", size_of_input_content_buffer, md_json_len, vid_sig_len);
	res = verify_hash(buf, size_of_input_content_buffer + md_json_len, (unsigned char*)vid_sig, vid_sig_len, pukey);
	free(buf);
	if(res != 1){
		printf("Verify signature failed\n");
		return 1;
	}

	// Cleanup
	X509_free(cam_cert);
	EVP_PKEY_free(vendor_pubkey);
	EVP_PKEY_free(pukey);

	u32 status;
	storage_t dec;
	status = h264bsdInit(&dec, HANTRO_FALSE);

	if (status != HANTRO_OK) {
		// fprintf(stderr, "h264bsdInit failed\n");
		printf("h264bsdInit failed\n");
		exit(1);
	}

	u8* byteStrm = (u8*)input_content_buffer;
	u32 readBytes;
	u32 len = size_of_input_content_buffer;
	int numPics = 0;
	size_t frame_size_in_rgb = 0;
	u8* pic;
	u8* pic_rgb = NULL;
	u32 picId, isIdrPic, numErrMbs;
	u32 top, left, width, height, croppingFlag;
	metadata* tmp;
	char* output_json;
	unsigned char* data_buf = NULL;
	// Obtain signature length and allocate memory for signature
	size_t pic_sig_len = 0;
	unsigned char* pic_sig = NULL;
	int tmp_total_digests = 0;

	u8* output_sig_buffer_temp = (u8*)output_sig_buffer;
	u8* output_rgb_buffer_temp = (u8*)output_rgb_buffer;
	u8* output_md_buffer_temp = (u8*)output_md_buffer;

	while (len > 0) {
		u32 result = h264bsdDecode(&dec, byteStrm, len, 0, &readBytes);
		len -= readBytes;
		byteStrm += readBytes;

		switch (result) {
		case H264BSD_PIC_RDY:
			// Extract frame
			pic = h264bsdNextOutputPicture(&dec, &picId, &isIdrPic, &numErrMbs);
			++numPics;
			if(pic_rgb == NULL){
				printf("No valid video header detected, exiting...\n");
				exit(1);
			}

			// Convert frame to RGB packed format
			yuv420_prog_planar_to_rgb_packed(pic, pic_rgb, width, height);

			// Generate metadata
			tmp = json_2_metadata((char*)md_json, md_json_len);
			if (!tmp) {
				printf("Failed to parse metadata\n");
				exit(1);
			}
			tmp->frame_id = numPics - 1;
			tmp_total_digests = tmp->total_digests;
			tmp->total_digests = tmp_total_digests + 1;
			tmp->digests = (char**)malloc(sizeof(char*) * 1);
			tmp->digests[0] = (char*)malloc(mrenclave_len);
			memset(tmp->digests[0], 0, mrenclave_len);
			memcpy(tmp->digests[0], mrenclave, mrenclave_len);
			output_json = metadata_2_json(tmp);

			// Create buffer for signing
			data_buf = (unsigned char*)malloc(frame_size_in_rgb + strlen(output_json));
			memset(data_buf, 0, frame_size_in_rgb + strlen(output_json));
			memcpy(data_buf, pic_rgb, frame_size_in_rgb);
			memcpy(data_buf + frame_size_in_rgb, output_json, strlen(output_json));

			// Generate signature
			res = sign(enc_priv_key, data_buf, frame_size_in_rgb + strlen(output_json), pic_sig, &pic_sig_len);
			// printf("orig size: %li, sig size: %li, json: %s\n", frame_size_in_rgb + strlen(output_json), pic_sig_len, output_json);
			if(res != 0){
				printf("Signing frame failed\n");
				break;
			}

			// Save signature to output buffer
			memset(output_sig_buffer_temp, 0, pic_sig_len);
			memcpy(output_sig_buffer_temp, pic_sig, pic_sig_len);
			output_sig_buffer_temp += pic_sig_len;
			memset(pic_sig, 0, pic_sig_len);

			// Save frame to output buffer
			memset(output_rgb_buffer_temp, 0, frame_size_in_rgb);
			memcpy(output_rgb_buffer_temp, pic_rgb, frame_size_in_rgb);
			output_rgb_buffer_temp += frame_size_in_rgb;
			memset(pic_rgb, 0, frame_size_in_rgb);

			// Save metadata to output buffer
			memset(output_md_buffer_temp, 0, strlen(output_json));
			memcpy(output_md_buffer_temp, output_json, strlen(output_json));
			output_md_buffer_temp += strlen(output_json);

			// Clean up
			free_metadata(tmp);
			free(output_json);
			free(data_buf);

			break;
		case H264BSD_HDRS_RDY:
			// Obtain frame parameters
			h264bsdCroppingParams(&dec, &croppingFlag, &left, &width, &top, &height);
			if (!croppingFlag) {
			width = h264bsdPicWidth(&dec) * 16;
			height = h264bsdPicHeight(&dec) * 16;
			}
			// Allocate memory for frame
			if(pic_rgb == NULL){
				frame_size_in_rgb = width * height * 3;
				pic_rgb = (u8*)malloc(frame_size_in_rgb);
				InitConvt(width, height);
			}
			// Call sign() with NULL to obtain signature length
			res = sign(enc_priv_key, pic_rgb, frame_size_in_rgb, NULL, &pic_sig_len);
			if(res != 0){
				printf("Failed to obtain signature length\n");
				return res;
			}
			pic_sig = (unsigned char*)malloc(pic_sig_len);
			break;
		case H264BSD_RDY:
			break;
		case H264BSD_ERROR:
			printf("Error\n");
			return 1;
		case H264BSD_PARAM_SET_ERROR:
			printf("Param set error\n");
			return 1;
		}
	}

	h264bsdShutdown(&dec);
	// Free other things
	if(pic_rgb)
		free(pic_rgb);
	if(pic_sig)
		free(pic_sig);

	// Before we go out of enclave, assign all required output values
	*frame_width = width;
	*frame_height = height;
	*num_of_frames = numPics;

	return res;
}

extern struct ra_tls_options my_ra_tls_options;

void t_create_key_and_x509(void* cert, size_t size_of_cert, void* actual_size_of_cert, size_t asoc)
{
    uint8_t der_key[2048];
    uint8_t der_cert[4 * 4096];
    int32_t der_key_len = sizeof(der_key);
    int32_t der_cert_len = sizeof(der_cert);

    create_key_and_x509(der_key, &der_key_len,
                        der_cert, &der_cert_len,
                        &my_ra_tls_options);
    // Get private key
	enc_priv_key = 0;
	const unsigned char *key = (const unsigned char*)der_key;
    enc_priv_key = d2i_AutoPrivateKey(&enc_priv_key, &key, der_key_len);

	// Copy certificate to output
	memcpy(cert, der_cert, der_cert_len);
	size_of_cert = der_cert_len;
	*(size_t*)actual_size_of_cert = der_cert_len;

	// Get MRENCLAVE value from cert
	get_mrenclave(der_cert, der_cert_len, &mrenclave, &mrenclave_len);
}

void t_free(void)
{
	freeEverthing();
}
