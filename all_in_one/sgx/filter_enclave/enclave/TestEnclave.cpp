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


// #include <stdio.h>      /* vsnprintf */
// #include <stdarg.h>
// #include <string.h>

// #include <errno.h>
// #include <limits.h>

// #include "TestEnclave.h"
// #include "TestEnclave_t.h"  /* print_string */
// #include "tSgxSSL_api.h"
// #include "SampleFilters.h"
// #include "ra-attester.h"
// #include "ra-challenger.h"

// #include <openssl/ec.h>
// #include <openssl/bn.h>
// #include <openssl/rsa.h>
// #include <openssl/evp.h>
// #include <openssl/err.h>
// #include <openssl/rand.h>
// #include <openssl/bio.h>
// #include <openssl/pem.h>

// #include "metadata.h"

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

#include "minih264e.h"
#include "metadata.h"
#include <math.h>

// Include for Decoder
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>

#include "decoder/src/h264bsd_decoder.h"
#include "decoder/src/h264bsd_util.h"

#include "yuvconverter.h"
#define MINIMP4_IMPLEMENTATION
#include "minimp4.h"

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

int is_source_video_verified = -3;
int is_decoding_finished = 0;

// // For Decoding use
// char* s_md_json;
// long s_md_json_len;
// u32 status;
// storage_t dec;
// u8* byteStrm;
// u32 readBytes;
// u32 len;
// int numPics = 0;
// size_t frame_size_in_rgb = 0;
// u8* pic;
// size_t pic_sig_len = 0;
// u32 picId, isIdrPic, numErrMbs;
// u32 top, left, width = 0, height = 0, croppingFlag;
// metadata* tmp;
// unsigned char* data_buf = NULL;
// // Obtain signature length and allocate memory for signature
// int tmp_total_digests = 0;

// For ffmpeg Decoder
// TO-DO: Move this extern "C" to header files and add #if defined (__cplusplus)
extern "C" 
{
#include "libavcodec/avcodec.h"
#include "ffmpeg_decoder/decoder.h"
}
#define BUFFER_CAPACITY 4096*64
extern AVCodec ff_h264_decoder;
extern AVCodecParser ff_h264_parser;
AVCodec *codec;
AVCodecContext *codec_ctx;
AVCodecParserContext* parser;
AVFrame *frame;
int ending = 0;
int frame_index = 0;
uint8_t buffer[BUFFER_CAPACITY];
uint8_t* buf = buffer;
int buf_size = 0;
AVPacket packet;
u8 *byteStrm, *audio_strm, *audio_meta_strm;
unsigned char *audio_sig;
u8 *tempByteStrm; // For (moving) byteStrm pointer...
size_t readBytes;
size_t len;
size_t size_of_audio_strm = 0, size_of_audio_meta_strm = 0, size_of_audio_sig = 0;

// For Decoding use (New FFmpeg based)
char* s_md_json;
long s_md_json_len;
u32 status;
storage_t dec;
int numPics = 0;
size_t frame_size_in_rgb = 0;
u8* pic;
size_t pic_sig_len = 0;
u32 picId, isIdrPic, numErrMbs;
u32 top, left, width = 0, height = 0, croppingFlag;
metadata* tmp;
unsigned char* data_buf = NULL;
// Obtain signature length and allocate memory for signature
int tmp_total_digests = 0;

// For Encoding use
H264E_persist_t *enc;
H264E_scratch_t *scratch;
H264E_create_param_t create_param;
H264E_run_param_t run_param;
H264E_io_yuv_t yuv;
H264E_io_yuy2_t yuyv;
uint8_t *buf_in, *buf_save;
uint8_t *temp_buf_in, *p;
uint8_t *coded_data, *all_coded_data;
int sizeof_coded_data, frame_size, yuyv_frame_size, temp_frame_size, g_w, g_h, _qp, frame_counter;
size_t total_coded_data_size;
unsigned char* total_coded_data;
cmdline* cl;
metadata* in_md;
metadata* out_md;

// For muxing
uint8_t *mp4_strm = NULL;
size_t sizeof_mp4_strm = 0;
size_t sizeof_current_mp4_strm = 0;
size_t sizeof_used_mp4_strm = 0;
size_t standard_block_size = 1000000;	// For controlling how mp4_strm grows

static void psnr_init()
{
    memset(&g_psnr, 0, sizeof(g_psnr));
}

static void psnr_add(unsigned char *p0, unsigned char *p1, int w, int h, int bytes)
{
    int i, k;
    for (k = 0; k < 3; k++)
    {
        double s = 0;
        for (i = 0; i < w*h; i++)
        {
            int d = *p0++ - *p1++;
            s += d*d;
        }
        g_psnr.count[k] += w*h;
        g_psnr.noise[k] += s;
        if (!k) w >>= 1, h >>= 1;
    }
    g_psnr.count[3] = g_psnr.count[0] + g_psnr.count[1] + g_psnr.count[2];
    g_psnr.noise[3] = g_psnr.noise[0] + g_psnr.noise[1] + g_psnr.noise[2];
    g_psnr.frames++;
    g_psnr.bytes += bytes;
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

size_t calcDecodeLength(const char* b64input) {
    size_t len = strlen(b64input), padding = 0;
    // printf("The len in calc is: %d\n", (int)len);

    if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len-1] == '=') //last char is =
        padding = 1;

    // printf("The padding in calc is: %d\n", (int)padding);
    return (len*3)/4 - padding;
}

void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length) {
    BIO *bio, *b64;

    int decodeLen = calcDecodeLength(b64message);
    // printf("decodeLen is: %d\n", decodeLen);
    *buffer = (unsigned char*)malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    *length = BIO_read(bio, *buffer, strlen(b64message));
    // printf("The length is: %d\n", (int)*length);
    // printf("The buffer is: %s\n", buffer);
    BIO_free_all(bio);
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

int sign_4_encoder(EVP_PKEY* priKey, unsigned char *data, size_t data_size, unsigned char** sig, size_t *sig_size){
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
        if(1 != EVP_DigestSignUpdate(mdctx, data, data_size)){
            printf("EVP_DigestSignUpdate error: %ld. \n", ERR_get_error());
            ret = 1;
            break;
        }
    
        /* Finalise the DigestSign operation */
        /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
        * signature. Length is returned in slen */
        if (!sig) {
            if (1 != EVP_DigestSignFinal(mdctx, NULL, sig_size)) {
                printf("[EncoderEnclave]: EVP_DigestSignFinal error: %s. \n", ERR_error_string(ERR_get_error(), NULL));
                ret = 1;
                break;
            }
        } else {
            if (1 != EVP_DigestSignFinal(mdctx, *sig, sig_size)) {
                printf("[EncoderEnclave]: EVP_DigestSignFinal error: %s. \n", ERR_error_string(ERR_get_error(), NULL));
                ret = 1;
                break;
            }
        }
    } while (0);
    
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

int verify_sig_4_encoder (void* file, size_t size_of_file,
                unsigned char* signature, size_t size_of_siganture,
                EVP_PKEY* public_key)
{
    // Return true on success; otherwise, return false
    EVP_MD_CTX *mdctx = NULL;
    const EVP_MD *md = NULL;
    int ret = 0;

    OpenSSL_add_all_digests();

	do {
		md = EVP_get_digestbyname("SHA256");

		if (md == NULL) {
			printf("[EncoderEnclave]: Unknown message digest %s\n", "SHA256");
			break;
		}

		mdctx = EVP_MD_CTX_new();
		EVP_DigestInit_ex(mdctx, md, NULL);

		ret = EVP_VerifyInit_ex(mdctx, EVP_sha256(), NULL);
		if(ret != 1){
			printf("[EncoderEnclave]: EVP_VerifyInit_ex error: %s. \n", ERR_error_string(ERR_get_error(), NULL));
			break;
		}

		ret = EVP_VerifyUpdate(mdctx, file, size_of_file);
		if(ret != 1){
			printf("[EncoderEnclave]: EVP_VerifyUpdate error: %s. \n", ERR_error_string(ERR_get_error(), NULL));
			break;
		}

		ret = EVP_VerifyFinal(mdctx, signature, (unsigned int)size_of_siganture, public_key);
		if(ret != 1){
			printf("[EncoderEnclave]: EVP_VerifyFinal error: %s. \n", ERR_error_string(ERR_get_error(), NULL));
			break;
		}
	} while(0);

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

typedef struct
{
    uint8_t *buffer;
    ssize_t size;
} INPUT_BUFFER;

static int read_callback(int64_t offset, void *buffer, size_t size, void *token)
{
    INPUT_BUFFER *buf = (INPUT_BUFFER*)token;
    size_t to_copy = MINIMP4_MIN(size, buf->size - offset - size);
    memcpy(buffer, buf->buffer + offset, to_copy);
    return to_copy != size;
}

static ssize_t get_nal_size(uint8_t *buf, ssize_t size)
{
    ssize_t pos = 3;
    while ((size - pos) > 3)
    {
        if (buf[pos] == 0 && buf[pos + 1] == 0 && buf[pos + 2] == 1)
            return pos;
        if (buf[pos] == 0 && buf[pos + 1] == 0 && buf[pos + 2] == 0 && buf[pos + 3] == 1)
            return pos;
        pos++;
    }
    return size;
}

int expand_allocation_space_if_necessary(void** pointer_to_check, size_t *size_of_data, size_t current_used_size, size_t size_to_write, size_t size_to_expand) 
{
	// Return 0 for success, otherwise fail

	while ((*size_of_data - current_used_size) < size_to_write) {
		// printf("[decoder:TestEnclave]: expand_allocation_space_if_necessary: Going to expand to %d\n", *size_of_data + size_to_expand);
		*pointer_to_check = realloc(*pointer_to_check, *size_of_data + size_to_expand);
		// printf("[decoder:TestEnclave]: expand_allocation_space_if_necessary: Expanded to %d\n", *size_of_data + size_to_expand);
		if (*pointer_to_check == NULL) {
			printf("[decoder:TestEnclave]: expand_allocation_space_if_necessary is failed when trying to resize from %d to %d...\n", *size_of_data, current_used_size);
			return 1;
		}
		*size_of_data += size_to_expand;
	}
	// printf("[decoder:TestEnclave]: After expand_allocation_space_if_necessary, size_of_data is now expanded to: %d\n", *size_of_data);
	return 0;
}

int adjust_allocation_space_as_needed(void** pointer_to_check, size_t *size_of_data, size_t current_used_size)
{
	// Return 0 for success, otherwise fail
	if (*size_of_data < current_used_size) {
		printf("[decoder:TestEnclave]: adjust_allocation_space_as_needed is failed when trying to resize from %d to %d...\n", *size_of_data, current_used_size);
		return 1;
	} else if (*size_of_data > current_used_size) {
		*pointer_to_check = realloc(*pointer_to_check, current_used_size);
		if (*pointer_to_check == NULL) {
			printf("[decoder:TestEnclave]: adjust_allocation_space_as_needed is failed when trying to resize from %d to %d...\n", *size_of_data, current_used_size);
			return 1;
		}
		*size_of_data = current_used_size;
	}
	return 0;
}

static int write_callback(int64_t offset, const void *buffer, size_t size, void *token)
{
	// Return 0 for success, otherwise fail

    // FILE *f = (FILE*)token;
    // fseek(f, offset, SEEK_SET);
    // return fwrite(buffer, 1, size, f) != size;

    // Don't forget to play the trick: passing **token into the *token argument...(since otherwise have to modify the whole minimp4.h)
    // Also, we are assuming token is the mp4_strm

    // printf("[EncoderEnclave]: mux: write_callback is called...\n");
    if (expand_allocation_space_if_necessary((void**) token, &sizeof_current_mp4_strm, sizeof_used_mp4_strm, size, standard_block_size) != 0) {
        return 1;
    }
    // printf("[EncoderEnclave]: mux: write_callback is called 1...\n");

    memcpy((*(void**)token) + offset, buffer, size);
    // printf("[EncoderEnclave]: mux: write_callback is called 2...\n");
    sizeof_used_mp4_strm += size;
    return 0;
}

int mux(metadata* video_meta,
        uint8_t* video_strm, size_t video_strm_size,
        uint8_t* audio_dsi_strm, size_t audio_dsi_strm_size,
        uint8_t* audio_strm, size_t audio_strm_size,
        uint8_t** mp4_buffer, size_t* mp4_buffer_size) {
    // Return 0 for success, otherwise fail
    // Note that mp4_buffer will be newly allocated here, so make sure you free it

    // printf("[EncoderEnclave]: mux: checkpoint 1...\n");

    int is_hevc = 0;    // TO-DO: Consider supporting HEVC
    int sequential_mode = 0;    // TO-DO: Consider supporting sequential_mode
    int fragmentation_mode = 0; // TO-DO: Consider supporting fragmentation_mode
    
    // printf("[EncoderEnclave]: mux: checkpoint 2...\n");

    // Init mp4_buffer
    sizeof_current_mp4_strm = standard_block_size;
    *mp4_buffer = (uint8_t*) malloc(sizeof_current_mp4_strm);

    // printf("[EncoderEnclave]: mux: checkpoint 3...\n");

    MP4E_mux_t *mux;
    mp4_h26x_writer_t mp4wr;
    mux = MP4E_open(sequential_mode, fragmentation_mode, mp4_buffer, write_callback);

    if (mux == 0) {
        printf("[EncoderEnclave]: MP4E_open failed...\n");
        return 1;
    }
    
    // printf("[EncoderEnclave]: mux: checkpoint 4...\n");

    if (MP4E_STATUS_OK != mp4_h26x_write_init(&mp4wr, mux, 352, 288, is_hevc))
    {
        printf("[EncoderEnclave]: error: mp4_h26x_write_init failed\n");
        return 1;
    }
    
    // printf("[EncoderEnclave]: mux: checkpoint 5...\n");

    // Start of audio part
    uint8_t *audio_dsi_strm_temp = audio_dsi_strm;
    // Get sample rate and timescale
    unsigned int sample_rate = 0, timescale = 0;
    memcpy(&sample_rate, audio_dsi_strm_temp, sizeof(unsigned int));
    audio_dsi_strm_temp += sizeof(unsigned int);
    memcpy(&timescale, audio_dsi_strm_temp, sizeof(unsigned int));
    audio_dsi_strm_temp += sizeof(unsigned int);
    
    // printf("[EncoderEnclave]: mux: checkpoint 6...\n");

    // Set track data
    MP4E_track_t tr;
    tr.track_media_kind = e_audio;
    tr.language[0] = 'u';
    tr.language[1] = 'n';
    tr.language[2] = 'd';
    tr.language[3] = 0;
    tr.object_type_indication = MP4_OBJECT_TYPE_AUDIO_ISO_IEC_14496_3;
    tr.time_scale = timescale;
    tr.default_duration = 0;
    tr.u.a.channelcount = 2;
    tr.u.a.samplerate_hz = sample_rate;
    int audio_track_id = MP4E_add_track(mux, &tr);
    
    // printf("[EncoderEnclave]: mux: checkpoint 7...\n");

    // Set DSI
    unsigned int dsi_bytes = 0;
    memcpy(&dsi_bytes, audio_dsi_strm_temp, sizeof(unsigned int));
    audio_dsi_strm_temp += sizeof(unsigned int);
    MP4E_set_dsi(mux, audio_track_id, audio_dsi_strm_temp, dsi_bytes);
    // End of audio part
    
    // printf("[EncoderEnclave]: mux: checkpoint 8...\n");

    int counter = 0;
    uint8_t *buf_h264_audio_temp = audio_strm;
    uint8_t *video_strm_temp = video_strm;
    
    // printf("[EncoderEnclave]: mux: checkpoint 9...video_strm_size: %d\n", video_strm_size);

    while (video_strm_size > 0)
    {
        // printf("[EncoderEnclave]: mux: checkpoint 9.1...\n");

        ssize_t nal_size = get_nal_size(video_strm_temp, video_strm_size);

        // printf("[EncoderEnclave]: mux: checkpoint 9.2...nal_size: %d\n", nal_size);

        if (nal_size < 4)
        {
            video_strm_temp  += 1;
            video_strm_size -= 1;
            continue;
        }

        // printf("[EncoderEnclave]: mux: checkpoint 9.3...video_meta->frame_rate: %d\n", video_meta->frame_rate);

        if (MP4E_STATUS_OK != mp4_h26x_write_nal(&mp4wr, video_strm_temp, nal_size, 90000/video_meta->frame_rate))
        {
            printf("[EncoderEnclave]: error: mp4_h26x_write_nal failed\n");
            return 1;
        }

        // printf("[EncoderEnclave]: mux: checkpoint 9.4...\n");

        video_strm_temp  += nal_size;
        video_strm_size -= nal_size;
        
        // printf("[EncoderEnclave]: mux: checkpoint 9.5...\n");

        if (fragmentation_mode && !mux->fragments_count)
            continue; /* make sure mp4_h26x_write_nal writes sps/pps, because in fragmentation mode first MP4E_put_sample writes moov with track information and dsi.
                         all tracks dsi must be set (MP4E_set_dsi) before first MP4E_put_sample. */
        ++counter;

        // printf("[EncoderEnclave]: mux: checkpoint 9.6...\n");
    }

    // printf("[EncoderEnclave]: mux: checkpoint 10...\n");

    // Put audio data to container
    unsigned int sample_count = 0;

    // printf("[EncoderEnclave]: mux: checkpoint 11...\n");

    memcpy(&sample_count, buf_h264_audio_temp, sizeof(unsigned int));

    // printf("[EncoderEnclave]: mux: checkpoint 12...\n");

    // printf("[EncoderEnclave]: read sample_count: %u\n", sample_count);
    buf_h264_audio_temp += sizeof(unsigned int);

    // printf("[EncoderEnclave]: mux: checkpoint 13...\n");

    for (int i = 0; i < sample_count; ++i){
        unsigned frame_bytes = 0;
        memcpy(&frame_bytes, buf_h264_audio_temp, sizeof(unsigned));
        // if (i == 3) printf("[EncoderEnclave]: read frame_bytes: %u\n", frame_bytes);
        buf_h264_audio_temp += sizeof(unsigned);
        if (MP4E_STATUS_OK != MP4E_put_sample(mux, audio_track_id, buf_h264_audio_temp, frame_bytes, 1024, MP4E_SAMPLE_RANDOM_ACCESS))
        {
            printf("error: MP4E_put_sample failed\n");
            exit(1);
        }
        buf_h264_audio_temp += frame_bytes;
    }
    // End of audio part

    // printf("[EncoderEnclave]: mux: checkpoint 14...\n");

    MP4E_close(mux);
    mp4_h26x_write_close(&mp4wr);
    
    // Muxing finished!
    if (adjust_allocation_space_as_needed((void**) mp4_buffer, &sizeof_current_mp4_strm, sizeof_used_mp4_strm) != 0) {
		return 1;
	}
    *mp4_buffer_size = sizeof_used_mp4_strm;

    printf("[EncoderEnclave]: mux: mp4_buffer_size: %d\n", *mp4_buffer_size);

    return 0;
}

int demux(uint8_t *input_buf, size_t input_size, 
	uint8_t **video_out, size_t *size_of_video_out, // TO-DO: Might want to change u32 to size_t
	uint8_t **audio_out, size_t *size_of_audio_out,
	uint8_t **audio_meta_out, size_t *size_of_audio_meta_out,
	int ntrack)
{
	// Return 0 on success, otherwise fail

	// This will allocate space for video_out, audio_out, audio_meta_out, remember to clean them
	// Sizes will be stored accordingly in size_of_video_out, size_of_audio_out, size_of_audio_meta_out

    int /*ntrack, */i, spspps_bytes;
    const void *spspps;
    INPUT_BUFFER buf = { input_buf, input_size };
    MP4D_demux_t mp4 = { 0, };
    MP4D_open(&mp4, read_callback, &buf, input_size);

	size_t standard_block_size = 1000000;	// For controlling how video_out, audio_out, audio_meta_out grow

	size_t current_size_of_video_out = standard_block_size;
	size_t current_used_size_of_video_out = 0;
	size_t current_size_of_audio_out = standard_block_size;
	size_t current_used_size_of_audio_out = 0;
	size_t current_size_of_audio_meta_out = standard_block_size;
	size_t current_used_size_of_audio_meta_out = 0;

	*video_out = (uint8_t*) malloc(current_size_of_video_out);
	*audio_out = (uint8_t*) malloc(current_size_of_audio_out);
	*audio_meta_out = (uint8_t*) malloc(current_size_of_audio_meta_out);

    // printf("[decoder:TestEnclave]: There are a total of %d tracks in this mp4 container...\n", mp4.track_count);

    for (ntrack = 0; ntrack < mp4.track_count; ntrack++)
    {
        // printf("[decoder:TestEnclave]: Dealing with track %d now...\n", ntrack);
        MP4D_track_t *tr = mp4.track + ntrack;
        unsigned sum_duration = 0;
        i = 0;
        if (tr->handler_type == MP4D_HANDLER_TYPE_VIDE)
        {   // assume h264
#define USE_SHORT_SYNC 0
            char sync[4] = { 0, 0, 0, 1 };
            while (spspps = MP4D_read_sps(&mp4, ntrack, i, &spspps_bytes))
            {
				if (expand_allocation_space_if_necessary((void**) video_out, &current_size_of_video_out, current_used_size_of_video_out, 4 - USE_SHORT_SYNC + spspps_bytes, standard_block_size) != 0) {
					return 1;
				}
				memcpy(*video_out + current_used_size_of_video_out, sync + USE_SHORT_SYNC, 4 - USE_SHORT_SYNC);
				current_used_size_of_video_out += 4 - USE_SHORT_SYNC;
				memcpy(*video_out + current_used_size_of_video_out, spspps, spspps_bytes);
				current_used_size_of_video_out += spspps_bytes;
                // fwrite(sync + USE_SHORT_SYNC, 1, 4 - USE_SHORT_SYNC, fout);
                // fwrite(spspps, 1, spspps_bytes, fout);
                i++;
            }
            i = 0;
            while (spspps = MP4D_read_pps(&mp4, ntrack, i, &spspps_bytes))
            {
				if (expand_allocation_space_if_necessary((void**) video_out, &current_size_of_video_out, current_used_size_of_video_out, 4 - USE_SHORT_SYNC + spspps_bytes, standard_block_size) != 0) {
					return 1;
				}
				memcpy(*video_out + current_used_size_of_video_out, sync + USE_SHORT_SYNC, 4 - USE_SHORT_SYNC);
				current_used_size_of_video_out += 4 - USE_SHORT_SYNC;
				memcpy(*video_out + current_used_size_of_video_out, spspps, spspps_bytes);
				current_used_size_of_video_out += spspps_bytes;
                // fwrite(sync + USE_SHORT_SYNC, 1, 4 - USE_SHORT_SYNC, fout);
                // fwrite(spspps, 1, spspps_bytes, fout);
                i++;
            }
            // printf("[decoder:TestEnclave]: There are a total of %d samples in the video track...\n", mp4.track[ntrack].sample_count);
            for (i = 0; i < mp4.track[ntrack].sample_count; i++)
            {
                unsigned frame_bytes, timestamp, duration;
                MP4D_file_offset_t ofs = MP4D_frame_offset(&mp4, ntrack, i, &frame_bytes, &timestamp, &duration);
                uint8_t *mem = input_buf + ofs;
                sum_duration += duration;
                // printf("frame_bytes in video is: %d\n", frame_bytes);
                while (frame_bytes)
                {
                    uint32_t size = ((uint32_t)mem[0] << 24) | ((uint32_t)mem[1] << 16) | ((uint32_t)mem[2] << 8) | mem[3];
                    // printf("size in video is: %d\n", size);
                    size += 4;
                    mem[0] = 0; mem[1] = 0; mem[2] = 0; mem[3] = 1;
					if (expand_allocation_space_if_necessary((void**) video_out, &current_size_of_video_out, current_used_size_of_video_out, size - USE_SHORT_SYNC, standard_block_size) != 0) {
						return 1;
					}
					memcpy(*video_out + current_used_size_of_video_out, mem + USE_SHORT_SYNC, size - USE_SHORT_SYNC);
					current_used_size_of_video_out += size - USE_SHORT_SYNC;
                    // fwrite(mem + USE_SHORT_SYNC, 1, size - USE_SHORT_SYNC, fout);
                    if (frame_bytes < size)
                    {
                        printf("[decoder:TestEnclave]: error: demux sample failed\n");
                        return 1;
                    }
                    frame_bytes -= size;
                    mem += size;
                }
            }
        } else if (tr->handler_type == MP4D_HANDLER_TYPE_SOUN)
        { 
            // The following codes are for storing both audio dsi and audio raw data(AAC)...
            // printf("[decoder:TestEnclave]: Audio track detected...with sample_count: %d, channel_count: %d, sample_rate: %d, dsi_bytes: %d, and language: {%s}, timescale: %i\n", 
            //     mp4.track[ntrack].sample_count, (tr->SampleDescription).audio.channelcount, (tr->SampleDescription).audio.samplerate_hz, tr->dsi_bytes, tr->language, tr->timescale);
            // printf("[decoder:TestEnclave]: Audio has type: %x, compared with default_output_audio_type: %x\n", tr->object_type_indication, MP4_OBJECT_TYPE_AUDIO_ISO_IEC_14496_3);

            // Write audio-related metadata.
            // Samplerate in Hz.
			if (expand_allocation_space_if_necessary((void**) audio_meta_out, &current_size_of_audio_meta_out, current_used_size_of_audio_meta_out, sizeof(unsigned int) * 3 + tr->dsi_bytes, standard_block_size) != 0) {
				return 1;
			}
			memcpy(*audio_meta_out + current_used_size_of_audio_meta_out, &(tr->SampleDescription).audio.samplerate_hz, sizeof(unsigned int));
			current_used_size_of_audio_meta_out += sizeof(unsigned int);
            // fwrite(&(tr->SampleDescription).audio.samplerate_hz, 1, sizeof(unsigned int), f_audio_meta_out);
            // timescale
			memcpy(*audio_meta_out + current_used_size_of_audio_meta_out, &tr->timescale, sizeof(unsigned int));
			current_used_size_of_audio_meta_out += sizeof(unsigned int);
            // fwrite(&tr->timescale, 1, sizeof(unsigned int), f_audio_meta_out);
            // DSI
			memcpy(*audio_meta_out + current_used_size_of_audio_meta_out, &tr->dsi_bytes, sizeof(unsigned int));
			current_used_size_of_audio_meta_out += sizeof(unsigned int);
			memcpy(*audio_meta_out + current_used_size_of_audio_meta_out, tr->dsi, tr->dsi_bytes);
			current_used_size_of_audio_meta_out += tr->dsi_bytes;
            // fwrite(&tr->dsi_bytes, 1, sizeof(unsigned int), f_audio_meta_out);
            // fwrite(tr->dsi, 1, tr->dsi_bytes, f_audio_meta_out);

            // Write audio data
			if (expand_allocation_space_if_necessary((void**) audio_out, &current_size_of_audio_out, current_used_size_of_audio_out, sizeof(unsigned int), standard_block_size) != 0) {
				return 1;
			}
			memcpy(*audio_out + current_used_size_of_audio_out, &(mp4.track[ntrack].sample_count), sizeof(unsigned int));
			current_used_size_of_audio_out += sizeof(unsigned int);
            // fwrite(&(mp4.track[ntrack].sample_count), 1, sizeof(unsigned int), f_audio_out);
            for (i = 0; i < mp4.track[ntrack].sample_count; i++)
            {
                // printf("Dealing with audio sample_count: %d, where the total sample count is: %d\n", i, mp4.track[ntrack].sample_count);
                unsigned frame_bytes, timestamp, duration;
                MP4D_file_offset_t ofs = MP4D_frame_offset(&mp4, ntrack, i, &frame_bytes, &timestamp, &duration);
				if (expand_allocation_space_if_necessary((void**)audio_out, &current_size_of_audio_out, current_used_size_of_audio_out, sizeof(unsigned) + frame_bytes, standard_block_size) != 0) {
					return 1;
				}
				memcpy(*audio_out + current_used_size_of_audio_out, &frame_bytes, sizeof(unsigned));
				current_used_size_of_audio_out += sizeof(unsigned);
                // fwrite(&frame_bytes, 1, sizeof(unsigned), f_audio_out);
                if (ofs > input_size) {
                    // printf("[decoder:TestEnclave]: Abandoning audio from sample_count: %d, where the total sample_count is: %d\n", i, mp4.track[ntrack].sample_count);
                    break;
                }
				memcpy(*audio_out + current_used_size_of_audio_out, input_buf + ofs, frame_bytes);
				current_used_size_of_audio_out += frame_bytes;
                // fwrite(input_buf + ofs, 1, frame_bytes, f_audio_out);
                // printf("sample_count: %d, ofs=%d frame_bytes=%d timestamp=%d duration=%d\n", i, (unsigned)ofs, frame_bytes, timestamp, duration);
            }
            // printf("Audio track is done...\n");
        }
    }

    MP4D_close(&mp4);

	if (adjust_allocation_space_as_needed((void**) video_out, &current_size_of_video_out, current_used_size_of_video_out) != 0) {
		return 1;
	}
	if (adjust_allocation_space_as_needed((void**) audio_meta_out, &current_size_of_audio_meta_out, current_used_size_of_audio_meta_out) != 0) {
		return 1;
	}
	if (adjust_allocation_space_as_needed((void**) audio_out, &current_size_of_audio_out, current_used_size_of_audio_out) != 0) {
		return 1;
	}

	*size_of_video_out = current_used_size_of_video_out;
	*size_of_audio_meta_out = current_used_size_of_audio_meta_out;
	*size_of_audio_out = current_used_size_of_audio_out;

    // if (input_buf)
    //     free(input_buf);
    return 0;
}

static void yuv_save(unsigned char *buf[], int wrap[], int xsize,int ysize, unsigned char *target_buffer)
{
	int i;
	unsigned char* temp_target = target_buffer;	
	for (i = 0; i < ysize; i++) {
		// fwrite(buf[0] + i * wrap[0], 1, xsize, f);
		memcpy(temp_target, buf[0] + i * wrap[0], xsize);
		// if (!is_test_2_printed) {
		// 	printf("real first five chars: {%d} {%d} {%d} {%d} {%d}\n", *(buf[0] + i * wrap[0]), *(buf[0] + i * wrap[0] + 1), *(buf[0] + i * wrap[0] + 2), *(buf[0] + i * wrap[0] + 3), *(buf[0] + i * wrap[0] + 4));
		// 	printf("copied first five chars: {%d} {%d} {%d} {%d} {%d}\n", target_buffer[0], target_buffer[1], target_buffer[2], target_buffer[3], target_buffer[4]);
		// 	is_test_2_printed = 1;
		// }
		temp_target += xsize;
	}
	for (i = 0; i < ysize / 2; i++) {
		// fwrite(buf[1] + i * wrap[1], 1, xsize/2, f);
		memcpy(temp_target, buf[1] + i * wrap[1], xsize/2);
		temp_target += xsize/2;
	}
	for (i = 0; i < ysize / 2; i++) {
		// fwrite(buf[2] + i * wrap[2], 1, xsize/2, f);
		memcpy(temp_target, buf[2] + i * wrap[2], xsize/2);
		temp_target += xsize/2;
	}
}

// int is_test_printed = 0;

static int decode_write_frame(unsigned char *target_buffer, AVCodecContext *avctx,
							  AVFrame *frame, int *frame_index, AVPacket *pkt, int flush, int *is_frame_decoded)
{
	int got_frame = 0;
	do {
		int len = avcodec_decode_video2(avctx, frame, &got_frame, pkt);
		if (len < 0) {
			// fprintf(stderr, "Error while decoding frame %d\n", *frame_index);
			printf("[decoder:TestEnclave]: Error while decoding frame %d\n", *frame_index);
			return len;
		}
		if (got_frame) {
			// printf("Got frame %d\n", *frame_index);
			if (target_buffer) {
				size_t size_of_temp_yuv_data = sizeof(unsigned char) * frame->width * frame->height * 3 / 2;
				unsigned char *temp_yuv_data = (unsigned char*)malloc(size_of_temp_yuv_data);
				memset(temp_yuv_data, 0, size_of_temp_yuv_data);
				yuv_save(frame->data, frame->linesize, frame->width, frame->height, temp_yuv_data);
				// if (!is_test_printed) {
				// 	printf("first five chars: {%d} {%d} {%d} {%d} {%d}\n", temp_yuv_data[0], temp_yuv_data[1], temp_yuv_data[2], temp_yuv_data[3], temp_yuv_data[4]);
				// 	int total_size = sizeof(unsigned char) * frame->width * frame->height * 3 / 2;
				// 	printf("last five chars: {%d} {%d} {%d} {%d} {%d}\n", temp_yuv_data[total_size - 1], temp_yuv_data[total_size - 2], temp_yuv_data[total_size - 3], temp_yuv_data[total_size - 4], temp_yuv_data[total_size - 5]);
				// 	is_test_printed = 1;
				// }
				yuv420_prog_planar_to_rgb_packed(temp_yuv_data, target_buffer, frame->width, frame->height);
				free(temp_yuv_data);
			}
			(*frame_index)++;
		}
	} while (flush && got_frame);
	*is_frame_decoded = got_frame;
	return 0;
}

int get_filter_idx(metadata* md, char* filter_name)
{
	for (int i = 0; i < md->total_filters; i++) {
		if (strcmp(md->filters[i], filter_name) == 0)
			return i;
	}
	return -1;
}

int t_encoder_init (cmdline *cl_in, size_t cl_size, 
                    unsigned char* frame_sig, size_t frame_sig_size,
                    uint8_t* frame, size_t frame_size,
                    char* md_json,  size_t md_json_size)
{
    int res = -1;
    // Verify first frame and metadata to obtain 
    // frame-related information from metadata
	if (!ias_pubkey) {
        printf("Run t_verify_cert first\n");
        return res;
    }
    // printf("frame_size: %d, md_json_size: %d\n", frame_size, md_json_size);
    unsigned char* buf = (unsigned char*)malloc(frame_size + md_json_size);
    if (!buf) {
        printf("No memory left\n");
        return res;
    }
    memset(buf, 0, frame_size + md_json_size);
    memcpy(buf, frame, frame_size);
    memcpy(buf + frame_size, md_json, md_json_size);
    // printf("[EncoderEnclave]: frame_size: %d; md_json(%d): [%s]; client_id: [%d]\n", frame_size, md_json_size, md_json, client_id);
    // printf("[EncoderEnclave]: frame_sig(%d): [%s]\n", frame_sig_size, frame_sig);
    res = verify_sig_4_encoder((void*)buf, frame_size + md_json_size, frame_sig, frame_sig_size, ias_pubkey);
    free(buf);
    if (res != 1) {
        printf("[EncoderEnclave]: Signature cannot be verified\n");
        return -1;
    }
    md_json[md_json_size - 18] = '}'; // Remove frame_id from metadata
    memset(md_json + (md_json_size - 17), '\0', 17);
    // printf("[EncoderEnclave]: Let's see if we actually remove frame_id(%d)(%d): [%s]\n", strlen(md_json), md_json_size - 17, md_json);
    in_md = json_2_metadata(md_json, md_json_size - 17);

    // char* output_json_4_in = metadata_2_json_without_frame_id(in_md);
    
    // printf("[EncoderEnclave]: In t_encoder_init, we have output_json_4_in(%d): [%s]\n", strlen(output_json_4_in), output_json_4_in);
    // free(output_json_4_in);

    cl = (cmdline*)malloc(sizeof(cmdline));
    memset(cl, 0, sizeof(cmdline));
    memcpy(cl, cl_in, sizeof(cmdline));
    g_h = in_md->height;
    g_w = in_md->width;
    frame_counter = 0;

    create_param.enableNEON = 1;
#if H264E_SVC_API
    create_param.num_layers = 1;
    create_param.inter_layer_pred_flag = 1;
    create_param.inter_layer_pred_flag = 0;
#endif
    create_param.gop = cl->gop;
    create_param.height = g_h;
    create_param.width  = g_w;
    create_param.max_long_term_reference_frames = 0;
#if ENABLE_TEMPORAL_SCALABILITY
    create_param.max_long_term_reference_frames = MAX_LONG_TERM_FRAMES;
#endif
    create_param.fine_rate_control_flag = 0;
    create_param.const_input_flag = cl->psnr ? 0 : 1;
    create_param.vbv_size_bytes = 100000/8;
    create_param.temporal_denoise_flag = cl->denoise;

    // Allocate space for yuv420 (the one used for actually process data)
    buf_in   = (uint8_t*)malloc(frame_size);
    memset(buf_in, 0, frame_size);
    buf_save = (uint8_t*)malloc(frame_size);
    memset(buf_save, 0, frame_size);

    // If yuyv frames are used, allocate space for both the src and temp space for converting chroma format
    if(cl->is_yuyv){
        // Allocate space for temp space
        temp_frame_size = g_w * g_h * 2;
        temp_buf_in = (uint8_t*)malloc(temp_frame_size * sizeof(uint8_t));
        memset(temp_buf_in, 0, temp_frame_size);
        // printf("yuyv detected\n");
    }

    // If rgb frames are used, allocate space for both the src and temp space for converting chroma format
    if(cl->is_rgb){
        // Allocate space for temp space of dest (yuv 4:2:0 planar)
        // Update: Probably no longer needed
        // temp_frame_size = g_w * g_h * 3 / 2;
        // temp_buf_in = (uint8_t*)malloc(temp_frame_size * sizeof(uint8_t));
        // memset(temp_buf_in, 0, temp_frame_size);
        // printf("rgb detected, init with width: %d, height: %d\n", g_w, g_h);
        // Init rgbToYuv conversion
        InitConvt(g_w, g_h);
    }

    if (!buf_in || !buf_save)
    {
        printf("ERROR: not enough memory\n");
        return 1;
    }
    enc = NULL;
    scratch = NULL;
    total_coded_data = NULL;
    total_coded_data_size = 0;
    int sizeof_persist = 0, sizeof_scratch = 0, error;
    if (cl->psnr)
        psnr_init();

    error = H264E_sizeof(&create_param, &sizeof_persist, &sizeof_scratch);
    if (error)
    {
        printf("H264E_sizeof error = %d\n", error);
        return 1;
    }
    enc     = (H264E_persist_t *)malloc(sizeof_persist);
    memset(enc, 0, sizeof_persist);
    scratch = (H264E_scratch_t *)malloc(sizeof_scratch);
    memset(scratch, 0, sizeof_scratch);
    error = H264E_init(enc, &create_param);
    if (error)
    {
        printf("H264E_init error = %d\n", error);
        return 1;
    }

    return 0;
}

int t_encode_frame (unsigned char* frame_sig, size_t frame_sig_size,
                    uint8_t* frame, size_t frame_size,
                    char* md_json,  size_t md_json_size)
{
    int res = -1;
    // Verify signature of frame
    // The signature should have two information:
    // (1) The frame
    // (2) A metadata of the frame (frame ID, total # of frames, segment ID)
	if (!ias_pubkey) {
        printf("Run t_verify_cert first\n");
        return res;
    }
    // printf("frame_size: %d, md_json_size: %d\n", frame_size, md_json_size);
    unsigned char* buf = (unsigned char*)malloc(frame_size + md_json_size);
    if (!buf) {
        printf("No memory left\n");
        return res;
    }
    memset(buf, 0, frame_size + md_json_size);
    memcpy(buf, frame, frame_size);
    memcpy(buf + frame_size, md_json, md_json_size);
    // printf("[EncoderEnclave]: frame_size: %d; md_json(%d): [%s]; client_id: [%d]\n", frame_size, md_json_size, md_json, client_id);
    // printf("[EncoderEnclave]: frame_sig(%d): [%s]\n", frame_sig_size, frame_sig);
    res = verify_sig_4_encoder((void*)buf, frame_size + md_json_size, frame_sig, frame_sig_size, ias_pubkey);
    free(buf);
    if (res != 1) {
        printf("[EncoderEnclave]: Signature cannot be verified\n");
        return -1;
    }
    metadata* md;
    md = json_2_metadata(md_json, md_json_size);
    if (frame_counter != md->frame_id) {
        printf("Frame out of order\n");
        return -1;
    }
    int fps = md->frame_rate;
    free_metadata(md);
    frame_counter++;
    // Encode frame
    if (cl->is_yuyv) {
        p = frame;   // Record head adddress

        // temp conversion address
        yuyv.Y = temp_buf_in;
        yuyv.U = yuyv.Y + g_w * g_h;
        yuyv.V = yuyv.U + (g_w * g_h >> 1);   // Y  U  V  =4 : 2 ; 2

        // final incoming yuv data address
        yuv.yuv[0] = buf_in; yuv.stride[0] = g_w;
        yuv.yuv[1] = buf_in + g_w*g_h; yuv.stride[1] = g_w/2;
        yuv.yuv[2] = buf_in + g_w*g_h*5/4; yuv.stride[2] = g_w/2;

        // yuyv to yuv
        int k, j;
        for (k = 0; k < g_h; ++k)
        {
            for (j = 0; j < (g_w >> 1); ++j)
            {
                yuyv.Y[j * 2] = p[4 * j];
                yuyv.U[j] = p[4 * j + 1];
                yuyv.Y[j * 2 + 1] = p[4 * j + 2];
                yuyv.V[j] = p[4 * j + 3];
            }
            p = p + g_w * 2;

            yuyv.Y = yuyv.Y + g_w;
            yuyv.U = yuyv.U + (g_w >> 1);
            yuyv.V = yuyv.V + (g_w >> 1);
        }
        // Now packed is planar
        // reset
        yuyv.Y = temp_buf_in;
        yuyv.U = yuyv.Y + g_w * g_h;
        yuyv.V = yuyv.U + (g_w * g_h >> 1);

        int l;
        for (l = 0; l < g_h / 2; ++l)
        {
            memcpy(yuv.yuv[1], yuyv.U, g_w >> 1);
            memcpy(yuv.yuv[2], yuyv.V, g_w >> 1);

            yuv.yuv[1] = yuv.yuv[1] + (g_w >> 1);
            yuv.yuv[2] = yuv.yuv[2] + (g_w >> 1);

            yuyv.U = yuyv.U + (g_w);
            yuyv.V = yuyv.V + (g_w);
        }

        memcpy(yuv.yuv[0], yuyv.Y, g_w * g_h);

        // reset
        yuv.yuv[0] = buf_in;
        yuv.yuv[1] = buf_in + g_w*g_h;
        yuv.yuv[2] = buf_in + g_w*g_h*5/4;
    } else if (cl->is_rgb) {
        // printf("Processing rgb frame with frame size: %d...\n", frame_size);
        rgb_packed_to_yuv420_prog_planar(frame, buf_in, g_w, g_h);
        yuv.yuv[0] = buf_in; yuv.stride[0] = g_w;
        yuv.yuv[1] = buf_in + g_w*g_h; yuv.stride[1] = g_w/2;
        yuv.yuv[2] = buf_in + g_w*g_h*5/4; yuv.stride[2] = g_w/2;
    } else {
        buf_in = frame;
        yuv.yuv[0] = buf_in; yuv.stride[0] = g_w;
        yuv.yuv[1] = buf_in + g_w*g_h; yuv.stride[1] = g_w/2;
        yuv.yuv[2] = buf_in + g_w*g_h*5/4; yuv.stride[2] = g_w/2;
    }

    // For printing psnr
    if (cl->psnr)
        memcpy(buf_save, buf_in, frame_size);

    run_param.frame_type = 0;
    run_param.encode_speed = cl->speed;
    run_param.target_fps = fps;
    //run_param.desired_nalu_bytes = 100;

    if (cl->kbps)
    {
        printf("kbps is set manually to %i\n", cl->kbps);
        run_param.desired_frame_bytes = cl->kbps*1000/8/30;    // Modified for framerates
        run_param.qp_min = 10;
        run_param.qp_max = 50;
    } else
    {
        run_param.qp_min = run_param.qp_max = cl->qp;
    }

#if ENABLE_TEMPORAL_SCALABILITY
    int level, logmod = 1;
    int j, mod = 1 << logmod;
    static int fresh[200] = {-1,-1,-1,-1};

    run_param.frame_type = H264E_FRAME_TYPE_CUSTOM;

    for (level = logmod; level && (~i & (mod >> level)); level--){}

    run_param.long_term_idx_update = level + 1;
    if (level == logmod && logmod > 0)
        run_param.long_term_idx_update = -1;
    if (level == logmod - 1 && logmod > 1)
        run_param.long_term_idx_update = 0;

    //if (run_param.long_term_idx_update > logmod) run_param.long_term_idx_update -= logmod+1;
    //run_param.long_term_idx_update = logmod - 0 - level;
    //if (run_param.long_term_idx_update > 0)
    //{
    //    run_param.long_term_idx_update = logmod - run_param.long_term_idx_update;
    //}
    run_param.long_term_idx_use    = fresh[level];
    for (j = level; j <= logmod; j++)
    {
        fresh[j] = run_param.long_term_idx_update;
    }
    if (!i)
    {
        run_param.long_term_idx_use = -1;
    }
#endif
    res = H264E_encode(enc, scratch, &run_param, &yuv, &coded_data, &sizeof_coded_data);
    if (res)
    {
        printf("t_encode_frame: ERROR during encoding\n");
        return res;
    }

    if (cl->psnr)
        psnr_add(buf_save, buf_in, g_w, g_h, sizeof_coded_data);

    // Save encoded frame to global variable
    unsigned char* tmp;
    tmp = (unsigned char*)realloc(total_coded_data, (size_t)(total_coded_data_size + sizeof_coded_data));
    if (tmp)
    {
        memset(tmp + total_coded_data_size, 0, sizeof_coded_data);
        memcpy(tmp + total_coded_data_size, coded_data, sizeof_coded_data);
        total_coded_data_size += sizeof_coded_data;
        total_coded_data = tmp;
    }
    else
    {
        printf("t_encode_frame: ERROR no memory available\n");
        res = -1;
    }
   
    return res;
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

int verify_cert(X509* cert_to_verify, EVP_PKEY* pubkey_for_verify)
{
    int r = X509_verify(cert_to_verify, pubkey_for_verify);
    return r;
}

// int t_sgxver_prepare_decoder(
// 	void* input_content_buffer, long size_of_input_content_buffer, 
// 	void* md_json, long md_json_len,
// 	void* vendor_pub, long vendor_pub_len,
// 	void* camera_cert, long camera_cert_len,
// 	void* vid_sig, size_t vid_sig_len) {
// 	// Return 1 on success, return 0 on fail, return -1 on error, return -2 on already verified

// 	if(is_source_video_verified != -3){
// 		return -2;
// 	}

//     int res = -1;

// 	// Verify certificate
// 	BIO* bo_pub = BIO_new( BIO_s_mem() );
// 	BIO_write(bo_pub, (char*)vendor_pub, vendor_pub_len);

// 	EVP_PKEY* vendor_pubkey = EVP_PKEY_new();
// 	vendor_pubkey = PEM_read_bio_PUBKEY(bo_pub, &vendor_pubkey, 0, 0);
// 	BIO_free(bo_pub);

// 	BIO* bo = BIO_new( BIO_s_mem() );
// 	BIO_write(bo, (char*)camera_cert, camera_cert_len);
//     X509* cam_cert;
//     cam_cert = X509_new();
// 	cam_cert = PEM_read_bio_X509(bo, &cam_cert, 0, NULL);
// 	BIO_free(bo);

// 	res = verify_cert(cam_cert, vendor_pubkey);

// 	if(res != 1){
// 		printf("Verify certificate failed\n");
// 		return 0;
// 	}

// 	// Verify signature
// 	EVP_PKEY* pukey = EVP_PKEY_new();
// 	pukey = X509_get_pubkey(cam_cert);
// 	unsigned char* buf = (unsigned char*)malloc(size_of_input_content_buffer + md_json_len);
// 	if (!buf) {
// 		printf("No memory left\n");
// 		return 0;
// 	}
// 	memset(buf, 0, size_of_input_content_buffer + md_json_len);
// 	memcpy(buf, input_content_buffer, size_of_input_content_buffer);
// 	memcpy(buf + size_of_input_content_buffer, md_json, md_json_len);
// 	// printf("Size of input_content_buffer is: %ld, size of md_json is: %ld, size of vid_sig: %d\n", size_of_input_content_buffer, md_json_len, vid_sig_len);
// 	res = verify_hash(buf, size_of_input_content_buffer + md_json_len, (unsigned char*)vid_sig, vid_sig_len, pukey);
// 	free(buf);
// 	if(res != 1){
// 		printf("Verify signature failed\n");
// 		return 0;
// 	}

// 	// Cleanup
// 	X509_free(cam_cert);
// 	EVP_PKEY_free(vendor_pubkey);
// 	EVP_PKEY_free(pukey);

// 	is_source_video_verified = res;

// 	if(is_source_video_verified){
// 		// Prepare Decoder
// 		status = h264bsdInit(&dec, HANTRO_FALSE);

// 		if (status != HANTRO_OK) {
// 			// fprintf(stderr, "h264bsdInit failed\n");
// 			printf("h264bsdInit failed\n");
// 			return 0;
// 		}

// 		len = size_of_input_content_buffer;
// 		byteStrm = (u8*)malloc(len);
// 		memset(byteStrm, 0, len);
// 		memcpy(byteStrm, input_content_buffer, len);

// 		s_md_json_len = md_json_len;
// 		s_md_json = (char*)malloc(s_md_json_len);
// 		memset(s_md_json, 0, s_md_json_len);
// 		memcpy(s_md_json, md_json, s_md_json_len);
// 	} else {
// 		printf("Source video is not verified...\n");
// 		return 0;
// 	}

// 	return res;
// }

int t_sgxver_prepare_decoder(
	void* input_content_buffer, long size_of_input_content_buffer, 
	void* md_json, long md_json_len,
	void* vendor_pub, long vendor_pub_len,
	void* camera_cert, long camera_cert_len,
	void* vid_sig, size_t vid_sig_len,
	int is_safetynet_presented) {
	// Return 1 on success, return 0 on fail, return -1 on error, return -2 on already verified

	// printf("[decoder:TestEnclave]: now inside t_sgxver_prepare_decoder...\n");

	if(is_source_video_verified != -3){
		return -2;
	}

    int res = -1;

	EVP_PKEY* pukey = EVP_PKEY_new();

	// Extra parsing metadata for Safetynet
	// This might be potentially a vulnerbility as attacker can use this check to bypass our check for certificate
	// One solution is to seperate SafetyNet based server from the original Vronicle server
    metadata* original_md = json_2_metadata((char*)md_json, md_json_len);
    if (original_md->is_safetynet_presented) {
        printf("[decoder:TestEnclave]: SafetyNet detected, using cert as pubkey...\n");

		unsigned char* pubkey_str;
		size_t size_of_pubkey_str;
		Base64Decode((char*)camera_cert, &pubkey_str, &size_of_pubkey_str);

		// printf("[decoder:TestEnclave]: pubkey_str_b64(%d): {%s}\n", camera_cert_len, camera_cert);
   		// printf("[decoder:TestEnclave]: size_of_pubkey_str: %d\n", size_of_pubkey_str);
		pukey = d2i_PublicKey(EVP_PKEY_RSA, &pukey, (const unsigned char**)(&pubkey_str), size_of_pubkey_str);
		// free(pubkey_str);

    } else {
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
			printf("[decoder:TestEnclave]: Verify certificate failed\n");
			return 0;
		}
		pukey = X509_get_pubkey(cam_cert);

		X509_free(cam_cert);
		EVP_PKEY_free(vendor_pubkey);
	}

	// Verify signature
	unsigned char* buf = (unsigned char*)malloc(size_of_input_content_buffer + md_json_len);
	if (!buf) {
		printf("[decoder:TestEnclave]: No memory left\n");
		return 0;
	}
	memset(buf, 0, size_of_input_content_buffer + md_json_len);
	memcpy(buf, input_content_buffer, size_of_input_content_buffer);
	memcpy(buf + size_of_input_content_buffer, md_json, md_json_len);
	// printf("Size of input_content_buffer is: %ld, size of md_json is: %ld, size of vid_sig: %d\n", size_of_input_content_buffer, md_json_len, vid_sig_len);
	res = verify_hash(buf, size_of_input_content_buffer + md_json_len, (unsigned char*)vid_sig, vid_sig_len, pukey);
	free(buf);
	if(res != 1){
		printf("[decoder:TestEnclave]: Verify signature failed\n");
		return 0;
	}

	// Cleanup
	EVP_PKEY_free(pukey);

	is_source_video_verified = res;

	// printf("[decoder:TestEnclave]: is_source_video_verified: %d\n", is_source_video_verified);

	if(is_source_video_verified){
		// Prepare Decoder
		// status = h264bsdInit(&dec, HANTRO_FALSE);

		// if (status != HANTRO_OK) {
		// 	// fprintf(stderr, "h264bsdInit failed\n");
		// 	printf("h264bsdInit failed\n");
		// 	return 0;
		// }
		avcodec_register(&ff_h264_decoder);
		av_register_codec_parser(&ff_h264_parser);
		
		codec = avcodec_find_decoder(AV_CODEC_ID_H264);
		if (!codec) {
			// fprintf(stderr, "Codec not found\n");
			printf("[decoder:TestEnclave]: Codec not found\n");
			return 0;
		}

		codec_ctx = avcodec_alloc_context3(codec);
		if (!codec_ctx) {
			// fprintf(stderr, "Could not allocate video codec context\n");
			printf("[decoder:TestEnclave]: Could not allocate video codec context\n");
			return 0;
		}
		
		if (avcodec_open2(codec_ctx, codec, NULL) < 0) {
			// fprintf(stderr, "Could not open codec\n");
			printf("[decoder:TestEnclave]: Could not open codec\n");
			return 0;
		}
		
		parser = av_parser_init(AV_CODEC_ID_H264);
		if(!parser) {
			// fprintf(stderr, "Could not create H264 parser\n");
			printf("[decoder:TestEnclave]: Could not create H264 parser\n");
			return 0;
		}

		frame = av_frame_alloc();
		if (!frame) {
			// fprintf(stderr, "Could not allocate video frame\n");
			printf("[decoder:TestEnclave]: Could not allocate video frame\n");
			return 0;
		}

		int demux_result = demux((uint8_t*)input_content_buffer, size_of_input_content_buffer, &byteStrm, &len, &audio_strm, &size_of_audio_strm, &audio_meta_strm, &size_of_audio_meta_strm, 0);

		// printf("[decoder:TestEnclave]: demux result is: %d...\n", demux_result);

		if (demux_result != 0) {
			printf("[decoder:TestEnclave]: demux is failed...\n");
			return 0;
		}

		// Create buffer for signing audio
		long size_of_audio_related_data_buf = (size_of_audio_strm + size_of_audio_meta_strm) * sizeof(unsigned char);
		unsigned char* temp_audio_related_data_buf = (unsigned char*) malloc(size_of_audio_related_data_buf);
		memset(temp_audio_related_data_buf, 0, size_of_audio_related_data_buf);
		memcpy(temp_audio_related_data_buf, audio_meta_strm, size_of_audio_meta_strm);
		memcpy(temp_audio_related_data_buf + size_of_audio_meta_strm, audio_strm, size_of_audio_strm);

		// printf("[decode:TestEnclave]: Now we have a audio related data buffer of size: %d\n", size_of_audio_related_data_buf);

		// // private key - string
		// int len = i2d_PrivateKey(enc_priv_key, NULL);
		// unsigned char* buf = (unsigned char *)malloc(len + 1);
		// unsigned char* tbuf = buf;
		// i2d_PrivateKey(enc_priv_key, &tbuf);
		// // print private key
		// printf("{\"[decode:TestEnclave]: private\":\"");
		// for (int i = 0; i < len; i++) {
		// 	printf("%02x", (unsigned char)buf[i]);
		// }
		// printf("\"}\n");
		// free(buf);

		// sign the audio related data
		size_t preset_audio_sig_size = EVP_PKEY_size(enc_priv_key);	// TO-DO: Remove hard coded size
		size_of_audio_sig = preset_audio_sig_size;
		// printf("[decode:TestEnclave]: preset_audio_sig_size: %d\n", preset_audio_sig_size);
		audio_sig = (unsigned char*) malloc(preset_audio_sig_size);
		unsigned char* audio_sig_temp = (unsigned char*)audio_sig;
		memset(audio_sig_temp, 0, preset_audio_sig_size);

		int res_4_sign = sign(enc_priv_key, temp_audio_related_data_buf, size_of_audio_related_data_buf, audio_sig_temp, &size_of_audio_sig);
		// int res_4_sign = sign(enc_priv_key, temp_audio_related_data_buf, size_of_audio_related_data_buf, NULL, &size_of_audio_sig);
		if(res_4_sign != 0){
			printf("[decode:TestEnclave]: Signing audio failed\n");
			return 0;
		} else if (size_of_audio_sig > preset_audio_sig_size) {
			printf("[decode:TestEnclave]: size_of_audio_sig: %d is bigger than preset_audio_sig_size: %d...\n", size_of_audio_sig, preset_audio_sig_size);
			return 0;
		}

		// printf("[decode:TestEnclave]: After signing of audio related data, size_of_audio_sig: %d\n", size_of_audio_sig);

		free(temp_audio_related_data_buf);

		// if (byteStrm) {
		// 	printf("[decoder:TestEnclave]: byteStrm does exist...\n");
		// }

		// len = size_of_input_content_buffer;
		// byteStrm = (u8*)malloc(len);
		// memset(byteStrm, 0, len);
		// memcpy(byteStrm, input_content_buffer, len);

		// For the following decoding frame process
		tempByteStrm = byteStrm;

		// printf("[decoder:TestEnclave]: Going to try to access address of byteStrm...\n");
		// printf("[decoder:TestEnclave]: After demuxing, the first five characters: 1: {%d}, 2: {%d}, 3: {%d}, 4: {%d}, 5: {%d}\n", byteStrm[0], byteStrm[1], byteStrm[2], byteStrm[3], byteStrm[4]);
		// printf("[decoder:TestEnclave]: After demuxing, the last five characters: 5: {%d}, 4: {%d}, 3: {%d}, 2: {%d}, 1: {%d}\n", byteStrm[len - 1], byteStrm[len - 2], byteStrm[len - 3], byteStrm[len - 4], byteStrm[len - 5]);

		if (original_md->is_safetynet_presented) {
			metadata *temp_md = json_2_metadata((char*)md_json, md_json_len);
			for (int i = 0; i < temp_md->num_of_safetynet_jws; ++i) {
				free(temp_md->safetynet_jws[i]);
			}
			free(temp_md->safetynet_jws);
			temp_md->num_of_safetynet_jws = 0;
			temp_md->is_safetynet_presented = 0;
			md_json = metadata_2_json_without_frame_id(temp_md);
			md_json_len = strlen((char*)md_json);
			free_metadata(temp_md);
		}

		s_md_json_len = md_json_len;
		s_md_json = (char*)malloc(s_md_json_len);
		memset(s_md_json, 0, s_md_json_len);
		memcpy(s_md_json, md_json, s_md_json_len);

		if (original_md->is_safetynet_presented) {
			free(md_json);
		}
	} else {
		printf("[decoder:TestEnclave]: Source video is not verified...\n");
		return 0;
	}

	if (original_md) {
		free_metadata(original_md);
	}

	return res;
}

int t_sgxver_get_audio_related_data_sizes(void* size_of_audio_meta_out, void* size_of_audio_data_out, void* size_of_audio_sig_out, size_t size_of_arguments) {
	// Return 0 on success, otherwise fail

	if (!size_of_audio_strm || !size_of_audio_meta_strm || !size_of_audio_sig) {
		printf("[decoder:TestEnclave]: either size_of_audio_strm or size_of_audio_meta_strm or size_of_audio_sig is not set yet..\n");
		return 1;
	}

	*(size_t*)size_of_audio_meta_out = size_of_audio_meta_strm;
	*(size_t*)size_of_audio_data_out = size_of_audio_strm;
	*(size_t*)size_of_audio_sig_out = size_of_audio_sig;

	return 0;
}

int t_sgxver_get_audio_related_data(void* audio_meta_out, size_t size_of_audio_meta_out, void* audio_strm_out, size_t size_of_audio_strm_out, void* audio_sig_out, size_t size_of_audio_sig_out) {
	// Return 0 on success, otherwise fail
	if (!audio_meta_strm || !audio_strm || !audio_sig) {
		printf("[decoder:TestEnclave]: either audio_meta_strm or audio_strm or audio_sig is not set yet..\n");
		return 1;
	}

	if ((size_of_audio_meta_strm != size_of_audio_meta_out) || (size_of_audio_strm != size_of_audio_strm_out) || (size_of_audio_sig != size_of_audio_sig_out)) {
		printf("[decoder:TestEnclave]: incorrect size(s): size_of_audio_meta_strm: %d, size_of_audio_meta_out: %d, size_of_audio_strm: %d, size_of_audio_strm_out: %d, size_of_audio_sig: %d, size_of_audio_sig_out: %d...\n", 
			size_of_audio_meta_strm, size_of_audio_meta_out, size_of_audio_strm, size_of_audio_strm_out, size_of_audio_sig, size_of_audio_sig_out);
		return 1;
	}

	memcpy(audio_meta_out, audio_meta_strm, size_of_audio_meta_strm);
	memcpy(audio_strm_out, audio_strm, size_of_audio_strm);
	memcpy(audio_sig_out, audio_sig, size_of_audio_sig);

	// free audio_meta_out and audio_strm_out and audio_sig as we only want output them once
	free(audio_meta_strm);
	free(audio_strm);
	free(audio_sig);

	return 0;
}

// int t_sgxver_decode_single_frame(
// 	void* decoded_frame, long size_of_decoded_frame, 
// 	void* output_md_json, long size_of_output_json,
// 	void* output_sig, long size_of_output_sig) {
	
// 	// Return 0 on success; return -1 on finish all decoding; otherwise fail...

// 	if(is_decoding_finished){
// 		printf("[decoder:TestEnclave]: decoding is already finished...\n");
// 		return 1;
// 	}

// 	if(is_source_video_verified != 1){
// 		printf("[decoder:TestEnclave]: please init the decoder first...\n");
// 		return 1;
// 	}

// 	u8* decoded_frame_temp = (u8*)decoded_frame;
// 	memset(decoded_frame_temp, 0, size_of_decoded_frame);
// 	char* output_md_json_temp = (char*)output_md_json;
// 	memset(output_md_json_temp, 0, size_of_output_json);
// 	unsigned char* output_sig_temp = (unsigned char*)output_sig;
// 	memset(output_sig_temp, 0, size_of_output_sig);

// 	int is_single_frame_successfully_decoded = 0;

// 	// For some temp variables
// 	size_t real_size_of_output_md_json = 0;
// 	int res = -1;
// 	char* output_json_n = NULL;
// 	u8* pic_rgb = NULL;

// 	while (len > 0 && !is_single_frame_successfully_decoded) {
// 		u32 result = h264bsdDecode(&dec, byteStrm, len, 0, &readBytes);
// 		// printf("[decoder:TestEnclave]: readBytes: [%d], frame_size: [%d]\n", readBytes, frame_size_in_rgb);
// 		len -= readBytes;
// 		byteStrm += readBytes;

// 		switch (result) {
// 			case H264BSD_PIC_RDY:
// 				// Extract frame
// 				pic = h264bsdNextOutputPicture(&dec, &picId, &isIdrPic, &numErrMbs);
// 				++numPics;
// 				if(!frame_size_in_rgb){
// 					printf("No valid video header detected, exiting...\n");
// 					exit(1);
// 				}

// 				// Convert frame to RGB packed format
// 				yuv420_prog_planar_to_rgb_packed(pic, decoded_frame_temp, width, height);

// 				// Generate metadata
// 				tmp = json_2_metadata((char*)s_md_json, s_md_json_len);
// 				if (!tmp) {
// 					printf("Failed to parse metadata\n");
// 					exit(1);
// 				}
// 				tmp->frame_id = numPics - 1;
// 				tmp_total_digests = tmp->total_digests;
// 				tmp->total_digests = tmp_total_digests + 1;
// 				tmp->digests = (char**)malloc(sizeof(char*) * 1);
// 				tmp->digests[0] = (char*)malloc(mrenclave_len);
// 				memset(tmp->digests[0], 0, mrenclave_len);
// 				memcpy(tmp->digests[0], mrenclave, mrenclave_len);
// 				output_json_n = metadata_2_json(tmp);
// 				// printf("[all_in_one:TestEnclave]: We now have output_json_n[%d]: {%s}\n", strlen(output_json_n), output_json_n);

// 				// Check size of md_json
// 				real_size_of_output_md_json = strlen(output_json_n);
// 				if(real_size_of_output_md_json != (size_t)size_of_output_json){
// 					printf("[all_in_one:TestEnclave]: Incorrect md_json size...real_size_of_output_md_json: [%d]; size_of_output_json: [%ld]\n", real_size_of_output_md_json, size_of_output_json);
// 					return 1;
// 				}
// 				memcpy(output_md_json_temp, output_json_n, real_size_of_output_md_json);
// 				// printf("[all_in_one:TestEnclave]: We now have output_json_n[%d]: {%s}\n", real_size_of_output_md_json, output_md_json_temp);

// 				// Create buffer for signing
// 				data_buf = (unsigned char*)malloc(frame_size_in_rgb + real_size_of_output_md_json);
// 				memset(data_buf, 0, frame_size_in_rgb + real_size_of_output_md_json);
// 				memcpy(data_buf, decoded_frame_temp, frame_size_in_rgb);
// 				memcpy(data_buf + frame_size_in_rgb, output_md_json_temp, real_size_of_output_md_json);

// 				// Generate signature
// 				// printf("[all_in_one:TestEnclave]: orig size: %li, sig size: %li, json: %s\n", frame_size_in_rgb + real_size_of_output_md_json, pic_sig_len, output_md_json_temp);
// 				// printf("[all_in_one:TestEnclave]: orig size: %li, sig size: %li, json: %s\n", frame_size_in_rgb + real_size_of_output_md_json, pic_sig_len, output_md_json_temp);
// 				res = sign(enc_priv_key, data_buf, frame_size_in_rgb + real_size_of_output_md_json, output_sig_temp, &pic_sig_len);
// 				if(res != 0){
// 					printf("Signing frame failed\n");
// 					return 1;
// 				}

// 				// Clean up
// 				free_metadata(tmp);
// 				free(output_json_n);
// 				free(data_buf);

// 				is_single_frame_successfully_decoded = 1;

// 				break;
// 			case H264BSD_HDRS_RDY:
// 				// printf("[all_in_one:TestEnclave]: in H264BSD_HDRS_RDY ...\n");
// 				// Obtain frame parameters
// 				h264bsdCroppingParams(&dec, &croppingFlag, &left, &width, &top, &height);
// 				if (!croppingFlag) {
// 				width = h264bsdPicWidth(&dec) * 16;
// 				height = h264bsdPicHeight(&dec) * 16;
// 				}
// 				// Allocate memory for frame
// 				if(!frame_size_in_rgb){
// 					frame_size_in_rgb = width * height * 3;
// 					if(size_of_decoded_frame != frame_size_in_rgb){
// 						printf("[all_in_one:TestEnclave]: Incorrect size...size_of_decoded_frame: [%d]; frame_size_in_rgb: [%d]...\n", size_of_decoded_frame, frame_size_in_rgb);
// 						return 1;
// 					}
// 					InitConvt(width, height);
// 					pic_rgb = (u8*)malloc(frame_size_in_rgb);
// 					res = sign(enc_priv_key, pic_rgb, frame_size_in_rgb, NULL, &pic_sig_len);
// 					free(pic_rgb);
// 					if(res != 0){
// 						printf("Failed to obtain signature length\n");
// 						return res;
// 					}
// 				}
// 				break;
// 			case H264BSD_RDY:
// 				break;
// 			case H264BSD_ERROR:
// 				printf("Error\n");
// 				return 1;
// 			case H264BSD_PARAM_SET_ERROR:
// 				printf("Param set error\n");
// 				return 1;
// 		}
// 	}

// 	if(len <= 0){
// 		h264bsdShutdown(&dec);
// 		is_decoding_finished = 1;
// 		return -1;
// 	}

// 	// printf("[all_in_one:TestEnclave]: Going to return from t_sgxver_decode_single_frame...\n");
	
// 	return 0;
// }

int t_sgxver_decode_single_frame(
	void* decoded_frame, long size_of_decoded_frame, 
	void* output_md_json, long size_of_output_json,
	void* output_sig, long size_of_output_sig) {
	
	// Return 0 on success; return -1 on finish all decoding; otherwise fail...

	if(is_decoding_finished){
		printf("[decoder:TestEnclave]: decoding is already finished...\n");
		return 1;
	}

	if(is_source_video_verified != 1){
		printf("[decoder:TestEnclave]: please init the decoder first...\n");
		return 1;
	}

	u8* decoded_frame_temp = (u8*)decoded_frame;
	memset(decoded_frame_temp, 0, size_of_decoded_frame);
	char* output_md_json_temp = (char*)output_md_json;
	memset(output_md_json_temp, 0, size_of_output_json);
	unsigned char* output_sig_temp = (unsigned char*)output_sig;
	memset(output_sig_temp, 0, size_of_output_sig);

	int is_single_frame_successfully_decoded = 0;

	// For some temp variables
	size_t real_size_of_output_md_json = 0;
	int res = -1;
	char* output_json_n = NULL;
	u8* pic_rgb = NULL;

	// printf("[decoder:TestEnclave]: Currently in t_sgxver_decode_single_frame, with remaining len: %d\n", len);

	while (len > 0 && !is_single_frame_successfully_decoded) {
		// u32 result = h264bsdDecode(&dec, byteStrm, len, 0, &readBytes);
		uint8_t* data = NULL;
  		int size = 0;
		// printf("[decoder:TestEnclave]: Going to call av_parser_parse2\n");
		readBytes = av_parser_parse2(parser, codec_ctx, &data, &size, tempByteStrm, len, 0, 0, AV_NOPTS_VALUE);
		// printf("[decoder:TestEnclave]: readBytes: [%d], frame_size: [%d]\n", readBytes, frame_size_in_rgb);

		if (readBytes > 0) {
			// Set up some parameters for the first time
			if(!frame_size_in_rgb){
				width = parser->width;
				height = parser->height;
				frame_size_in_rgb = width * height * 3;
				if(size_of_decoded_frame != frame_size_in_rgb){
					printf("[decoder:TestEnclave]: Incorrect size...size_of_decoded_frame: [%d]; frame_size_in_rgb: [%d]...\n", size_of_decoded_frame, frame_size_in_rgb);
					return 1;
				}
				InitConvt(width, height);
				pic_rgb = (u8*)malloc(frame_size_in_rgb);
				res = sign(enc_priv_key, pic_rgb, frame_size_in_rgb, NULL, &pic_sig_len);
				free(pic_rgb);
				if(res != 0){
					printf("[decoder:TestEnclave]: Failed to obtain signature length\n");
					return res;
				}
			}

			av_init_packet(&packet);
			packet.data = data;
			packet.size = size;
			int got_frame = 0;
			int ret = decode_write_frame(decoded_frame_temp, codec_ctx, frame, &frame_index, &packet, 0, &got_frame);
			if (ret < 0) {
				printf("Decode or write frame error\n");
				exit(1);
			}

			if (got_frame) {
				// Generate metadata
				// printf("[decode:TestEnclave]: The s_md_json(%d): {%s}\n", s_md_json_len, s_md_json);
				tmp = json_2_metadata((char*)s_md_json, s_md_json_len);
				// printf("[decode:TestEnclave]: First check of is_safetynet_presented: %d\n", tmp->is_safetynet_presented);
				if (!tmp) {
					printf("Failed to parse metadata\n");
					exit(1);
				}
				tmp->frame_id = frame_index - 1;
				// printf("[decode:TestEnclave]: Got frame %d\n", tmp->frame_id);
				tmp_total_digests = tmp->total_digests;
				tmp->total_digests = tmp_total_digests + 1;
				tmp->digests = (char**)malloc(sizeof(char*) * 1);
				tmp->digests[0] = (char*)malloc(mrenclave_len);
				memset(tmp->digests[0], 0, mrenclave_len);
				memcpy(tmp->digests[0], mrenclave, mrenclave_len);
				// printf("[decode:TestEnclave]: Second check of is_safetynet_presented: %d\n", tmp->is_safetynet_presented);
				output_json_n = metadata_2_json(tmp);
				// printf("[decode:TestEnclave]: We now have output_json_n[%d]: {%s}\n", strlen(output_json_n), output_json_n);

				// Check size of decoded_rgb_frame
				if (frame_size_in_rgb != (size_t)size_of_decoded_frame) {
					printf("[decode:TestEnclave]: Incorrect decoded_frame size...frame_size_in_rgb: [%d]; size_of_decoded_frame: [%ld]\n", frame_size_in_rgb, size_of_decoded_frame);
					return 1;
				}

				// Check size of md_json
				real_size_of_output_md_json = strlen(output_json_n);
				if(real_size_of_output_md_json != (size_t)size_of_output_json){
					printf("[decode:TestEnclave]: Incorrect md_json size...real_size_of_output_md_json: [%d]; size_of_output_json: [%ld]\n", real_size_of_output_md_json, size_of_output_json);
					return 1;
				}
				memcpy(output_md_json_temp, output_json_n, real_size_of_output_md_json);
				// printf("[decode:TestEnclave]: We now have output_json_n[%d]: {%s}\n", real_size_of_output_md_json, output_md_json_temp);

				// Create buffer for signing
				data_buf = (unsigned char*)malloc(frame_size_in_rgb + real_size_of_output_md_json);
				memset(data_buf, 0, frame_size_in_rgb + real_size_of_output_md_json);
				memcpy(data_buf, decoded_frame_temp, frame_size_in_rgb);
				memcpy(data_buf + frame_size_in_rgb, output_md_json_temp, real_size_of_output_md_json);

				// Generate signature
				// printf("[decode:TestEnclave]: orig size: %li, sig size: %li, json: %s\n", frame_size_in_rgb + real_size_of_output_md_json, pic_sig_len, output_md_json_temp);
				// printf("[decode:TestEnclave]: orig size: %li, sig size: %li, json: %s\n", frame_size_in_rgb + real_size_of_output_md_json, pic_sig_len, output_md_json_temp);
				res = sign(enc_priv_key, data_buf, frame_size_in_rgb + real_size_of_output_md_json, output_sig_temp, &pic_sig_len);
				if(res != 0){
					printf("[decode:TestEnclave]: Signing frame failed\n");
					return 1;
				}

				
				// printf("[decode:TestEnclave]: Cleaning for frame %d\n", tmp->frame_id);

				// Clean up
				free_metadata(tmp);
				free(output_json_n);
				free(data_buf);

				// printf("[decode:TestEnclave]: Finished cleaning for frame %d\n", tmp->frame_id);

				is_single_frame_successfully_decoded = 1;
			}

			len -= readBytes;
			tempByteStrm += readBytes;
		}

	}

	if(len <= 0){
		// printf("[decode:TestEnclave]: Decoding should be finished...going to clean...\n");
		// h264bsdShutdown(&dec);
		// Flush the decoder
		packet.data = NULL;
		packet.size = 0;
		// TO-DO: Check if possible that there is still one last frame when program gets here...
		avcodec_close(codec_ctx);
		av_free(codec_ctx);
		av_parser_close(parser);
		av_frame_free(&frame);
		is_decoding_finished = 1;

		// printf("[decode:TestEnclave]: Decoding should be finished...going to actually clean byteStrm...\n");
		if (byteStrm) {
			free(byteStrm);
		}
		// The cleaning of audio_strm and audio_meta_strm is performed when they are being copied out in a seperate function
		// printf("[decode:TestEnclave]: Decoding should be finished...going to actually clean audio_strm...\n");
		// if (audio_strm) {
		// 	free(audio_strm);
		// }
		// printf("[decode:TestEnclave]: Decoding should be finished...going to actually clean audio_meta_strm...\n");
		// if (audio_meta_strm) {
		// 	free(audio_meta_strm);
		// }
		
		printf("[decode:TestEnclave]: Decoding should be finished...cleaning also finished...\n");

		return -1;
	}
	
	return 0;
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
	char* filter_name = "all_in_one";
	if (!img_pixels) {
		printf("[all_in_one:TestEnclave]: Holy sh*t, this should never happen!!!!!!!!!\n");
		return ret;
	}

	// Verify signature
	unsigned char* buf = (unsigned char*)malloc(size_of_img_pixels + size_of_md_json);
	if (!buf) {
		printf("[all_in_one:TestEnclave]: No memory left\n");
		ret = 1;
		return ret;
	}
	memset(buf, 0, size_of_img_pixels + size_of_md_json);
	memcpy(buf, img_pixels, size_of_img_pixels);
	memcpy(buf + size_of_img_pixels, md_json, size_of_md_json);
	// printf("[all_in_one:TestEnclave]: size_of_img_pixels: [%d], size_of_md_json: [%d], size_of_img_sig: [%d], md_json: {%s}\n", size_of_img_pixels, size_of_md_json, size_of_img_sig, md_json);
	// print_public_key(ias_pubkey);
	// printf("[all_in_one:TestEnclave]: img_sig is: {%s}\n", (char*)img_sig);
	ret = verify_hash(buf, size_of_img_pixels + size_of_md_json, (unsigned char*)img_sig, size_of_img_sig, ias_pubkey);
	// printf("verify_hash is called...\n");
	free(buf);
	if (ret != 1) {
		ret = 1;
		printf("[all_in_one:TestEnclave]: Failed to verify signature\n");
		return ret;
	}

	// Parse metadata
	// printf("Going to call json_2_metadata\n");
	metadata* tmp = json_2_metadata((char*)md_json, size_of_md_json);
	if (!tmp) {
		printf("[all_in_one:TestEnclave]: Failed to parse metadata\n");
		ret = 1;
		return ret;
	}
	int filter_idx = get_filter_idx(tmp, filter_name);
	int current_filter_parameter_start_pos = 0;
	for(int i = 0; i < filter_idx; ++i){
		current_filter_parameter_start_pos += (int)(tmp->filters_parameters_registry[i]);
	}

	// Process image
    pixel* processed_pixels;
	size_t processed_pixels_size = sizeof(pixel) * tmp->height * tmp->width;
    processed_pixels = (pixel*)malloc(processed_pixels_size);
	// auto_white_balance((pixel*)img_pixels, processed_pixels, tmp->width, tmp->width * tmp->height);
	blur((pixel*)img_pixels, processed_pixels, tmp->width, tmp->width * tmp->height, (int)tmp->filters_parameters[current_filter_parameter_start_pos++]);
	memcpy((pixel*)img_pixels, processed_pixels, processed_pixels_size);
	memset(processed_pixels, 0, processed_pixels_size);
	// printf("Going to call sharpen\n");
	sharpen((pixel*)img_pixels, processed_pixels, tmp->width, tmp->width * tmp->height, (int)tmp->filters_parameters[current_filter_parameter_start_pos++]);
	
	memcpy((pixel*)img_pixels, processed_pixels, processed_pixels_size);
	memset(processed_pixels, 0, processed_pixels_size);
	auto_white_balance((pixel*)img_pixels, processed_pixels, tmp->width, tmp->width * tmp->height);
	memcpy((pixel*)img_pixels, processed_pixels, processed_pixels_size);
	memset(processed_pixels, 0, processed_pixels_size);
	denoise_simple((pixel*)img_pixels, processed_pixels, tmp->width, tmp->width * tmp->height);
	memcpy((pixel*)img_pixels, processed_pixels, processed_pixels_size);
	memset(processed_pixels, 0, processed_pixels_size);
	change_brightness((pixel*)img_pixels, processed_pixels, tmp->width, tmp->width * tmp->height, tmp->filters_parameters[current_filter_parameter_start_pos++]);
	memcpy((pixel*)img_pixels, processed_pixels, processed_pixels_size);
	memset(processed_pixels, 0, processed_pixels_size);
	gray_frame((pixel*)img_pixels, processed_pixels, tmp->width, tmp->width * tmp->height);

	// printf("Going to call Generate metadata\n");
	// Generate metadata
	int tmp_total_digests = tmp->total_digests;
	tmp->total_digests = tmp_total_digests + 1;
	tmp->digests = (char**)realloc(tmp->digests, sizeof(char*) * (/*decoder*/1 + /*filter*/filter_idx + 1));
	tmp->digests[filter_idx + 1] = (char*)malloc(mrenclave_len);
	memset(tmp->digests[filter_idx + 1], 0, mrenclave_len);
	memcpy(tmp->digests[filter_idx + 1], mrenclave, mrenclave_len);
	char* output_json = metadata_2_json(tmp);
	free_metadata(tmp);


	// printf("Going to call  Create buffer for signing\n");
	// Create buffer for signing
	unsigned char* data_buf = (unsigned char*)malloc(processed_pixels_size + strlen(output_json));
	memset(data_buf, 0, processed_pixels_size + strlen(output_json));
	memcpy(data_buf, processed_pixels, processed_pixels_size);
	memcpy(data_buf + processed_pixels_size, output_json, strlen(output_json));

	//printf("[est_bundle_sharpen_and_blur]");


	// printf("Going to call Generate signature\n");
	// Generate signature
	size_t sig_size = 384;
	unsigned char* sig = (unsigned char*)malloc(sig_size);
	// printf("Going to call sign\n");
	ret = sign(enc_priv_key, (void*)data_buf, processed_pixels_size + strlen(output_json), sig, &sig_size);
	if(ret != 0){
		free(processed_pixels);
		free(sig);
		free(data_buf);
		printf("Failed to generate signature\n");
		return ret;
	}

	// printf("Going to generate output...\n");

	// Copy processed pixels to output buffer
	memset(out_pixels, 0, processed_pixels_size);
	memcpy(out_pixels, processed_pixels, processed_pixels_size);
	memset(out_img_sig, 0, sig_size);
	memcpy(out_img_sig, sig, sig_size);
	// printf("Comparing sig_size: %d with size_of_out_img_sig: %d\n", sig_size, size_of_out_img_sig);
	// size_of_out_img_sig = sig_size;
	memset(out_md_json, 0, strlen(output_json));
	memcpy(out_md_json, output_json, strlen(output_json));
	// size_of_out_md_json = strlen(output_json);

	// printf("Going to Clean up...\n");
	// Clean up
	free(processed_pixels);
	free(sig);
	free(data_buf);
	free(output_json);

	// printf("md_json size is expected to be: %d\n", size_of_out_md_json);
	// printf("Going to return with md_json(%d): {%s}; sig(%d): {%s}...\n", strlen(output_json), out_md_json, sig_size, out_img_sig);

	// printf("Going to return...\n");
	return 0;
}

void t_get_sig_size (size_t* sig_size, char* original_md_json,  size_t original_md_json_size)
{
    // Generate metadata
    // This must be called first before any other signature or metadata related output functions

    // char* output_json_4_in = metadata_2_json(in_md);
    
    // printf("[all_in_one:TestEnclave]: In t_get_sig_size, we have output_json_4_in(%d): [%s]\n", strlen(output_json_4_in), output_json_4_in);
    // free(output_json_4_in);

    out_md = in_md;
	int tmp_total_digests = out_md->total_digests;
	out_md->total_digests = tmp_total_digests + 1;
	out_md->digests = (char**)realloc(out_md->digests, sizeof(char*) * out_md->total_digests);
	out_md->digests[tmp_total_digests] = (char*)malloc(mrenclave_len);
	memset(out_md->digests[tmp_total_digests], 0, mrenclave_len);
	memcpy(out_md->digests[tmp_total_digests], mrenclave, mrenclave_len);

    // printf("[all_in_one:TestEnclave]: original_md_json(%d): {%s}\n", original_md_json_size, original_md_json);

    // For case of SafetyNet
    metadata *original_md = json_2_metadata(original_md_json, original_md_json_size);
    if (original_md->is_safetynet_presented) {
        // printf("[all_in_one:TestEnclave]: safetynet_jws_report_1_size in original_md: %d, safetynet_jws_report_2_size in original_md: %d.\n", strlen(original_md->safetynet_jws[0]), strlen(original_md->safetynet_jws[1]));
        out_md->is_safetynet_presented = original_md->is_safetynet_presented;
        out_md->num_of_safetynet_jws = original_md->num_of_safetynet_jws;
        out_md->safetynet_jws = (char**)malloc(sizeof(char*) * out_md->num_of_safetynet_jws);
        for (int i = 0; i < out_md->num_of_safetynet_jws; ++i) {
            size_t size_of_current_jws = strlen(original_md->safetynet_jws[i]);
            out_md->safetynet_jws[i] = (char*)malloc(sizeof(char) * size_of_current_jws + sizeof(char));
            memcpy(out_md->safetynet_jws[i], original_md->safetynet_jws[i], sizeof(char) * size_of_current_jws);
            out_md->safetynet_jws[i][size_of_current_jws] = '\0';
        }
    }

	char* output_json = metadata_2_json_without_frame_id(out_md);

    if (original_md->is_safetynet_presented) {
        // printf("[all_in_one:TestEnclave]: safetynet_jws_report_1_size in out_md: %d, safetynet_jws_report_2_size in out_md: %d.\n", strlen(out_md->safetynet_jws[0]), strlen(out_md->safetynet_jws[1]));
        // printf("[all_in_one:TestEnclave]: output_json: {%s}\n", output_json);
        printf("[all_in_one:TestEnclave]: After safetynet related data is presented in metadata, the final size of output_json will be: %d\n", strlen(output_json));
    }

    // printf("[all_in_one:TestEnclave]: In t_get_sig_size, we have output_json(%d): [%s]\n", strlen(output_json), output_json);

	// Create buffer for signing
	// unsigned char *buf = (unsigned char*)malloc(total_coded_data_size + strlen(output_json));
	// memset(buf, 0, total_coded_data_size + strlen(output_json));
	// memcpy(buf, total_coded_data, total_coded_data_size);
	// memcpy(buf + total_coded_data_size, output_json, strlen(output_json));

    unsigned char *buf = (unsigned char*)malloc(sizeof_mp4_strm + strlen(output_json));
	memset(buf, 0, sizeof_mp4_strm + strlen(output_json));
	memcpy(buf, mp4_strm, sizeof_mp4_strm);
	memcpy(buf + sizeof_mp4_strm, output_json, strlen(output_json));

    // Sign
    // printf("[all_in_one:TestEnclave]: Going to sign with output_json(%d): [%s]\n", strlen(output_json), output_json);
    // sign_4_encoder(enc_priv_key, buf, total_coded_data_size + strlen(output_json), NULL, sig_size);
    sign_4_encoder(enc_priv_key, buf, sizeof_mp4_strm + strlen(output_json), NULL, sig_size);

    free(buf);
    free(output_json);
    free_metadata(original_md);
}

void t_get_sig (unsigned char* sig, size_t sig_size)
{
	char* output_json = metadata_2_json_without_frame_id(out_md);

    // printf("[EncoderEnclave]: In t_get_sig, we have output_json(%d): [%s]\n", strlen(output_json), output_json);

	// Create buffer for signing
	// unsigned char *buf = (unsigned char*)malloc(total_coded_data_size + strlen(output_json));
	// memset(buf, 0, total_coded_data_size + strlen(output_json));
	// memcpy(buf, total_coded_data, total_coded_data_size);
	// memcpy(buf + total_coded_data_size, output_json, strlen(output_json));

    unsigned char *buf = (unsigned char*)malloc(sizeof_mp4_strm + strlen(output_json));
	memset(buf, 0, sizeof_mp4_strm + strlen(output_json));
	memcpy(buf, mp4_strm, sizeof_mp4_strm);
	memcpy(buf + sizeof_mp4_strm, output_json, strlen(output_json));

    // Sign
    // sign_4_encoder(enc_priv_key, buf, total_coded_data_size + strlen(output_json), &sig, &sig_size);
    sign_4_encoder(enc_priv_key, buf, sizeof_mp4_strm + strlen(output_json), &sig, &sig_size);

    free(buf);
    free(output_json);
}

void t_get_metadata_size (size_t *size_of_metadata) {
    char* output_json = metadata_2_json_without_frame_id(out_md);
    *size_of_metadata = strlen(output_json);
    free(output_json);
}

void t_get_metadata (char* metadata, size_t metadata_size)
{
    // printf("[EncoderEnclave]: We are not in t_get_metadata...with metadata_size: %d\n", metadata_size);
	char* output_json = metadata_2_json_without_frame_id(out_md);

    // printf("[EncoderEnclave]: In t_get_metadata, we get metadata(%d): [%s]\n", strlen(output_json), output_json);

    metadata_size = strlen(output_json);
    memcpy(metadata, output_json, metadata_size);

    // printf("[EncoderEnclave]: Going to free output_json...\n");

    free(output_json);

    // printf("[EncoderEnclave]: t_get_metadata finished...\n");
}

void t_get_encoded_video_size (size_t* out_data_size)
{
    *out_data_size = total_coded_data_size;
}

void t_get_encoded_video (unsigned char* out_data, size_t out_data_size)
{
    memcpy(out_data, total_coded_data, total_coded_data_size);
    out_data_size = total_coded_data_size;
}

int t_mux_video_with_audio (char* audio_meta_in, size_t size_of_audio_meta_in, 
                            char* audio_data_in, size_t size_of_audio_data_in, 
                            unsigned char* audio_related_data_sig_in, size_t size_of_audio_related_data_sig_in, 
                            size_t* size_of_muxed_video) 
{
    // Return 0 on success, otherwise fail

    if (sizeof_mp4_strm != 0) {
        printf("[EncoderEnclave]: Multiple calls of t_mux_video_with_audio is not allowed...\n");
        return 1;
    }

    int res_of_mux = mux(in_md, total_coded_data, total_coded_data_size, (uint8_t*)audio_meta_in, size_of_audio_meta_in, (uint8_t*)audio_data_in, size_of_audio_data_in, &mp4_strm, &sizeof_mp4_strm);
    if (res_of_mux != 0) {
        printf("[EncoderEnclave]: Mux is failed...\n");
        return -1;
    }

    *size_of_muxed_video = sizeof_mp4_strm;
    return 0;
}

int t_get_muxed_video (char* mp4_video, size_t size_of_mp4_video)
{
    // Return 0 on success, otherwise fail
    if (sizeof_mp4_strm == 0) {
        printf("[EncoderEnclave]: call t_mux_video_with_audio first...\n");
        return 1;
    }

    if (size_of_mp4_video != sizeof_mp4_strm) {
        printf("[EncoderEnclave]: size_of_mp4_video: %d is not equal to sizeof_mp4_strm: %d...\n", size_of_mp4_video, sizeof_mp4_strm);
        return 1;
    }

    memcpy(mp4_video, mp4_strm, size_of_mp4_video);

    return 0;
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

	X509 *crt = NULL;
	const unsigned char* p = (unsigned char*)der_cert;
	// printf("Going to call d2i_X509...\n");
	crt = d2i_X509(NULL, &p, der_cert_len);
	// printf("Going to call assert...\n");
	assert(crt != NULL);
	// printf("Going to call X509_get_pubkey...\n");
 	ias_pubkey = X509_get_pubkey(crt);
	// printf("Going to call X509_free...\n");
	X509_free(crt);

	// Copy certificate to output
	memcpy(cert, der_cert, der_cert_len);
	size_of_cert = der_cert_len;
	*(size_t*)actual_size_of_cert = der_cert_len;

	// Get MRENCLAVE value from cert
	get_mrenclave(der_cert, der_cert_len, &mrenclave, &mrenclave_len);
}

void t_free(void)
{
	EVP_PKEY_free(enc_priv_key);

	if(ias_pubkey)
		EVP_PKEY_free(ias_pubkey);

	if (enc)
        free(enc);
    if (scratch)
        free(scratch);
    if (total_coded_data)
        free(total_coded_data);

    if (buf_in)
        free(buf_in);
    if (buf_save)
        free(buf_save);

	if (cl->is_yuyv) {
        if (temp_buf_in){
            printf("free memory for yuyv\n");
            free(temp_buf_in);
        }
    }

	if (cl)
        free(cl);
}
