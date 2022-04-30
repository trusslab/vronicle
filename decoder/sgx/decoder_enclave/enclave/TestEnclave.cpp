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

// Include for Decoder
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>

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
u32 readBytes;
u32 len;
size_t size_of_audio_strm = 0, size_of_audio_meta_strm = 0, size_of_audio_sig = 0;

#include "metadata.h"

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

int is_source_video_verified = -3;
int is_decoding_finished = 0;

// For Decoding use
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

int expand_allocation_space_if_necessary(void** pointer_to_check, u32 *size_of_data, u32 current_used_size, u32 size_to_write, u32 size_to_expand) 
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

int adjust_allocation_space_as_needed(void** pointer_to_check, u32 *size_of_data, u32 current_used_size)
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

int demux(uint8_t *input_buf, size_t input_size, 
	uint8_t **video_out, u32 *size_of_video_out, // TO-DO: Might want to change u32 to size_t
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

	u32 standard_block_size = 1000000;	// For controlling how video_out, audio_out, audio_meta_out grow

	u32 current_size_of_video_out = standard_block_size;
	u32 current_used_size_of_video_out = 0;
	u32 current_size_of_audio_out = standard_block_size;
	u32 current_used_size_of_audio_out = 0;
	u32 current_size_of_audio_meta_out = standard_block_size;
	u32 current_used_size_of_audio_meta_out = 0;

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

// int is_test_2_printed = 0;

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
	printf("Size of input_content_buffer is: %ld, size of md_json is: %ld, size of vid_sig: %d\n", size_of_input_content_buffer, md_json_len, vid_sig_len);
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

	// while (!frame_size_in_rgb){
	// 	u32 result = h264bsdDecode(&dec, byteStrm, len, 0, &readBytes);
	// 	printf("[decoder:TestEnclave]: t_sgxver_prepare_decoder: readBytes: [%d], frame_size: [%d]\n", readBytes, frame_size_in_rgb);
	// 	len -= readBytes;
	// 	byteStrm += readBytes;

	// 	switch (result) {
	// 		case H264BSD_HDRS_RDY:
	// 			// Obtain frame parameters
	// 			h264bsdCroppingParams(&dec, &croppingFlag, &left, &width, &top, &height);
	// 			if (!croppingFlag) {
	// 			width = h264bsdPicWidth(&dec) * 16;
	// 			height = h264bsdPicHeight(&dec) * 16;
	// 			}
	// 			// Allocate memory for frame
	// 			if(!frame_size_in_rgb){
	// 				frame_size_in_rgb = width * height * 3;
	// 				InitConvt(width, height);
	// 			}
	// 			break;
	// 		case H264BSD_RDY:
	// 			break;
	// 		case H264BSD_ERROR:
	// 			printf("Error\n");
	// 			return 1;
	// 		case H264BSD_PARAM_SET_ERROR:
	// 			printf("Param set error\n");
	// 			return 1;
	// 		default:
	// 			break;
	// 	}
	// }

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
// 				// printf("[decode:TestEnclave]: We now have output_json_n[%d]: {%s}\n", strlen(output_json_n), output_json_n);

// 				// Check size of md_json
// 				real_size_of_output_md_json = strlen(output_json_n);
// 				if(real_size_of_output_md_json != (size_t)size_of_output_json){
// 					printf("[decode:TestEnclave]: Incorrect md_json size...real_size_of_output_md_json: [%d]; size_of_output_json: [%ld]\n", real_size_of_output_md_json, size_of_output_json);
// 					return 1;
// 				}
// 				memcpy(output_md_json_temp, output_json_n, real_size_of_output_md_json);
// 				// printf("[decode:TestEnclave]: We now have output_json_n[%d]: {%s}\n", real_size_of_output_md_json, output_md_json_temp);

// 				// Create buffer for signing
// 				data_buf = (unsigned char*)malloc(frame_size_in_rgb + real_size_of_output_md_json);
// 				memset(data_buf, 0, frame_size_in_rgb + real_size_of_output_md_json);
// 				memcpy(data_buf, decoded_frame_temp, frame_size_in_rgb);
// 				memcpy(data_buf + frame_size_in_rgb, output_md_json_temp, real_size_of_output_md_json);

// 				// Generate signature
// 				// printf("[decode:TestEnclave]: orig size: %li, sig size: %li, json: %s\n", frame_size_in_rgb + real_size_of_output_md_json, pic_sig_len, output_md_json_temp);
// 				// printf("[decode:TestEnclave]: orig size: %li, sig size: %li, json: %s\n", frame_size_in_rgb + real_size_of_output_md_json, pic_sig_len, output_md_json_temp);
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
// 				// printf("[decoder:TestEnclave]: in H264BSD_HDRS_RDY ...\n");
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
// 						printf("[decoder:TestEnclave]: Incorrect size...size_of_decoded_frame: [%d]; frame_size_in_rgb: [%d]...\n", size_of_decoded_frame, frame_size_in_rgb);
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
	printf("Size of input_content_buffer is: %ld, size of md_json is: %ld, size of vid_sig: %d\n", size_of_input_content_buffer, md_json_len, vid_sig_len);
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
		// printf("[decoder:TestEnclave]: readBytes: [%d], frame_size: [%d]\n", readBytes, frame_size_in_rgb);
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
			// printf("[decode:TestEnclave]: orig size: %li, sig size: %li, json: %s\n", frame_size_in_rgb + strlen(output_json), pic_sig_len, output_json);
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
			// printf("[decoder:TestEnclave]: in H264BSD_HDRS_RDY ...\n");
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

#ifndef ENABLE_DCAP
extern struct ra_tls_options my_ra_tls_options;
#else
extern struct ecdsa_ra_tls_options my_ecdsa_ra_tls_options;
#endif

void t_create_key_and_x509(void* cert, size_t size_of_cert,
					       void* actual_size_of_cert, size_t asoc)
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
	freeEverthing();
}
