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

#include "EncoderEnclave.h"
#include "EncoderEnclave_t.h"  /* print_string */
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

#include "yuvconverter.h"

// Encoder related global variables
#include "minih264e.h"
#include "metadata.h"
#include <math.h>

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
char* mrenclave;
size_t mrenclave_len;

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
EVP_PKEY **ias_pubkeys;
int num_of_ias_pubkey_allocated = 0;    // Note that this may not be the true number of ias_pubkeys available

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

int sign(EVP_PKEY* priKey, unsigned char *data, size_t data_size, unsigned char** sig, size_t *sig_size){
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

int verify_sig (void* file, size_t size_of_file,
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

int t_encoder_init (cmdline *cl_in, size_t cl_size, 
                    unsigned char* frame_sig, size_t frame_sig_size,
                    uint8_t* frame, size_t frame_size,
                    char* md_json,  size_t md_json_size, 
                    size_t client_id)
{
    int res = -1;
    // Verify first frame and metadata to obtain 
    // frame-related information from metadata
    if (!ias_pubkeys || !ias_pubkeys[client_id]) {
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
    res = verify_sig((void*)buf, frame_size + md_json_size, frame_sig, frame_sig_size, ias_pubkeys[client_id]);
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
    free(buf);
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
                    char* md_json,  size_t md_json_size, 
                    size_t client_id)
{
    int res = -1;
    // Verify signature of frame
    // The signature should have two information:
    // (1) The frame
    // (2) A metadata of the frame (frame ID, total # of frames, segment ID)
    if (!ias_pubkeys || !ias_pubkeys[client_id]) {
        printf("Run t_verify_cert first\n");
        return -1;
    }
    unsigned char* buf = (unsigned char*)malloc(frame_size + md_json_size);
    if (!buf) {
        printf("No memory left\n");
        return res;
    }
    memset(buf, 0, frame_size + md_json_size);
    memcpy(buf, frame, frame_size);
    memcpy(buf + frame_size, md_json, md_json_size);
    res = verify_sig((void*)buf, frame_size + md_json_size, frame_sig, frame_sig_size, ias_pubkeys[client_id]);
    if (res != 1) {
        printf("Signature cannot be verified\n");
        return -1;
    }
    free(buf);
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

int t_verify_cert(void* ias_cert, size_t size_of_ias_cert, size_t client_id)
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

        if(client_id + 1 > num_of_ias_pubkey_allocated){
            num_of_ias_pubkey_allocated = client_id + 1;
            ias_pubkeys = (EVP_PKEY**)realloc(ias_pubkeys, num_of_ias_pubkey_allocated * sizeof(EVP_PKEY*));
        }

		// Extract public key from IAS certificate
		ias_pubkeys[client_id] = EVP_PKEY_new();
 	    const unsigned char* p = (unsigned char*)ias_cert;
 	    crt = d2i_X509(NULL, &p, size_of_ias_cert);
 	    assert(crt != NULL);
 	    ias_pubkeys[client_id] = X509_get_pubkey(crt);
		if(!ias_pubkeys[client_id]){
			ret = 1;
			printf("Failed to retreive public key\n");
			break;
		}
	} while(0);

	// Clean up
    if (crt) X509_free(crt);
	return ret;
}

void t_get_sig_size (size_t* sig_size)
{
    // Generate metadata

    // char* output_json_4_in = metadata_2_json(in_md);
    
    // printf("[EncoderEnclave]: In t_get_sig_size, we have output_json_4_in(%d): [%s]\n", strlen(output_json_4_in), output_json_4_in);
    // free(output_json_4_in);

    out_md = in_md;
	int tmp_total_digests = out_md->total_digests;
	out_md->total_digests = tmp_total_digests + 1;
	out_md->digests = (char**)realloc(out_md->digests, sizeof(char*) * out_md->total_digests);
	out_md->digests[tmp_total_digests] = (char*)malloc(mrenclave_len);
	memset(out_md->digests[tmp_total_digests], 0, mrenclave_len);
	memcpy(out_md->digests[tmp_total_digests], mrenclave, mrenclave_len);
	char* output_json = metadata_2_json_without_frame_id(out_md);

    // printf("[EncoderEnclave]: In t_get_sig_size, we have output_json(%d): [%s]\n", strlen(output_json), output_json);

	// Create buffer for signing
	unsigned char *buf = (unsigned char*)malloc(total_coded_data_size + strlen(output_json));
	memset(buf, 0, total_coded_data_size + strlen(output_json));
	memcpy(buf, total_coded_data, total_coded_data_size);
	memcpy(buf + total_coded_data_size, output_json, strlen(output_json));

    // Sign
    // printf("Going to sign with output_json(%d): [%s]\n", strlen(output_json), output_json);
    sign(enc_priv_key, buf, total_coded_data_size + strlen(output_json), NULL, sig_size);

    free(buf);
    free(output_json);
}

void t_get_sig (unsigned char* sig, size_t sig_size)
{
	char* output_json = metadata_2_json_without_frame_id(out_md);

    // printf("[EncoderEnclave]: In t_get_sig, we have output_json(%d): [%s]\n", strlen(output_json), output_json);

	// Create buffer for signing
	unsigned char *buf = (unsigned char*)malloc(total_coded_data_size + strlen(output_json));
	memset(buf, 0, total_coded_data_size + strlen(output_json));
	memcpy(buf, total_coded_data, total_coded_data_size);
	memcpy(buf + total_coded_data_size, output_json, strlen(output_json));

    // Sign
    sign(enc_priv_key, buf, total_coded_data_size + strlen(output_json), &sig, &sig_size);

    free(buf);
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
    if (ias_pubkeys){
        for(int i = 0; i < num_of_ias_pubkey_allocated; ++i){
            if(ias_pubkeys[i])
                EVP_PKEY_free(ias_pubkeys[i]);
        }
        free(ias_pubkeys);
    }
    if (enc_priv_key)
        EVP_PKEY_free(enc_priv_key);

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
    
    // Probably just need to free in_md as I saw out_md is the same as in_md
    // if (in_md)
    //     free_metadata(in_md);

    // Need to free more if yuyv frames are src
    if (cl->is_yuyv) {
        if (temp_buf_in){
            printf("free memory for yuyv\n");
            free(temp_buf_in);
        }
    }

    // Need to free more if yuyv frames are src
    // Update: Probably no longer needed
    // if (cl->is_rgb) {
    //     if (temp_buf_in){
    //         printf("free memory for rgb\n");
    //         free(temp_buf_in);
    //     }
    // }

    if (cl)
        free(cl);
}
