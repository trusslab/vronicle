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

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fstream>
#include <bits/stdc++.h> 
#include <sys/stat.h> 

#include <unistd.h>
#include <pwd.h>
#include <libgen.h>
#include <stdlib.h>
// #include <pthread.h>

# define MAX_PATH FILENAME_MAX
# define SIZEOFHASH 256
# define SIZEOFSIGN 512
# define SIZEOFPUKEY 2048
# define TARGET_NUM_FILES_RECEIVED 3

#include <sgx_urts.h>

#include "EncoderApp.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h> /* gettimeofday() */
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "minih264e.h"
#include "metadata.h"
#include <math.h>

#include <time.h> /* for time() and ctime() */

// For TCP module
#include <ctime>
#include <cerrno>
#include <cstring>
#include "tcp_module/TCPServer.h"
#include "tcp_module/TCPClient.h"

using namespace std;

#include <chrono> 
using namespace std::chrono;

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

unsigned char* image_buffer = NULL;	/* Points to large array of R,G,B-order data */
unsigned char* pure_input_image_str = NULL; /* for signature verification purpose */
int image_height = 0;	/* Number of rows in image */
int image_width = 0;		/* Number of columns in image */

char* hash_of_file;  /* temp test */

/* Encoder Related definitions and variables */
#define DEFAULT_GOP 20
#define DEFAULT_QP 33
#define DEFAULT_DENOISE 0
#define DEFAULT_FPS 30
#define DEFAULT_IS_YUYV 0
#define DEFAULT_IS_RGB 0

#define ENABLE_TEMPORAL_SCALABILITY 0
#define MAX_LONG_TERM_FRAMES        8 // used only if ENABLE_TEMPORAL_SCALABILITY==1

#define DEFAULT_MAX_FRAMES  99999

H264E_create_param_t create_param;
H264E_run_param_t run_param;
H264E_io_yuv_t yuv;
H264E_io_yuy2_t yuyv;
uint8_t *buf_in, *buf_save;
uint8_t *yuyv_buf_in, *temp_buf_in, *p;
uint8_t *coded_data, *all_coded_data;
char *input_file, *output_file, *input_file_sig, *output_file_sig, *in_ias_cert_file, *out_ias_cert_file, *in_md_file, *out_md_file;
int sizeof_coded_data, _qp;
cmdline *cl;

// TCP Related parameters
int incoming_port = 0;
int port_for_viewer = 0;
TCPServer tcp_server;
TCPServer tcp_server_for_viewer;
pthread_t msg1[MAX_CLIENT];
int num_message = 0;
int time_send   = 1;
int num_of_times_received = 0;
int size_of_msg_buf = 100;
char* msg_buf;

// For incoming data
long size_of_ias_cert = 0;
char *ias_cert = NULL;
long md_json_len_i = 0;
char* md_json_i = NULL;
long raw_signature_length_i = 0;
char* raw_signature_i = NULL;
long raw_frame_buf_len_i = 0;
char* raw_frame_buf_i = NULL;

// For incoming data being processed (Cache of incoming data)
long md_json_len = 0;
char* md_json = NULL;
long raw_signature_length = 0;
char* raw_signature = NULL;
long raw_frame_buf_len = 0;
char* raw_frame_buf = NULL;

// For Outgoing Data
size_t potential_out_md_json_len = -1;

// For evaluation
ofstream eval_file;
ofstream alt_eval_file;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid Intel® Software Guard Extensions device.",
        "Please make sure Intel® Software Guard Extensions module is enabled in the BIOS, and install Intel® Software Guard Extensions driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "Intel® Software Guard Extensions device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

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

void Base64Encode( const unsigned char* buffer,
                   size_t length,
                   char** base64Text, 
                   size_t* actual_base64_len) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    *actual_base64_len = (*bufferPtr).length;
  // printf("Inside Base64Encode we have data(length: %d){%s}\n", (*bufferPtr).length, (*bufferPtr).data);

    *base64Text=(*bufferPtr).data;
}

int num_digits(int x)  
{  
    x = abs(x);  
    return (x < 10 ? 1 :   
        (x < 100 ? 2 :   
        (x < 1000 ? 3 :   
        (x < 10000 ? 4 :   
        (x < 100000 ? 5 :   
        (x < 1000000 ? 6 :   
        (x < 10000000 ? 7 :  
        (x < 100000000 ? 8 :  
        (x < 1000000000 ? 9 :  
        10)))))))));  
}  

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred [0x%x].\n", ret);
}

/* Initialize the enclave:
 *   Step 1: retrive the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    /* Step 1: retrive the launch token saved by last transaction */

    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }
    printf("token_path: %s\n", token_path);
    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }

    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */

    ret = sgx_create_enclave(TESTENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);

    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);

        return -1;
    }

    /* Step 3: save the launch token if it is updated */

    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);

    return 0;
}

/* OCall functions */
void uprint(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
    fflush(stdout);
}


void usgx_exit(int reason)
{
	printf("usgx_exit: %d\n", reason);
	exit(reason);
}

#define UTC_NTP 2208988800U /* 1970 - 1900 */

/* get Timestamp for NTP in LOCAL ENDIAN */
void gettime64(uint32_t ts[])
{
	struct timeval tv;
	gettimeofday(&tv, NULL);

	ts[0] = tv.tv_sec + UTC_NTP;
	ts[1] = (4294*(tv.tv_usec)) + ((1981*(tv.tv_usec))>>11);
}


int die(const char *msg)
{
	if (msg) {
		fputs(msg, stderr);
	}
	exit(-1);
}


void log_request_arrive(uint32_t *ntp_time)
{
	time_t t; 

	if (ntp_time) {
		t = *ntp_time - UTC_NTP;
	} else {
		t = time(NULL);
	}
	printf("A request comes at: %s", ctime(&t));
}


void log_ntp_event(char *msg)
{
	puts(msg);
}

static rd_t psnr_get()
{
    int i;
    rd_t rd;
    double fps = 30;    // Modified for adjusting fps output (Note that this is just for psnr output)
    double realkbps = g_psnr.bytes*8./((double)g_psnr.frames/(fps))/1000;
    double db = 10*log10(255.*255/(g_psnr.noise[0]/g_psnr.count[0]));
    for (i = 0; i < 4; i++)
    {
        rd.psnr[i] = 10*log10(255.*255/(g_psnr.noise[i]/g_psnr.count[i]));
    }
    rd.psnr_to_kbps_ratio = 10*log10((double)g_psnr.count[0]*g_psnr.count[0]*3/2 * 255*255/(g_psnr.noise[0] * g_psnr.bytes));
    rd.psnr_to_logkbps_ratio = db / log10(realkbps);
    rd.kpbs_30fps = realkbps;
    return rd;
}

static void psnr_print(rd_t rd)
{
    int i;
    printf("%5.0f kbps@30fps  ", rd.kpbs_30fps);
    for (i = 0; i < 3; i++)
    {
        //printf("  %.2f db ", rd.psnr[i]);
        printf(" %s=%.2f db ", i ? (i == 1 ? "UPSNR" : "VPSNR") : "YPSNR", rd.psnr[i]);
    }
    printf("  %6.2f db/rate ", rd.psnr_to_kbps_ratio);
    printf("  %6.3f db/lgrate ", rd.psnr_to_logkbps_ratio);
    printf("  \n");
}

static int str_equal(const char *pattern, char **p)
{
    if (!strncmp(pattern, *p, strlen(pattern)))
    {
        *p += strlen(pattern);
        return 1;
    } else
    {
        return 0;
    }
}

static int read_cmdline_options(int argc, char *argv[])
{
    int i;
    input_file = NULL;
    output_file = NULL;
    cl = (cmdline*)malloc(sizeof(cmdline));
    memset(cl, 0, sizeof(cmdline));
    cl->gop = DEFAULT_GOP;
    cl->qp = DEFAULT_QP;
    cl->max_frames = DEFAULT_MAX_FRAMES;
    cl->kbps = 0;
    //cl->kbps = 2048;
    cl->denoise = DEFAULT_DENOISE;
    cl->fps = DEFAULT_FPS;
    cl->is_yuyv = DEFAULT_IS_YUYV;
    cl->is_rgb = DEFAULT_IS_RGB;
    for (i = 1; i < argc; i++)
    {
        char *p = argv[i];
        if (*p == '-')
        {
            p++;
            if (str_equal(("gen"), &p))
            {
                cl->gen = 1;
            } else if (str_equal(("gop"), &p))
            {
                cl->gop = atoi(p);
            } else if (str_equal(("qp"), &p))
            {
                cl->qp = atoi(p);
            } else if (str_equal(("kbps"), &p))
            {
                cl->kbps = atoi(p);
            } else if (str_equal(("maxframes"), &p))
            {
                cl->max_frames = atoi(p);
            } else if (str_equal(("threads"), &p))
            {
                cl->threads = atoi(p);
            } else if (str_equal(("speed"), &p))
            {
                cl->speed = atoi(p);
            } else if (str_equal(("denoise"), &p))
            {
                cl->denoise = 1;
            } else if (str_equal(("stats"), &p))
            {
                cl->stats = 1;
            } else if (str_equal(("psnr"), &p))
            {
                cl->psnr = 1;
            } else if (str_equal(("fps"), &p))
            {
                cl->fps = atoi(p);
            } else if (str_equal(("is_yuyv"), &p))
            {
                cl->is_yuyv = 1;
            } else if (str_equal(("is_rgb"), &p))
            {
                cl->is_rgb = 1;
            } else
            {
                printf("ERROR: Unknown option %s\n", p - 1);
                return 0;
            }
        } else if (!incoming_port && !cl->gen)
        {
            incoming_port = atoi(p);
        } else if (!port_for_viewer)
        {
            port_for_viewer = atoi(p);
        } else
        {
            printf("ERROR: Unknown option %s\n", p);
            return 0;
        }
    }
    if (!incoming_port && !cl->gen)
    {
        printf("Usage:\n"
               "    EncoderApp [options] <incoming_port> <port_for_viewer>\n"
               "Frame size can be: WxH sqcif qvga svga 4vga sxga xga vga qcif 4cif\n"
               "    4sif cif sif pal ntsc d1 16cif 16sif 720p 4SVGA 4XGA 16VGA 16VGA\n"
               "Options:\n"
               "    -gen            - generate input instead of passing <input.yuv>\n"
               "    -qop<n>         - key frame period >= 0\n"
               "    -qp<n>          - set QP [10..51]\n"
               "    -kbps<n>        - set bitrate (fps=30 assumed)\n"
               "    -maxframes<n>   - encode no more than given number of frames\n"
               "    -threads<n>     - use <n> threads for encode\n"
               "    -speed<n>       - speed [0..10], 0 means best quality\n"
               "    -denoise        - use temporal noise supression\n"
               "    -stats          - print frame statistics\n"
               "    -psnr           - print psnr statistics\n"
               "    -fps<n>         - set target fps of the video, default is 30\n"
               "    -is_yuyv        - if the frames' chroma is in yuyv 4:2:2 packed format(note that psnr might not work when using yuyv)\n"
               "    -is_rgb         - if the frames' chroma is in rgb packed format(note that psnr might not work when using rgb)\n");
        return 0;
    }
    return 1;
}

typedef struct
{
    const char *size_name;
    int g_w;
    int h;
} frame_size_descriptor_t;

static const frame_size_descriptor_t g_frame_size_descriptor[] =
{
    {"sqcif",  128,   96},
    { "qvga",  320,  240},
    { "svga",  800,  600},
    { "4vga", 1280,  960},
    { "sxga", 1280, 1024},
    {  "xga", 1024,  768},
    {  "vga",  640,  480},
    { "qcif",  176,  144},
    { "4cif",  704,  576},
    { "4sif",  704,  480},
    {  "cif",  352,  288},
    {  "sif",  352,  240},
    {  "pal",  720,  576},
    { "ntsc",  720,  480},
    {   "d1",  720,  480},
    {"16cif", 1408, 1152},
    {"16sif", 1408,  960},
    { "720p", 1280,  720},
    {"4SVGA", 1600, 1200},
    { "4XGA", 2048, 1536},
    {"16VGA", 2560, 1920},
    {"16VGA", 2560, 1920},
    {NULL, 0, 0},
};

/**
*   Guess image size specification from ASCII string.
*   If string have several specs, only last one taken.
*   Spec may look like "352x288" or "qcif", "cif", etc.
*/
static int guess_format_from_name(const char *file_name, int *w, int *h)
{
    int i = (int)strlen(file_name);
    int found = 0;
    while(--i >= 0)
    {
        const frame_size_descriptor_t *fmt = g_frame_size_descriptor;
        const char *p = file_name + i;
        int prev_found = found;
        found = 0;
        if (*p >= '0' && *p <= '9')
        {
            char * end;
            int width = strtoul(p, &end, 10);
            if (width && (*end == 'x' || *end == 'X') && (end[1] >= '1' && end[1] <= '9'))
            {
                int height = strtoul(end + 1, &end, 10);
                if (height)
                {
                    *w = width;
                    *h = height;
                    found = 1;
                }
            }
        }
        do
        {
            if (!strncmp(file_name + i, fmt->size_name, strlen(fmt->size_name)))
            {
                *w = fmt->g_w;
                *h = fmt->h;
                found = 1;
            }
        } while((++fmt)->size_name);

        if (!found && prev_found)
        {
            return prev_found;
        }
    }
    return found;
}

char* read_file_as_str(const char* file_name, long* str_len){
    // Return str_to_return on success, otherwise, return NULL
    // Need to free the return after finishing using
    FILE* file = fopen(file_name, "r");
    if(file == NULL){
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    *str_len = ftell(file) + 1;
    fseek(file, 0, SEEK_SET);

    char* str_to_return = (char*)malloc(*str_len);

    fread(str_to_return, 1, *str_len - 1, file);

    // printf("When reading {%s}, the str_len is: %d, the very last char is: %c\n", file_name, *str_len, str_to_return[*str_len - 2]);

    str_to_return[*str_len - 1] = '\0';

    fclose(file);

    return str_to_return;
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

unsigned char* read_signature(const char* sign_file_name, size_t* signatureLength){
    // Return signature on success, otherwise, return NULL
    // Need to free the return after finishing using
    FILE* signature_file = fopen(sign_file_name, "r");
    if(signature_file == NULL){
        return NULL;
    }

    fseek(signature_file, 0, SEEK_END);
    long length = ftell(signature_file);
    // printf("read_signature: length of file from ftell is: %d\n", length);
    fseek(signature_file, 0, SEEK_SET);

    char* base64signature = (char*)malloc(length + 1);

    int success_read_count = fread(base64signature, 1, length, signature_file);
    base64signature[success_read_count] = '\0';
    // printf("success_read_count is %d\n", success_read_count);

    fclose(signature_file);

    // printf("base64signautre: {%s}\n", base64signature);
    
    unsigned char* signature;
    Base64Decode(base64signature, &signature, signatureLength);

    free(base64signature);

    return signature;
}

unsigned char* decode_signature(char* encoded_sig, long encoded_sig_len, size_t* signatureLength){
    // Return signature on success, otherwise, return NULL
    // Need to free the return after finishing using
    // Make sure you have extra char space for puting EOF at the end of encoded_sig

    encoded_sig[encoded_sig_len] = '\0';
    unsigned char* signature;
    Base64Decode(encoded_sig, &signature, signatureLength);

    return signature;
}

int start_enclave()
{
	printf("enclave initialization started\n");

    /* Initialize the enclave */
    if (initialize_enclave() < 0)
        return 1; 
    return 0;
}

void wait_wrapper(int s)
{
	wait(&s);
}

void close_app(int signum) {
	printf("There is a SIGINT error happened...exiting......(%d)\n", signum);
    tcp_server.closed();
    tcp_server_for_viewer.closed();
	exit(0);
}

void * received(void * m)
{
    // pthread_detach(pthread_self());

	int current_mode = 0;	// 0 means awaiting reading file's nickname; 1 means awaiting file size; 2 means awaiting file content
    int current_file_indicator = -1;   // 0 means frame; 1 means metadata; 2 means signature; 3 menas cert
    void* current_writing_location = NULL;
    long* current_writing_size = NULL;
	long remaining_file_size = 0;

	int num_of_files_received = 0;

    // Set uniformed msg to skip sleeping
    int size_of_reply = 100;
    char* reply_msg = (char*) malloc(size_of_reply);

    // Prepare temp_buf for receiving data
    char* temp_buf;

	while(num_of_files_received < TARGET_NUM_FILES_RECEIVED)
	{
        // printf("current_mode is: %d, with remaining size: %ld\n", current_mode, remaining_file_size);
        if(current_mode == 0){
            string file_name = tcp_server.receive_name();
            // printf("Got new file_name: %s\n", file_name.c_str());
            if(file_name == "frame"){
                current_file_indicator = 0;
                current_writing_size = &raw_frame_buf_len_i;
            } else if (file_name == "meta"){
                current_file_indicator = 1;
                current_writing_size = &md_json_len_i;
            } else if (file_name == "sig"){
                current_file_indicator = 2;
                current_writing_size = &raw_signature_length_i;
            } else if (file_name == "cert"){
                current_file_indicator = 3;
                current_writing_size = &size_of_ias_cert;
                // Let's cheat the logic as we only need to receive cert once
                num_of_files_received = TARGET_NUM_FILES_RECEIVED - 1;
            } else if (file_name == "no_more_frame"){
                printf("no_more_frame received...finished processing...\n");
                free(reply_msg);
                return 0;
            } else {
                printf("The file_name is not valid: %s\n", file_name);
                free(reply_msg);
                return 0;
            }
            current_mode = 1;
        } else if (current_mode == 1){
            *current_writing_size = tcp_server.receive_size_of_data();
            remaining_file_size = *current_writing_size;
            // printf("File size got: %ld, which should be equal to: %ld\n", remaining_file_size, *current_writing_size);
            // printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!current file indicator is: %d\n", current_file_indicator);
            switch(current_file_indicator){
                case 0:
                    raw_frame_buf_i = (char*) malloc((*current_writing_size + 1) * sizeof(char));
                    current_writing_location = raw_frame_buf_i;
                    break;
                case 1:
                    md_json_i = (char*) malloc(*current_writing_size * sizeof(char));
                    current_writing_location = md_json_i;
                    break;
                case 2:
                    raw_signature_i = (char*) malloc((*current_writing_size + 1) * sizeof(char));
                    current_writing_location = raw_signature_i;
                    break;
                case 3:
                    ias_cert = (char*) malloc((*current_writing_size + 1) * sizeof(char));
                    current_writing_location = ias_cert;
                    break;
                default:
                    printf("No file indicator is set, aborted...\n");
                    free(reply_msg);
                    return 0;
            }
            current_mode = 2;
        } else {
            if(remaining_file_size > SIZEOFPACKAGE_HIGH){
                // printf("!!!!!!!!!!!!!!!!!!!Going to write data to current file location: %d\n", current_file_indicator);
                temp_buf = tcp_server.receive_exact(SIZEOFPACKAGE_HIGH);
                memcpy(current_writing_location, temp_buf, SIZEOFPACKAGE_HIGH);
                current_writing_location += SIZEOFPACKAGE_HIGH;
                remaining_file_size -= SIZEOFPACKAGE_HIGH;
            } else {
                // printf("!!!!!!!!!!!!!!!!!!!Last write to the current file location: %d\n", current_file_indicator);
                temp_buf = tcp_server.receive_exact(remaining_file_size);
                memcpy(current_writing_location, temp_buf, remaining_file_size);
                remaining_file_size = 0;
                current_mode = 0;
                ++num_of_files_received;
                // printf("num_of_files_received: %d\n", num_of_files_received);
            }
        }
        memset(reply_msg, 0, size_of_reply);
        memcpy(reply_msg, "ready", 5);
        tcp_server.send_to_last_connected_client(reply_msg, size_of_reply);
	}
    free(reply_msg);
	return 0;
}

int send_buffer_to_viewer(void* buffer, long buffer_lenth){
    // Return 0 on success, return 1 on failure

	// Send size of buffer
	// printf("Sending buffer size: %d\n", buffer_lenth);
	tcp_server_for_viewer.send_to_last_connected_client(&buffer_lenth, sizeof(long));
    // printf("Going to wait for receive...\n");
	string rec = tcp_server_for_viewer.receive_name();
    // printf("Going to wait for receive(finished)...\n");
	if( rec != "" )
	{
		// cout << rec << endl;
	}

    long remaining_size_of_buffer = buffer_lenth;
    void* temp_buffer = buffer;
    int is_finished = 0;

    printf("Going to start sending buffer...\n");

	while(1)
	{
        if(remaining_size_of_buffer > SIZEOFPACKAGE){
		    tcp_server_for_viewer.send_to_last_connected_client(temp_buffer, SIZEOFPACKAGE);
            remaining_size_of_buffer -= SIZEOFPACKAGE;
            temp_buffer += SIZEOFPACKAGE;
        } else {
		    tcp_server_for_viewer.send_to_last_connected_client(temp_buffer, remaining_size_of_buffer);
            remaining_size_of_buffer = 0;
            is_finished = 1;
        }
        // printf("(inside)Going to wait for receive...just send buffer with size: %d\n", remaining_size_of_buffer);
		string rec = tcp_server_for_viewer.receive_name();
        // printf("(inside)Going to wait for receive(finished)...\n");
		if( rec != "" )
		{
			// cout << "send_buffer received: " << rec << endl;
		}
        if(is_finished){
            break;
        }
	}

    return 0;
}

void cache_incoming_frame_info(){
    md_json_len = md_json_len_i;
    md_json = (char*) malloc(md_json_len * sizeof(char));
    memcpy(md_json, md_json_i, md_json_len);
    free(md_json_i);

    raw_signature_length = raw_signature_length_i;
    raw_signature = (char*) malloc((raw_signature_length + 1) * sizeof(char));
    memcpy(raw_signature, raw_signature_i, raw_signature_length + 1);
    free(raw_signature_i);

    raw_frame_buf_len = raw_frame_buf_len_i;
    raw_frame_buf = (char*) malloc((raw_frame_buf_len + 1) * sizeof(char));
    memcpy(raw_frame_buf, raw_frame_buf_i, raw_frame_buf_len);
    free(raw_frame_buf_i);
}

/* Application entry */
int main(int argc, char *argv[], char **env)
{
    int i = 0, res = -1;
    FILE *fin, *fout, *fsig, *fcert, *fmd;
    sgx_status_t status;

    // Register signal handlers
    std::signal(SIGINT, close_app);
	std::signal(SIGPIPE, sigpipe_handler);

    // Initialize variables
    if (!read_cmdline_options(argc, argv))
        return 1;

    // Check if incoming_port and port_for_viewer are set correctly
    if(incoming_port <= 0 || port_for_viewer <= 0){
        printf("Incoming port: %d or Port for viewer %d is invalid\n", incoming_port, port_for_viewer);
    }
    printf("Incoming port: %d; Port for viewer %d\n", incoming_port, port_for_viewer);

    // Open file to store evaluation results
    mkdir("../../../../evaluation/eval_result", 0777);
    eval_file.open("../../../../evaluation/eval_result/eval_encoder.csv");
    if (!eval_file.is_open()) {
        printf("Could not open eval file.\n");
        return 1;
    }

    alt_eval_file.open("../../../../evaluation/eval_result/eval_encoder_one_time.csv");
    if (!alt_eval_file.is_open()) {
        printf("Could not open alt_eval_file file.\n");
        return 1;
    }

	// Initialize and start the enclave

    auto start = high_resolution_clock::now();

	start_enclave();

    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(stop - start);
    alt_eval_file << duration.count() << ", "; 

    // Create enclave cert
    size_t size_of_cert = 4 * 4096;
    unsigned char *der_cert = (unsigned char *)malloc(size_of_cert);

    start = high_resolution_clock::now();

    status = t_create_key_and_x509(global_eid, der_cert, size_of_cert, &size_of_cert, sizeof(size_t));
    if (status != SGX_SUCCESS) {
        printf("Creating SGX certificate failed\n");
        return 1;
    }

    stop = high_resolution_clock::now();
    duration = duration_cast<microseconds>(stop - start);
    alt_eval_file << duration.count() << ", ";

    // Receive and verify IAS certificate
    pthread_t msg;
    // Receive ias cert
    vector<int> opts = { SO_REUSEPORT, SO_REUSEADDR };
    if( tcp_server.setup(incoming_port,opts) == 0) {
        tcp_server.accepted();
        cerr << "Accepted" << endl;
        start = high_resolution_clock::now();
        if(pthread_create(&msg, NULL, received, (void *)0) != 0){
            printf("pthread for receiving created failed...quiting...\n");
            return 1;
        }
        pthread_join(msg, NULL);
        // printf("ias cert received successfully...\n");
    }
    else
        cerr << "Errore apertura socket" << endl;

    stop = high_resolution_clock::now();
    duration = duration_cast<microseconds>(stop - start);
    alt_eval_file << duration.count() << ", ";

    start = high_resolution_clock::now();

    // Verify certificate in enclave
    int ret;
    sgx_status_t status_of_verification = t_verify_cert(global_eid, &ret, ias_cert, (size_t)size_of_ias_cert);

    stop = high_resolution_clock::now();
    duration = duration_cast<microseconds>(stop - start);
    alt_eval_file << duration.count() << ", ";

    if (status_of_verification != SGX_SUCCESS) {
        cout << "[EncoderApp]: Failed to read IAS certificate file" << endl;
        free(ias_cert);
        return 1;
    }
    free(ias_cert);
    // printf("ias certificate verified successfully, going to start receving and processing frames...\n");

    // Set up parameters for the case each frame is in a single file
    // Assume there are at most 999 frames
    int max_frames = 999; // Assume there are at most 999 frames
    int max_frame_digits = num_digits(max_frames);

    start = high_resolution_clock::now();

    // Receive the very first frame for setting up Encoder
    if( pthread_create(&msg, NULL, received, (void *)0) == 0)
    {
        // tcp_server.accepted();
        // cerr << "Accepted" << endl;
        ++num_of_times_received;
        // printf("num_of_times_received: %d\n", num_of_times_received);
        pthread_join(msg, NULL);
    } else {
        printf("pthread created failed...\n");
    }

    // Cache the very first frame
    start = high_resolution_clock::now();

    // printf("Going to cache incoming frame info...\n");
    cache_incoming_frame_info();
    // printf("Incoming frame info cached...\n");

    stop = high_resolution_clock::now();
    duration = duration_cast<microseconds>(stop - start);
    alt_eval_file << duration.count() << ", ";
    
    start = high_resolution_clock::now();

    // Initialize variables in host
    // printf("Before parsing metadata, we have it(%d): [%s]\n", md_json_len, md_json);
    // Parse metadata
    if (md_json[md_json_len - 1] == '\0') md_json_len--;
    if (md_json[md_json_len - 1] == '\0') md_json_len--;
    // printf("md_json(%ld) going to be used is: [%s]\n", md_json_len, md_json);
    metadata* md = json_2_metadata(md_json, md_json_len);
    if (!md) {
        printf("Failed to parse metadata\n");
        return 1;
    }

    // Use metadata to setup some info
    int g_w = md->width, g_h = md->height;
    int frame_size = 0;
    if (cl->is_yuyv) {
        frame_size = g_w * g_h * 2;
    }
    else if (cl->is_rgb) {
        frame_size = g_w * g_h * 3;
    }
    else {
        frame_size = g_w * g_h * 3/2;
    }
    int total_frames = md->total_frames;
    potential_out_md_json_len = md_json_len + 48 - 17;  // - 17 because of loss of frame_id; TO-DO: make this flexible (Get size dynamically)
    // printf("[EncoderApp]: potential_out_md_json_len: %d\n", potential_out_md_json_len);

    // Continue receiving next frame
    if(total_frames > 1 && pthread_create(&msg, NULL, received, (void *)0) != 0)
    {
        printf("pthread created failed for continuing receiving next frame after first frame...\n");
        return 1;
    }

    // Parse frame
    // uint8_t* frame = new uint8_t [frame_size];
    // memset(frame, 0, frame_size);
    // memcpy(frame, raw_frame_buf, raw_frame_buf_len);
    uint8_t* frame = (uint8_t*)raw_frame_buf;

    // Free frame raw
    // free(raw_frame_buf);
    raw_frame_buf = NULL;
    raw_frame_buf_len = 0;

    // Parse signature
    unsigned char* frame_sig = NULL;
    // size_t frame_sig_len = 0;
    // frame_sig = decode_signature(raw_signature, raw_signature_length, &frame_sig_len);
    size_t frame_sig_len = raw_signature_length;
    frame_sig = (unsigned char*)raw_signature;

    // Free signature raw
    // free(raw_signature);
    raw_signature = NULL;
    raw_signature_length = 0;

    // printf("Going to initialize encoder...\n");

    // Initialize variables in Enclave
    status = t_encoder_init(global_eid, &res,
                            cl, sizeof(cmdline),
                            frame_sig, frame_sig_len,
                            frame, frame_size,
                            md_json, md_json_len);
    if (res || status != SGX_SUCCESS) {
        printf("[EncoderApp]: t_encoder_init failed\n");
        return 1;
    }

    // Do not free everything that will used for encoding the first frame as we only receive it once
    // free(frame_sig);
    // free(md_json);
    free_metadata(md);

    stop = high_resolution_clock::now();
    duration = duration_cast<microseconds>(stop - start);
    alt_eval_file << duration.count() << ", ";
    
    // printf("Going to encode frame 0\n");
    
    start = high_resolution_clock::now();

    // Instead, we encode the very first frame now
    status = t_encode_frame(global_eid, &res, 
                                frame_sig, frame_sig_len,
                                frame, frame_size,
                                md_json, md_json_len);
    if (res || status != SGX_SUCCESS)
    {
        printf("[EncoderApp]: ERROR: encoding frame failed\n");
        free(frame_sig);
        delete frame;
        return 1;
    }
    
    stop = high_resolution_clock::now();
    duration = duration_cast<microseconds>(stop - start);
    alt_eval_file << duration.count() << ", ";

    // Now clean metadata raw data as we directly use it for encoding
    free(md_json);
    md_json = NULL;
    md_json_len = 0;

    // Clean up first frame
    free(frame_sig);

    // printf("Going to encode remaining frames...\n");

    // Encode frames
    for (i = 1; i < total_frames; i++)
    {
        // printf("[EncoderApp]: Going to receive and encode frame %d\n", i);

        start = high_resolution_clock::now();

        // Make sure we already successfully receive the frame
        ++num_of_times_received;
        // printf("num_of_times_received: %d\n", num_of_times_received);
        pthread_join(msg, NULL);

        stop = high_resolution_clock::now();
        duration = duration_cast<microseconds>(stop - start);
        eval_file << duration.count() << ", ";

        start = high_resolution_clock::now();
        
        // Cache this frame
        cache_incoming_frame_info();

        stop = high_resolution_clock::now();
        duration = duration_cast<microseconds>(stop - start);
        eval_file << duration.count() << ", ";

        // Continue receiving next frame
        if(i + 1 < total_frames && pthread_create(&msg, NULL, received, (void *)0) != 0)
        {
            printf("pthread created failed for receiving next frame...\n");
            return 1;
        }
        
        start = high_resolution_clock::now();

        // Parse frame
        // memset(frame, 0, frame_size);
        // memcpy(frame, raw_frame_buf, raw_frame_buf_len);
        frame = (uint8_t*)raw_frame_buf;

        // Free frame raw
        // free(raw_frame_buf);
        raw_frame_buf = NULL;
        raw_frame_buf_len = 0;

        // Parse signature
        // frame_sig_len = 0;
        // frame_sig = decode_signature(raw_signature, raw_signature_length, &frame_sig_len);
        frame_sig_len = raw_signature_length;
        frame_sig = (unsigned char*)raw_signature;

        // Free signature raw
        // free(raw_signature);
        raw_signature = NULL;
        raw_signature_length = 0;

        stop = high_resolution_clock::now();
        duration = duration_cast<microseconds>(stop - start);
        eval_file << duration.count() << ", ";
        
        start = high_resolution_clock::now();

        // Encode frame in enclave
        status = t_encode_frame(global_eid, &res, 
                                frame_sig, frame_sig_len,
                                frame, frame_size,
                                md_json, md_json_len);
        if (res || status != SGX_SUCCESS)
        {
            printf("ERROR: encoding frame failed\n");
            free(frame_sig);
            free(md_json);
            delete frame;
            return 1;
        }
        
        stop = high_resolution_clock::now();
        duration = duration_cast<microseconds>(stop - start);
        eval_file << duration.count() << endl;

        // Clean up
        free(frame_sig);

        // Now clean metadata raw data as we directly use it for encoding
        free(md_json);
        md_json = NULL;
        md_json_len = 0;
    }

    // More clean up
    delete frame;

    tcp_server.closed();

    printf("Encoding completed...going to try sending frames\n");

    // declaring argument of time() 
    time_t my_time = time(NULL); 
  
    // ctime() used to give the present time 
    printf("Encoding completed at: %s", ctime(&my_time));

    if( tcp_server_for_viewer.setup(port_for_viewer,opts) == 0) {
        printf("Ready for viewer to connect...\n");
        tcp_server_for_viewer.accepted();
        cerr << "Accepted viewer" << endl;
    }
    else
        cerr << "Errore apertura socket" << endl;

    // Init msg_buf
    string msg_reply_from_viewer;
    msg_buf = (char*) malloc(size_of_msg_buf);
    
    start = high_resolution_clock::now();

    // Send ias cert
    memset(msg_buf, 0, size_of_msg_buf);
    memcpy(msg_buf, "cert", 4);
    // printf("Going to send msg_buf(%d): [%s]\n", size_of_msg_buf, msg_buf);
    tcp_server_for_viewer.send_to_last_connected_client(msg_buf, size_of_msg_buf);
    printf("Send completed...\n");
    msg_reply_from_viewer = tcp_server_for_viewer.receive_name();
    // printf("Received reply: [%s]\n", msg_reply_from_viewer.c_str());
    if(msg_reply_from_viewer != "ready"){
        printf("No ready received from viewer but: %s\n", msg_reply_from_viewer.c_str());
        return 1;
    }

    send_buffer_to_viewer(der_cert, size_of_cert);

    stop = high_resolution_clock::now();
    duration = duration_cast<microseconds>(stop - start);
    alt_eval_file << duration.count() << ", ";

    free(der_cert);
    
    start = high_resolution_clock::now();

    // Send encoded video
    size_t total_coded_data_size = 0;
    status = t_get_encoded_video_size(global_eid, &total_coded_data_size);
    if (total_coded_data_size == 0 || status != SGX_SUCCESS) {
        printf("t_get_encoded_video_size failed\n");
        return 1;
    }
    unsigned char *total_coded_data = new unsigned char [total_coded_data_size];
    status = t_get_encoded_video(global_eid, total_coded_data, total_coded_data_size);
    if (status != SGX_SUCCESS) {
        printf("t_get_encoded_video failed\n");
        return 1;
    }

    memset(msg_buf, 0, size_of_msg_buf);
    memcpy(msg_buf, "vid", 3);
    tcp_server_for_viewer.send_to_last_connected_client(msg_buf, size_of_msg_buf);
    msg_reply_from_viewer = tcp_server_for_viewer.receive_name();
    if(msg_reply_from_viewer != "ready"){
        printf("No ready received from viewer but: %s\n", msg_reply_from_viewer.c_str());
        return 1;
    }

    send_buffer_to_viewer(total_coded_data, total_coded_data_size);

    stop = high_resolution_clock::now();
    duration = duration_cast<microseconds>(stop - start);
    alt_eval_file << duration.count() << ", ";

    delete total_coded_data;

    start = high_resolution_clock::now();

    // Send signature
    size_t sig_size = 0;
    status = t_get_sig_size(global_eid, &sig_size);
    if (sig_size == 0 || status != SGX_SUCCESS) {
        printf("t_get_sig_size failed\n");
        return 1;
    }
    unsigned char *sig = new unsigned char [sig_size];
    status = t_get_sig(global_eid, sig, sig_size);
    if (status != SGX_SUCCESS) {
        printf("t_get_sig failed\n");
        return 1;
    }
    char* b64_sig = NULL;
    size_t b64_sig_size = 0;
    Base64Encode(sig, sig_size, &b64_sig, &b64_sig_size);

    memset(msg_buf, 0, size_of_msg_buf);
    memcpy(msg_buf, "sig", 3);
    tcp_server_for_viewer.send_to_last_connected_client(msg_buf, size_of_msg_buf);
    msg_reply_from_viewer = tcp_server_for_viewer.receive_name();
    if(msg_reply_from_viewer != "ready"){
        printf("No ready received from viewer but: %s\n", msg_reply_from_viewer.c_str());
        return 1;
    }

    send_buffer_to_viewer(b64_sig, b64_sig_size);

    stop = high_resolution_clock::now();
    duration = duration_cast<microseconds>(stop - start);
    alt_eval_file << duration.count() << ", ";

    delete sig;
    free(b64_sig);
    
    start = high_resolution_clock::now();

    // Send metadata
    char* out_md_json = (char*)malloc(potential_out_md_json_len);
    status = t_get_metadata(global_eid, out_md_json, potential_out_md_json_len);
    // printf("[EncoderApp]: t_get_metadata just finished...\n");
    if (status != SGX_SUCCESS) {
        printf("[EncoderApp]: t_get_metadata failed\n");
        return 1;
    }
    if (cl->stats)
    {
        printf ("[EncoderApp]: out_metadata: %s\n", out_md_json);
    }

    // printf("[EncoderApp]: Going to send metadata(%d): [%s]\n", potential_out_md_json_len, out_md_json);

    memset(msg_buf, 0, size_of_msg_buf);
    memcpy(msg_buf, "meta", 4);
    tcp_server_for_viewer.send_to_last_connected_client(msg_buf, size_of_msg_buf);
    msg_reply_from_viewer = tcp_server_for_viewer.receive_name();
    if(msg_reply_from_viewer != "ready"){
        printf("[EncoderApp]: No ready received from viewer but: %s\n", msg_reply_from_viewer.c_str());
        return 1;
    }

    // printf("[EncoderApp]: Going to send metadata(%d): [%s]\n", potential_out_md_json_len, out_md_json);
    send_buffer_to_viewer(out_md_json, potential_out_md_json_len);

    stop = high_resolution_clock::now();
    duration = duration_cast<microseconds>(stop - start);
    alt_eval_file << duration.count() << endl;

    printf("[EncoderApp]: All files sent successfully...going to quit...\n");

    free(out_md_json);

    if (cl->psnr)
        psnr_print(psnr_get());

    // if (fin)
    //     fclose(fin);
    // if (fout)
    //     fclose(fout);
    // if (fsig)
    //     fclose(fsig);
    // if (cl)
    //     free(cl);

    status = t_free(global_eid);
    if (status != SGX_SUCCESS) {
        printf("t_get_sig failed\n");
        return 1;
    }

    // Close eval file
    eval_file.close();
    alt_eval_file.close();

	/* after verification we destroy the enclave */
    sgx_destroy_enclave(global_eid);
	return 0;
}


