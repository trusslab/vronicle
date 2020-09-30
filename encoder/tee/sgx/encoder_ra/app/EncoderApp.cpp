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
pixel* image_pixels;    /* also RGB, but all 3 vales in a single instance (used for processing filter) */
int image_height = 0;	/* Number of rows in image */
int image_width = 0;		/* Number of columns in image */

char* hash_of_file;  /* temp test */

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
        } else if (!input_file && !cl->gen)
        {
            input_file = p;
        } else if (!output_file)
        {
            output_file = p;
        } else if (!input_file_sig)
        {
            input_file_sig = p;
        } else if (!output_file_sig)
        {
            output_file_sig = p;
        } else if (!in_ias_cert_file)
        {
            in_ias_cert_file = p;
        } else if (!out_ias_cert_file)
        {
            out_ias_cert_file = p;
        } else if (!in_md_file)
        {
            in_md_file = p;
        } else if (!out_md_file)
        {
            out_md_file = p;
        } else
        {
            printf("ERROR: Unknown option %s\n", p);
            return 0;
        }
    }
    if (!input_file && !cl->gen)
    {
        printf("Usage:\n"
               "    h264e_test [options] <path_to_input_frames> <output.264> <path_to_input_frame_sigs> <output.sig> <path_to_filter_cert> <encoder_cert.der>\n"
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
               "    -is_rgb         - if the frames' chroma is in rgb packed format(note that psnr might not work when using rgb)");
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

// Keep the following two functions in case we need it in the future

// void request_process_loop(int fd, char** argv)
// {
// 	struct sockaddr src_addr;
// 	socklen_t src_addrlen = sizeof(src_addr);
// 	unsigned char buf[48];
// 	uint32_t recv_time[2];
// 	pid_t pid;

// 	while (1) {
// 		while (recvfrom(fd, buf,
// 				48, 0,
// 				&src_addr,
// 				&src_addrlen)
// 			< 48 );  /* invalid request */

// 		gettime64(recv_time);

//         if(strcmp((char*) buf, "no_more_frame") == 0){
//             printf("No more frame detected, ending encalve server...\n");
//             break;
//         }

//         auto start = high_resolution_clock::now();
// 		verification_reply(fd, &src_addr , src_addrlen, buf, recv_time, argv);
//         auto stop = high_resolution_clock::now();
//         auto duration = duration_cast<microseconds>(stop - start);
//         cout << "Processing frame " << (char*)buf << " takes time: " << duration.count() << endl; 

// 	}
// }


// void sgx_server(char** argv)
// {
// 	int s;
// 	struct sockaddr_in sinaddr;

// 	s = socket(AF_INET, SOCK_DGRAM, 0);
// 	if (s == -1) {
// 		perror("Can not create socket.");
// 		die(NULL);
// 	}

// 	memset(&sinaddr, 0, sizeof(sinaddr));
// 	sinaddr.sin_family = AF_INET;
// 	sinaddr.sin_port = htons(123);
// 	sinaddr.sin_addr.s_addr = INADDR_ANY;

// 	if (0 != bind(s, (struct sockaddr *)&sinaddr, sizeof(sinaddr))) {
// 		perror("Bind error");
// 		die(NULL);
// 	}

// 	log_ntp_event(	"\n========================================\n"
// 			"= Server started, waiting for requests =\n"
// 			"========================================\n");

// 	request_process_loop(s, argv);
// 	close(s);
// }

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


/* Application entry */
int main(int argc, char *argv[], char **env)
{
    int i = 0, res = -1;
    FILE *fin, *fout, *fsig, *fcert, *fmd;
    sgx_status_t status;

    // Initialize variables
    if (!read_cmdline_options(argc, argv))
        return 1;

    // printf("Input parameters:\n\
    //         input_file             : %s\n\
    //         output_file            : %s\n\
    //         input_file_sig         : %s\n\
    //         output_file_sig        : %s\n\
    //         in_ias_cert_file       : %s\n\
    //         out_ias_cert_file      : %s\n",
    //         fnin, fnout, fninsig, fnoutsig, fniniascert, fnoutiascert
    //       );

    if (!output_file)
        output_file = "output.h264";
    if (!output_file_sig)
        output_file_sig = "output.sig";
    if (!out_ias_cert_file)
        out_ias_cert_file = "encoder_cert.der";

	// Initialize and start the enclave
	start_enclave();

    // Create enclave cert
    size_t size_of_cert = 4 * 4096;
    unsigned char *der_cert = (unsigned char *)malloc(size_of_cert);
    auto start = high_resolution_clock::now();
    status = t_create_key_and_x509(global_eid, der_cert, size_of_cert, &size_of_cert, sizeof(size_t));
    if (status != SGX_SUCCESS) {
        printf("Creating SGX certificate failed\n");
        return 1;
    }
    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(stop - start);
    cout << "Conducting RA took time: " << duration.count() << endl; 

    // Save Enclave cert
    FILE* out_cert_file = fopen(out_ias_cert_file, "w");
    fwrite(der_cert, size_of_cert, 1, out_cert_file);
    fclose(out_cert_file);

	/* create the server waiting for the verification request from the client */
	// signal(SIGCHLD,wait_wrapper);
	// sgx_server(argv);

    // Verify IAS certificate
    printf("Reading in_ias_cert_file: %s\n", in_ias_cert_file);
    fcert = fopen(in_ias_cert_file, "r");
    if (!fcert)
    {
        printf("ERROR: cant open IAS cert file %s\n", in_ias_cert_file);
        return 1;
    }
    fseek(fcert, 0, SEEK_END);
    size_t size_of_ias_cert = (size_t)ftell(fcert);
    fseek(fcert, 0, SEEK_SET);
    char* ias_cert = (char*)malloc(size_of_ias_cert);
    if (!ias_cert) {
        cout << "Not enough memory" << endl;
        free(ias_cert);
        fclose(fcert);
        return 1;
    }
    size_t fread_result = fread(ias_cert, 1, size_of_ias_cert, fcert);
    if (fread_result != size_of_ias_cert) {
        cout << "Failed to read IAS certificate file" << endl;
        free(ias_cert);
        fclose(fcert);
        return 1;
    }
    fclose(fcert);
    status = t_verify_cert(global_eid, &res, ias_cert, size_of_ias_cert);
    if (status != SGX_SUCCESS || res) {
        cout << "Failed to read IAS certificate file" << endl;
        free(ias_cert);
        return res;
    }
    free(ias_cert);

    // Set up parameters for the case each frame is in a single file
    // Assume there are at most 999 frames
    int max_frames = 999; // Assume there are at most 999 frames
    int max_frame_digits = num_digits(max_frames);
    int length_of_base_frame_file_name = (int)strlen(input_file);
    int size_of_current_frame_file_name = sizeof(char) * (length_of_base_frame_file_name + sizeof(char) * max_frame_digits);
    char current_frame_file_name[size_of_current_frame_file_name];
    int length_of_base_sig_file_name = (int)strlen(input_file_sig);
    int size_of_current_sig_file_name = sizeof(char) * length_of_base_sig_file_name + sizeof(char) * max_frame_digits;
    char current_sig_file_name[size_of_current_sig_file_name];
    int length_of_base_md_file_name = (int)strlen(in_md_file);
    int size_of_current_md_file_name = sizeof(char) * length_of_base_md_file_name + sizeof(char) * max_frame_digits;
    char current_md_file_name[size_of_current_md_file_name];

    // Initialize variables in host
    // Read metadata
    memset(current_md_file_name, 0, size_of_current_md_file_name);
    memcpy(current_md_file_name, in_md_file, sizeof(char) * length_of_base_md_file_name);
    sprintf(current_md_file_name + sizeof(char) * length_of_base_md_file_name, "%d.json", i);
    long md_json_len = 0;
    char* md_json = read_file_as_str(current_md_file_name, &md_json_len);
    // printf("md_json_len: %d\n", md_json_len);
    if (!md_json) {
        printf("Failed to read metadata from file: %s\n", current_md_file_name);
        return 1;
    }
    metadata *md = json_2_metadata(md_json, md_json_len - 1);
    if (!md) {
        printf("Failed to parse metadata\n");
        return 1;
    }
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
    // Read frame
    uint8_t* frame = new uint8_t [frame_size];
    memset(current_frame_file_name, 0, size_of_current_frame_file_name);
    memcpy(current_frame_file_name, input_file, sizeof(char) * length_of_base_frame_file_name);
    sprintf(current_frame_file_name + sizeof(char) * length_of_base_frame_file_name, "%d", i);
    printf("Now reading file: %s\n", current_frame_file_name);
    fin = fopen(current_frame_file_name, "rb");
    if(!fin){
        printf("Finished reading frames\n");
        return 1;
    }
    memset(frame, 0, frame_size);
    if (!fread(frame, frame_size, 1, fin))
    {
        printf("Finished reading frames\n");
        fclose(fin);
        return 1;
    }
    fclose(fin);
    // Read signature
    memset(current_sig_file_name, 0, size_of_current_sig_file_name);
    memcpy(current_sig_file_name, input_file_sig, sizeof(char) * length_of_base_sig_file_name);
    sprintf(current_sig_file_name + sizeof(char) * length_of_base_sig_file_name, "%d", i);
    printf("Now reading sig: %s\n", current_sig_file_name);
    unsigned char* frame_sig = NULL;
    size_t frame_sig_len = 0;
    frame_sig = read_signature(current_sig_file_name, &frame_sig_len);
    if (!frame_sig || frame_sig_len == 0) {
        printf("ERROR: Reading signature failed\n");
        delete frame;
        return 1;
    }
    // Initialize variables in Enclave
    status = t_encoder_init(global_eid, &res,
                            cl, sizeof(cmdline),
                            frame_sig, frame_sig_len,
                            frame, frame_size,
                            md_json, md_json_len - 1);
    if (res || status != SGX_SUCCESS) {
        printf("t_encoder_init failed\n");
        return 1;
    }
    int total_frames = md->total_frames;
    free(frame_sig);
    free(md_json);
    free(md);

    // Encode frames
    for (i = 0; i < total_frames; i++)
    {
        // Read metadata
        memset(current_md_file_name, 0, size_of_current_md_file_name);
        memcpy(current_md_file_name, in_md_file, sizeof(char) * length_of_base_md_file_name);
        sprintf(current_md_file_name + sizeof(char) * length_of_base_md_file_name, "%d.json", i);
        printf("Now reading file: %s\n", current_md_file_name);
        fmd = fopen(current_md_file_name, "rb");
        if(!fmd){
            printf("Failed to open file: %s\n", current_md_file_name);
            break;
        }
        long md_json_len = 0;
        char* md_json = read_file_as_str(current_md_file_name, &md_json_len);
        if (!md_json) {
            printf("Failed to read metadata from file: %s\n", current_md_file_name);
            return 1;
        }

        // Read frame
        memset(current_frame_file_name, 0, size_of_current_frame_file_name);
        memcpy(current_frame_file_name, input_file, sizeof(char) * length_of_base_frame_file_name);
        sprintf(current_frame_file_name + sizeof(char) * length_of_base_frame_file_name, "%d", i);
        printf("Now reading file: %s\n", current_frame_file_name);
        fin = fopen(current_frame_file_name, "rb");
        if(!fin){
            printf("Finished reading frames\n");
            break;
        }
        memset(frame, 0, frame_size);
        if (!fread(frame, frame_size, 1, fin))
        {
            printf("Finished reading frames\n");
            fclose(fin);
            break;
        }
        fclose(fin);

        // Read signature
        memset(current_sig_file_name, 0, size_of_current_sig_file_name);
        memcpy(current_sig_file_name, input_file_sig, sizeof(char) * length_of_base_sig_file_name);
        sprintf(current_sig_file_name + sizeof(char) * length_of_base_sig_file_name, "%d", i);
        printf("Now reading sig: %s\n", current_sig_file_name);
        unsigned char* frame_sig = NULL;
        size_t frame_sig_len = 0;
        frame_sig = read_signature(current_sig_file_name, &frame_sig_len);
        if (!frame_sig || frame_sig_len == 0) {
            printf("ERROR: Reading signature failed\n");
            delete frame;
            return 1;
        }

        // Encode frame in enclave
        status = t_encode_frame(global_eid, &res, 
                                frame_sig, frame_sig_len,
                                frame, frame_size,
                                md_json, md_json_len - 1);
        if (res || status != SGX_SUCCESS)
        {
            printf("ERROR: encoding frame failed\n");
            free(frame_sig);
            delete frame;
            return 1;
        }

        // Clean up
        free(frame_sig);
        free(md_json);
    }
    delete frame;

    // Store encoded video
    fout = fopen(output_file, "wb");
    if (!fout)
    {
        printf("ERROR: cant open output file %s\n", output_file);
        return 1;
    }
    else // if (fout)
    {
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
        // printf("coded_data_size: %li\n", total_coded_data_size);
        if (!total_coded_data)
        {
            printf("ERROR obtaining encoded video\n");
            return 1;
        }
        if (!fwrite(total_coded_data, total_coded_data_size, 1, fout))
        {
            printf("ERROR writing encoded video\n");
            return 1;
        }
        delete total_coded_data;
    }

    // Store signature
    fsig = fopen(output_file_sig, "w");
    if (!fsig)
    {
        printf("ERROR: cant open output file %s\n", output_file_sig);
        return 1;
    }
    else // if (fsig)
    {
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
        if (!fwrite(b64_sig, b64_sig_size, 1, fsig))
        {
            printf("ERROR writing signature\n");
            return 1;
        }
        if (cl->stats)
        {
            printf ("{\"sig\":\"");
            for (int i = 0; i < (int)sig_size; i++) {
                printf("%02x", (unsigned char) sig[i]);
            }
            printf("\"}\n");
        }
        delete sig;
    }

    // Store metadata
    fmd = fopen(out_md_file, "w");
    if (!fmd)
    {
        printf("ERROR: cant open output file %s\n", out_md_file);
        return 1;
    }
    else // if (fmd)
    {
        size_t out_md_json_len = 409;
        char* out_md_json = (char*)malloc(out_md_json_len);
        status = t_get_metadata(global_eid, out_md_json, out_md_json_len);
        if (status != SGX_SUCCESS) {
            printf("t_get_metadata failed\n");
            return 1;
        }
        if (!fwrite(out_md_json, out_md_json_len, 1, fmd))
        {
            printf("ERROR writing metadata\n");
            return 1;
        }
        if (cl->stats)
        {
            printf ("out_metadata: %s\n", out_md_json);
        }
        free(out_md_json);
    }

    if (cl->psnr)
        psnr_print(psnr_get());

    if (fin)
        fclose(fin);
    if (fout)
        fclose(fout);
    if (fsig)
        fclose(fsig);
    if (cl)
        free(cl);

    status = t_free(global_eid);
    if (status != SGX_SUCCESS) {
        printf("t_get_sig failed\n");
        return 1;
    }

	/* after verification we destroy the enclave */
    sgx_destroy_enclave(global_eid);
	return 0;
}


