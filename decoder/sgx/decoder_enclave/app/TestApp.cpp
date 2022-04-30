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
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>

#include <unistd.h>
#include <pwd.h>
#include <libgen.h>
// #include <pthread.h>

# define MAX_PATH FILENAME_MAX
# define SIZEOFHASH 256
# define SIZEOFSIGN 512
# define SIZEOFPUKEY 2048
# define TARGET_NUM_TIMES_RECEIVED 4
# define TARGET_NUM_FILES_RECEIVED 1
// #define SIZEOFPACKAGE 40000

#include <sgx_urts.h>

#include "TestApp.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h> /* gettimeofday() */
#include <sys/wait.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <time.h> /* for time() and ctime() */

#include "metadata.h"

#include "basetype.h"

#ifdef ENABLE_DCAP
#define SGX_AESM_ADDR "SGX_AESM_ADDR"
#include "sgx_dcap_ql_wrapper.h"
#include "sgx_quote_3.h"
#include "sgx_report.h"
#include "sgx_pce.h"
#endif

// For TCP module
#include <ctime>
#include <cerrno>
#include <cstring>
#include "tcp_module/TCPServer.h"
#include "tcp_module/TCPClient.h"

// For TCP module
TCPServer tcp_server;   // For direct use (Deprecated)
TCPServer tcp_server_for_decoder;
TCPClient tcp_client_rec;    // For scheduler use
TCPClient **tcp_clients;
pthread_t msg1[MAX_CLIENT];
int num_message = 0;
int time_send   = 1;
int num_of_times_received = 0;
int size_of_msg_buf_for_rec = REPLYMSGSIZE;
char* msg_buf_for_rec;

// For TCP connection with encoder
TCPClient tcp_client_with_encoder;

// For multi bundle-filter enclaves
int num_of_pair_of_output = -1;
int current_sending_target_id = 0;
vector<pair<string, int>*> output_filters_info;

// For data
string input_vendor_pub_path = "../../../keys/camera_vendor_pub";
long contentSize = 0;
u8* contentBuffer = NULL;
long camera_cert_len = 0;
char* camera_cert = NULL;
long vid_sig_buf_length = 0;
char* vid_sig_buf = NULL;
long md_json_len = 0;
char* md_json = NULL;

// For SafetyNet data
char *original_md_json;
long original_md_json_len;

// For audio data
size_t size_of_audio_meta = 0;
char* audio_meta = NULL;
size_t size_of_audio_data = 0;
char* audio_data = NULL;
size_t size_of_audio_sig = 0;
char* audio_sig = NULL;

// For outgoing data
unsigned char *der_cert;
size_t size_of_cert;

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

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("[decoder:TestApp]: Info: %s\n", sgx_errlist[idx].sug);
            printf("[decoder:TestApp]: Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("[decoder:TestApp]: Error: Unexpected error occurred [0x%x].\n", ret);
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
        printf("[decoder:TestApp]: Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }
    // printf("[decoder:TestApp]: token_path: %s\n", token_path);
    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("[decoder:TestApp]: Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }

#ifdef ENABLE_DCAP
    /* Step 1.5: set enclave load policy to persistent if in-proc mode */
    quote3_error_t qe3_ret = SGX_QL_SUCCESS;
    bool is_out_of_proc = false;
    char *out_of_proc = getenv(SGX_AESM_ADDR);
    if(out_of_proc)
        is_out_of_proc = true;
    if(!is_out_of_proc)
    {
        // Following functions are valid in Linux in-proc mode only.
        printf("sgx_qe_set_enclave_load_policy is valid in in-proc mode only and it is optional: the default enclave load policy is persistent: \n");
        printf("set the enclave load policy as persistent:");
        qe3_ret = sgx_qe_set_enclave_load_policy(SGX_QL_PERSISTENT);
        if(SGX_QL_SUCCESS != qe3_ret) {
            printf("Error in set enclave load policy: 0x%04x\n", qe3_ret);
            if (fp != NULL) fclose(fp);
            return -1;
        }
        printf("succeed!\n");

        // Try to load PCE and QE3 from Ubuntu-like OS system path
        if (SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_PCE_PATH, "/usr/lib/x86_64-linux-gnu/libsgx_pce.signed.so") ||
                SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_QE3_PATH, "/usr/lib/x86_64-linux-gnu/libsgx_qe3.signed.so")) {

            // Try to load PCE and QE3 from RHEL-like OS system path
            if (SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_PCE_PATH, "/usr/lib64/libsgx_pce.signed.so") ||
                SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_QE3_PATH, "/usr/lib64/libsgx_qe3.signed.so")) {
                printf("Error in set PCE/QE3 directory.\n");
                if (fp != NULL) fclose(fp);
                return -1;
            }
        }

        qe3_ret = sgx_ql_set_path(SGX_QL_QPL_PATH, "/usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1");
        if (SGX_QL_SUCCESS != qe3_ret) {
            qe3_ret = sgx_ql_set_path(SGX_QL_QPL_PATH, "/usr/lib64/libdcap_quoteprov.so.1");
            if(SGX_QL_SUCCESS != qe3_ret) {
                printf("Error in set QPL directory.\n");
                if (fp != NULL) fclose(fp);
                return -1;
            }
        }
    }
#endif

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
        printf("[decoder:TestApp]: Warning: Failed to save launch token to \"%s\".\n", token_path);
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

void log_ntp_event(char *msg)
{
	puts(msg);
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

    *actual_base64_len = (*bufferPtr).length - 1;
    (*bufferPtr).data[*actual_base64_len] = '\0';
  // printf("Inside Base64Encode we have data(length: %d){%s}\n", (*bufferPtr).length, (*bufferPtr).data);

    *base64Text=(*bufferPtr).data;
}

unsigned char* read_signature(const char* sign_file_name, size_t* signatureLength){
    // Return signature on success, otherwise, return NULL
    // Need to free the return after finishing using
    FILE* signature_file = fopen(sign_file_name, "r");
    if(signature_file == NULL){
        printf("[decoder:TestApp]: Failed to read video signature from file: %s\n", sign_file_name);
        return NULL;
    }

    fseek(signature_file, 0, SEEK_END);
    long length = ftell(signature_file);
    fseek(signature_file, 0, SEEK_SET);
    char* base64signature = (char*)malloc(length + 1);
    int success_read_count = fread(base64signature, 1, length, signature_file);
    base64signature[success_read_count] = '\0';
    fclose(signature_file);
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

void print_public_key(EVP_PKEY* evp_pkey){
	// public key - string
	int len = i2d_PublicKey(evp_pkey, NULL);
	printf("[decoder:TestApp]: For publickey, the size of buf is: %d\n", len);
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
}

void print_private_key(EVP_PKEY* evp_pkey){
	// private key - string
	int len = i2d_PrivateKey(evp_pkey, NULL);
	printf("[decoder:TestApp]: For privatekey, the size of buf is: %d\n", len);
	unsigned char *buf = (unsigned char *) malloc (len + 1);
	unsigned char *tbuf = buf;
	i2d_PrivateKey(evp_pkey, &tbuf);

	// print private key
	printf ("{\"private\":\"");
	int i;
	for (i = 0; i < len; i++) {
	    printf("%02x", (unsigned char) buf[i]);
	}
	printf("\"}\n");

	free(buf);
}

void print_unsigned_chars(unsigned char* chars_to_print, int len){
	printf ("{\"(Outside enclave)unsigned_chars\":\"");
	int i;
	for (i = 0; i < len; i++) {
	    printf("%02x", (unsigned char) chars_to_print[i]);
	}
	printf("\"}\n");
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
    memset(str_to_return, 0, *str_len);
    fread(str_to_return, 1, *str_len - 1, file);
    str_to_return[*str_len - 1] = '\0';

    fclose(file);
    return str_to_return;
}

void createContentBuffer(char* contentPath, u8** pContentBuffer, size_t* pContentSize) {
    struct stat sb;
    if (stat(contentPath, &sb) == -1) {
      perror("[decoder:TestApp]: stat failed");
      exit(1);
    }

    *pContentSize = sb.st_size;
    *pContentBuffer = (u8*)malloc(*pContentSize);
}

void loadContent(char* contentPath, u8* contentBuffer, long contentSize) {
    FILE *input = fopen(contentPath, "r");
    if (input == NULL) {
      perror("[decoder:TestApp]: open failed");
      exit(1);
    }

    off_t offset = 0;
    while (offset < contentSize) {
      offset += fread(contentBuffer + offset, sizeof(u8), contentSize - offset, input);
    }

    fclose(input);
}

void close_app(int signum) {
	printf("[decoder:TestApp]: There is a SIGINT error happened...exiting......(%d)\n", signum);
	tcp_server.closed();
    tcp_client_rec.exit();
    for(int i = 0; i < num_of_pair_of_output; ++i){
	    tcp_clients[i]->exit();
    }
    tcp_client_with_encoder.exit();
	exit(0);
}

void * received(void * m)
{
    // Assume there is a connection for tcp_server
    // Will use the latest connected one

	int current_mode = 0;	// 0 means awaiting reading file's nickname; 1 means awaiting file size; 2 means awaiting file content
    int current_file_indicator = -1;   // 0 means video; 1 means metadata; 2 means signature; 3 means certificate 
    void* current_writing_location = NULL;
    long* current_writing_size = NULL;
	long remaining_file_size = 0;

	int num_of_files_received = 0;

    // Set uniformed msg to skip sleeping
    int size_of_reply = 100;
    char* reply_msg = (char*) malloc(size_of_reply);

	while(num_of_files_received != TARGET_NUM_FILES_RECEIVED)
	{
        if(current_mode == 0){
            string file_name = tcp_server.receive_name();
            // printf("[decoder:TestApp]: Got new file_name: %s\n", file_name.c_str());
            if(file_name == "vid"){
                current_file_indicator = 0;
                current_writing_size = &contentSize;
            } else if (file_name == "meta"){
                current_file_indicator = 1;
                current_writing_size = &md_json_len;
            } else if (file_name == "sig"){
                current_file_indicator = 2;
                current_writing_size = &vid_sig_buf_length;
            } else if (file_name == "cert"){
                current_file_indicator = 3;
                current_writing_size = &camera_cert_len;
            } else {
                printf("[decoder:TestApp]: The file_name is not valid: %s\n", file_name);
                free(reply_msg);
                return 0;
            }
            current_mode = 1;
        } else if (current_mode == 1){
            long size_of_data = tcp_server.receive_size_of_data();
            *current_writing_size = size_of_data;
            remaining_file_size = size_of_data;
            // printf("File size got: %ld, which should be equal to: %ld\n", remaining_file_size, *current_writing_size);
            // printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!current file indicator is: %d\n", current_file_indicator);
            switch(current_file_indicator){
                case 0:
                    contentBuffer = (u8*) malloc(*current_writing_size * sizeof(u8));
                    current_writing_location = contentBuffer;
                    break;
                case 1:
                    md_json = (char*) malloc(*current_writing_size * sizeof(char));
                    current_writing_location = md_json;
                    break;
                case 2:
                    vid_sig_buf = (char*) malloc((*current_writing_size + 1) * sizeof(char));
                    current_writing_location = vid_sig_buf;
                    break;
                case 3:
                    camera_cert = (char*) malloc(*current_writing_size * sizeof(char));
                    current_writing_location = camera_cert;
                    break;
                default:
                    printf("[decoder:TestApp]: No file indicator is set, aborted...\n");
                    free(reply_msg);
                    return 0;
            }
            current_mode = 2;
        } else {
            char* data_received;
            if(remaining_file_size > SIZEOFPACKAGE){
                // printf("!!!!!!!!!!!!!!!!!!!Going to write data to current file location: %d\n", current_file_indicator);
                data_received = tcp_server.receive_exact(SIZEOFPACKAGE);
                memcpy(current_writing_location, data_received, SIZEOFPACKAGE);
                current_writing_location += SIZEOFPACKAGE;
                remaining_file_size -= SIZEOFPACKAGE;
            } else {
                // printf("???????????????????Last write to the current file location: %d\n", current_file_indicator);
                data_received = tcp_server.receive_exact(remaining_file_size);
                memcpy(current_writing_location, data_received, remaining_file_size);
                remaining_file_size = 0;
                current_mode = 0;
                ++num_of_files_received;
            }
		}
        memset(reply_msg, 0, size_of_reply);
        memcpy(reply_msg, "ready", 5);
        tcp_server.send_to_last_connected_client(reply_msg, size_of_reply);
	}
    free(reply_msg);
	return 0;
}

void try_receive_something(void* data_for_storage, long data_size){
    long remaining_data_size = data_size;
    char* temp_data_for_storage = (char*)data_for_storage;
    char* data_received;
    while(remaining_data_size > 0){
        // printf("Receiving data with remaining_data_size: %ld\n", remaining_data_size);
        if(remaining_data_size > SIZEOFPACKAGE){
            data_received = tcp_client_rec.receive_exact(SIZEOFPACKAGE);
            memcpy(temp_data_for_storage, data_received, SIZEOFPACKAGE);
            temp_data_for_storage += SIZEOFPACKAGE;
            remaining_data_size -= SIZEOFPACKAGE;
        } else {
            data_received = tcp_client_rec.receive_exact(remaining_data_size);
            memcpy(temp_data_for_storage, data_received, remaining_data_size);
            remaining_data_size = 0;
        }
        free(data_received);
        // printf("Received with data and going to receive again after replying...\n");
        memset(msg_buf_for_rec, 0, size_of_msg_buf_for_rec);
        memcpy(msg_buf_for_rec, "ready", 5);
        tcp_client_rec.Send(msg_buf_for_rec, size_of_msg_buf_for_rec);
    }
    return;
}

int send_buffer(void* buffer, long buffer_length, TCPClient* target_tcp_client) {
    // Return 0 on success, return 1 on failure

    // Send size of buffer
	target_tcp_client->Send(&buffer_length, sizeof(long));
	string rec = target_tcp_client->receive_exact(REPLYMSGSIZE);
	if( rec != "" )
	{
		// cout << rec << endl;
	}

    long remaining_size_of_buffer = buffer_length;
    void* temp_buffer = buffer;
    int is_finished = 0;

	while(1)
	{
        if(remaining_size_of_buffer > SIZEOFPACKAGE_HIGH){
		    target_tcp_client->Send(temp_buffer, SIZEOFPACKAGE_HIGH);
            remaining_size_of_buffer -= SIZEOFPACKAGE_HIGH;
            temp_buffer += SIZEOFPACKAGE_HIGH;
        } else {
		    target_tcp_client->Send(temp_buffer, remaining_size_of_buffer);
            is_finished = 1;
        }
        // printf("(inside)Going to wait for receive...just send buffer with size: %d\n", remaining_size_of_buffer);
		string rec = target_tcp_client->receive_exact(REPLYMSGSIZE);
        // printf("(inside)Going to wait for receive(finished)...\n");
		if( rec != "" )
		{
			// cout << "send_buffer received: " << rec << "where remaining size is: " << remaining_size_of_buffer << endl;
		}
        // if(rec == "received from received 1"){
        //     printf("send_buffer: Buffer should be sent completed: %d\n", is_finished);
        // }
        if(is_finished){
            // printf("send_buffer: This buffer should be all sent: [%s]\n", rec.c_str());
            break;
        }
	}
    
    return 0;
}

int send_buffer_to_next_enclave(void* buffer, long buffer_lenth, int sending_target_id){

	return send_buffer(buffer, buffer_lenth, tcp_clients[sending_target_id]);
}

void send_message(char* message, int msg_size, TCPClient *target_tcp_client) {
    target_tcp_client->Send(message, msg_size);
    // printf("(send_message)Going to wait for receive...\n");
	string rec = target_tcp_client->receive_exact(REPLYMSGSIZE);
    // printf("(send_message)Going to wait for receive(finished)...\n");
	if( rec != "" )
	{
		// cout << "send_message received: " << rec << endl;
	}
}

void send_message_to_next_enclave(char* message, int msg_size, int sending_target_id){
	send_message(message, msg_size, tcp_clients[sending_target_id]);
}

int check_and_change_to_main_scheduler(){
    // Return 0 on success, otherwise return 1

    // printf("[decoder:TestApp]: In check_and_change_to_main_scheduler, going to receive...\n");
    string scheduler_mode = tcp_client_rec.receive_name();
    // printf("[decoder:TestApp]: In check_and_change_to_main_scheduler, received: {%s}\n", scheduler_mode.c_str());
    int mode_of_scheduler = 0;  // 0 means main; 1 means helper
    // printf("[decoder:TestApp]: In check_and_change_to_main_scheduler, is it main: {%d}\n", scheduler_mode == "main");
    if(scheduler_mode == "main"){
        mode_of_scheduler = 0;
    } else if (scheduler_mode == "helper"){
        mode_of_scheduler = 1;
    } else {
        return 1;
    }

    // printf("[decoder:TestApp]: In check_and_change_to_main_scheduler, going to reply...mode_of_scheduler = [%d]\n", mode_of_scheduler);
    char* reply_to_scheduler = (char*)malloc(REPLYMSGSIZE);
    memset(reply_to_scheduler, 0, REPLYMSGSIZE);
    memcpy(reply_to_scheduler, "ready", 5);
    tcp_client_rec.Send(reply_to_scheduler, REPLYMSGSIZE);
    // printf("[decoder:TestApp]: In check_and_change_to_main_scheduler, reply finished...\n");

    // Change the scheduler connected accordingly
    if(mode_of_scheduler == 1){
        // Get ip and port of main scheduler from current helper scheduler
        string ip_addr = tcp_client_rec.receive_name();
        memset(reply_to_scheduler, 0, REPLYMSGSIZE);
        memcpy(reply_to_scheduler, "ready", 5);
        tcp_client_rec.Send(reply_to_scheduler, REPLYMSGSIZE);
        string port = tcp_client_rec.receive_name();
        memset(reply_to_scheduler, 0, REPLYMSGSIZE);
        memcpy(reply_to_scheduler, "ready", 5);
        tcp_client_rec.Send(reply_to_scheduler, REPLYMSGSIZE);

        // Reconnect to the actual main scheduler
        tcp_client_rec.exit();
        int time_to_try = 10;
        int is_successfully_connected = 0;

        while (time_to_try && !is_successfully_connected) {
            bool result_of_connection_setup = tcp_client_rec.setup(ip_addr.c_str(), atoi(port.c_str()));
            if(!result_of_connection_setup){
                tcp_client_rec = TCPClient();
                --time_to_try;
                usleep(50000);
            } else {
                is_successfully_connected = 1;
            }
        }

        if(!is_successfully_connected){
            printf("[decoder:TestApp]: Connection cannot be established with main scheduler...\n");
            return 1;
        }
    }

    free(reply_to_scheduler);

    return 0;
}

int set_num_of_pair_of_output(){
    // Return 0 on success, otherwise return 1

    long new_num = tcp_client_rec.receive_size_of_data();

    char* reply_to_scheduler = (char*)malloc(REPLYMSGSIZE);
    memset(reply_to_scheduler, 0, REPLYMSGSIZE);
    memcpy(reply_to_scheduler, "ready", 5);
    tcp_client_rec.Send(reply_to_scheduler, REPLYMSGSIZE);

    if(new_num < 1){
        printf("[decoder:TestApp]: num_of_pair_of_output with main scheduler invalid: [%ld]...\n", new_num);
        return 1;
    }

    num_of_pair_of_output = (int)new_num;

    return 0;
}

int setup_tcp_clients_auto(){
    // Return 0 on success, otherwise return 1
    tcp_clients = (TCPClient**) malloc(sizeof(TCPClient*) * num_of_pair_of_output);
    char* reply_to_scheduler = (char*)malloc(REPLYMSGSIZE);
    string ip_addr, port;

    // Prepare sending cert to all bundle-filter enclaves
    char* msg_buf = (char*) malloc(SIZEOFPACKAGEFORNAME);
    memset(msg_buf, 0, SIZEOFPACKAGEFORNAME);
    memcpy(msg_buf, "cert", 4);

    for(int i = 0; i < num_of_pair_of_output; ++i){
        tcp_clients[i] = new TCPClient();
        // printf("[decoder:TestApp]: Setting up tcp client with args...\n");

        ip_addr = tcp_client_rec.receive_name();
        memset(reply_to_scheduler, 0, REPLYMSGSIZE);
        memcpy(reply_to_scheduler, "ready", 5);
        tcp_client_rec.Send(reply_to_scheduler, REPLYMSGSIZE);
        port = tcp_client_rec.receive_name();
        memset(reply_to_scheduler, 0, REPLYMSGSIZE);
        memcpy(reply_to_scheduler, "ready", 5);
        tcp_client_rec.Send(reply_to_scheduler, REPLYMSGSIZE);

        // printf("[decoder:TestApp]: In setup_tcp_clients_auto, going to connect to next filter_enclave with ip: {%s} and port: {%s}\n", ip_addr.c_str(), port.c_str());

        bool result_of_connection_setup = tcp_clients[i]->setup(ip_addr.c_str(), atoi(port.c_str()));
        if(!result_of_connection_setup){
            free(reply_to_scheduler);
            return 1;
        }
        // Send certificate
        send_message_to_next_enclave(msg_buf, SIZEOFPACKAGEFORNAME, i);
        // printf("[decoder:TestApp]: Going to send_buffer for cert...\n");
        send_buffer_to_next_enclave(der_cert, size_of_cert, i);
        // printf("[decoder:TestApp]: Both send_message and send_buffer completed...\n");
    }
    free(reply_to_scheduler);
    return 0;
}

int setup_connection_with_encoder_using_scheduler() {
    // Return 0 on success, otherwise return 1

    char* reply_to_scheduler = (char*)malloc(REPLYMSGSIZE);
    memset(reply_to_scheduler, 0, REPLYMSGSIZE);
    memcpy(reply_to_scheduler, "ready", 5);

    string encoder_ip_addr = tcp_client_rec.receive_name();
    tcp_client_rec.Send(reply_to_scheduler, REPLYMSGSIZE);

    int encoder_port = (long)tcp_client_rec.receive_size_of_data();
    tcp_client_rec.Send(reply_to_scheduler, REPLYMSGSIZE);

    // printf("[decoder:TestApp]: Going to connect to encoder at ip: %s with port: %d\n", encoder_ip_addr.c_str(), encoder_port);

    int time_to_try = 10;
    int is_successfully_connected = 0;

    while (time_to_try && !is_successfully_connected) {
        bool result_of_connection_setup = tcp_client_with_encoder.setup(encoder_ip_addr.c_str(), encoder_port);
        if(!result_of_connection_setup){
            tcp_client_with_encoder = TCPClient();
            --time_to_try;
            usleep(50000);
        } else {
            is_successfully_connected = 1;
        }
    }

    // printf("[decoder:TestApp]: is connection to encoder successful?: %d.\n", is_successfully_connected);

    if (!is_successfully_connected) {
        printf("[decoder:TestApp]: Connection to encoder is unsuccessful at ip: %s with port: %d\n", encoder_ip_addr.c_str(), encoder_port);
        free(reply_to_scheduler);
        return 1;
    }

    free(reply_to_scheduler);
    return 0;
}

void * get_and_send_audio_related_data_and_metadata_to_encoder(void* m) {
    // Will get audio related data from enclave and send to encoder
    // Return 0 on success, otherwise return 1

    int *result_to_return = (int*)malloc(sizeof(int));
    *result_to_return = 0;

    int ret = 1;
    sgx_status_t status = t_sgxver_get_audio_related_data_sizes(global_eid, &ret, &size_of_audio_meta, &size_of_audio_data, &size_of_audio_sig, sizeof(size_t));

    if (ret != 0) {
        printf("[decoder:TestApp]: Failed to get audio related data size with error code: [%d]\n", ret);
        *result_to_return = 1;
        return result_to_return;
    }

    // Pre allocate all audio data
    audio_meta = (char*) malloc(size_of_audio_meta);
    audio_data = (char*) malloc(size_of_audio_data);
    audio_sig = (char*) malloc(size_of_audio_sig);

    status = t_sgxver_get_audio_related_data(global_eid, &ret, audio_meta, size_of_audio_meta, audio_data, size_of_audio_data, audio_sig, size_of_audio_sig);

    if (ret != 0) {
        printf("[decoder:TestApp]: Failed to get audio related data with error code: [%d]\n", ret);
        *result_to_return = 1;
        return result_to_return;
    }

    int size_of_msg_buf = SIZEOFPACKAGEFORNAME;
    char* msg_buf = (char*) malloc(size_of_msg_buf);

    // Send certificate
    memset(msg_buf, 0, size_of_msg_buf);
    memcpy(msg_buf, "cert", 4);

    // printf("[decoder:TestApp]: Going to send {%s} to encoder...\n", msg_buf);
    send_message(msg_buf, size_of_msg_buf, &tcp_client_with_encoder);
    // printf("[decoder:TestApp]: Message is sent...\n");
    send_buffer(der_cert, size_of_cert, &tcp_client_with_encoder);
    // Free der_cert last as we need it for passing to next filter(s)

    // Send audio_data
    memset(msg_buf, 0, size_of_msg_buf);
    memcpy(msg_buf, "audio_data", 10);

    send_message(msg_buf, size_of_msg_buf, &tcp_client_with_encoder);
    send_buffer(audio_data, size_of_audio_data, &tcp_client_with_encoder);
    free(audio_data);

    // Send audio_sig
    memset(msg_buf, 0, size_of_msg_buf);
    memcpy(msg_buf, "audio_sig", 9);

    send_message(msg_buf, size_of_msg_buf, &tcp_client_with_encoder);
    send_buffer(audio_sig, size_of_audio_sig, &tcp_client_with_encoder);
    free(audio_sig);

    // Send audio_meta
    memset(msg_buf, 0, size_of_msg_buf);
    memcpy(msg_buf, "audio_meta", 10);

    send_message(msg_buf, size_of_msg_buf, &tcp_client_with_encoder);
    send_buffer(audio_meta, size_of_audio_meta, &tcp_client_with_encoder);
    free(audio_meta);

    // Send original metadata
    memset(msg_buf, 0, size_of_msg_buf);
    memcpy(msg_buf, "metadata", 8);

    send_message(msg_buf, size_of_msg_buf, &tcp_client_with_encoder);
    send_buffer(original_md_json, original_md_json_len, &tcp_client_with_encoder);

    free(msg_buf);
    
    return result_to_return;
}

void do_decoding(
    int argc,
    char** argv)
{
    // printf("[decoder:TestApp]: incoming port: %s, outgoing address: %s, outgoing port: %s\n", argv[1], argv[2], argv[3]);

    // Register signal handlers
    std::signal(SIGINT, close_app);
	std::signal(SIGPIPE, sigpipe_handler);

    // Init evaluation
    auto start = high_resolution_clock::now();
    auto end = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(end - start);

    // Init pub info
    long vendor_pub_len = 0;
    char* vendor_pub;

    // declaring argument of time() 

    // ctime() used to give the present time 

    // Prepare buf for sending message
    msg_buf_for_rec = (char*) malloc(size_of_msg_buf_for_rec);

    // Prepare tcp client
    // printf("[decoder:TestApp]: Setting up tcp client...\n");
    int time_to_try = 10;
    int is_successfully_connected = 0;

    while (time_to_try && !is_successfully_connected) {
        bool result_of_connection_setup = tcp_client_rec.setup("127.0.0.1", atoi(argv[1]));
        if(!result_of_connection_setup){
            tcp_client_rec = TCPClient();
            --time_to_try;
            usleep(50000);
        } else {
            is_successfully_connected = 1;
        }
    }

    if(!is_successfully_connected){
        printf("[decoder:TestApp]: Connection cannot be established...\n");
        close_app(0);
    }

    // Determine if the current scheduler is in main mode or in helper mode
    // If in helper mode, be ready to change tcp_client for connecting the main scheduler
    // printf("Going to do check_and_change_to_main_scheduler...\n");
    check_and_change_to_main_scheduler();
    // printf("check_and_change_to_main_scheduler finished...\n");

    // First receive vendor pub name
    // printf("[decoder:TestApp]: Going to receive vendor pub name...\n");
    input_vendor_pub_path.clear();
    input_vendor_pub_path = "../../../keys/";
    // printf("[decoder:TestApp]: Going to receive vendor pub name...\n");
    input_vendor_pub_path += tcp_client_rec.receive_name();

    time_t my_time = time(NULL); 
    // printf("[decoder:TestApp]: Receiving started at: %s", ctime(&my_time));
    
    // printf("[decoder:TestApp]: Receive vendor pub name and final path is: %s...\n", input_vendor_pub_path.c_str());
    memset(msg_buf_for_rec, 0, size_of_msg_buf_for_rec);
    memcpy(msg_buf_for_rec, "ready", 5);
    tcp_client_rec.Send(msg_buf_for_rec, REPLYMSGSIZE);
    // printf("[decoder:TestApp]: reply is sent...\n");
    // printf("[decoder:TestApp]: The input_vendor_pub_path is: %s\n", input_vendor_pub_path.c_str());

    start = high_resolution_clock::now();

    // Read camera vendor public key
    vendor_pub = read_file_as_str(input_vendor_pub_path.c_str(), &vendor_pub_len);
    if (!vendor_pub) {
        printf("[decoder:TestApp]: Failed to read camera vendor public key\n");
        close_app(0);
    }

    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start);
    alt_eval_file << duration.count() << ", ";

    // Start receiving other data
    while(num_of_times_received != TARGET_NUM_TIMES_RECEIVED){
        // printf("[decoder:TestApp]: Start receiving data...\n");
        string name_of_current_file = tcp_client_rec.receive_name();
        // printf("[decoder:TestApp]: Got new data: {%s}\n", name_of_current_file.c_str());
        void* current_writting_location;
        long current_writting_location_size;
        // printf("[decoder:TestApp]: Got new file name: %s\n", name_of_current_file.c_str());
        memset(msg_buf_for_rec, 0, size_of_msg_buf_for_rec);
        memcpy(msg_buf_for_rec, "ready", 5);
        // printf("[decoder:TestApp]: Going to send reply message...\n");
        tcp_client_rec.Send(msg_buf_for_rec, size_of_msg_buf_for_rec);
        // printf("[decoder:TestApp]: Reply to scheduler is sent...\n");
        if(name_of_current_file == "cert"){

            camera_cert_len = tcp_client_rec.receive_size_of_data() + 1;

            camera_cert = (char*) malloc(camera_cert_len);
            memset(camera_cert, 0, camera_cert_len);
            camera_cert[camera_cert_len - 1] = '\0';
            current_writting_location_size = camera_cert_len - 1;
            current_writting_location = camera_cert;

        } else if (name_of_current_file == "vid"){

            contentSize = tcp_client_rec.receive_size_of_data();
            
            contentBuffer = (unsigned char*) malloc(contentSize);
            current_writting_location_size = contentSize;
            current_writting_location = contentBuffer;

        } else if (name_of_current_file == "meta"){
            // printf("[decoder:TestApp]: Going to receive size of data...\n");
            md_json_len = tcp_client_rec.receive_size_of_data();
            
            // printf("[decoder:TestApp]: size of data received(%ld)...\n", md_json_len);
            
            md_json = (char*) malloc(md_json_len);
            current_writting_location_size = md_json_len;
            current_writting_location = md_json;

        } else if (name_of_current_file == "sig"){
            
            vid_sig_buf_length = tcp_client_rec.receive_size_of_data();
            
            vid_sig_buf = (char*) malloc(vid_sig_buf_length);
            current_writting_location_size = vid_sig_buf_length;
            current_writting_location = vid_sig_buf;

        } else {
            printf("[decoder:TestApp]: Received invalid file name: [%s]\n", name_of_current_file);
            close_app(0);
        }

        memset(msg_buf_for_rec, 0, size_of_msg_buf_for_rec);
        memcpy(msg_buf_for_rec, "ready", 5);
        tcp_client_rec.Send(msg_buf_for_rec, size_of_msg_buf_for_rec);

        // printf("[decoder:TestApp]: Going to try receive data for size: %ld\n", current_writting_location_size);
        try_receive_something(current_writting_location, current_writting_location_size);
        ++num_of_times_received;
    }

    // Free
    free(msg_buf_for_rec);

    start = high_resolution_clock::now();

    // Parse metadata
    // printf("[decoder:TestApp]: md_json(%ld): {%s}\n", md_json_len, md_json);
    if (md_json[md_json_len - 1] == '\0') md_json_len--;
    if (md_json[md_json_len - 1] == '\0') md_json_len--;
    metadata* md = json_2_metadata(md_json, md_json_len);
    if (!md) {
        printf("[decoder:TestApp]: Failed to parse metadata\n");
        close_app(0);
    }

    // Extra parsing for Safetynet
    metadata *original_md = md;
    original_md_json = md_json;
    original_md_json_len = md_json_len;
    if (original_md->is_safetynet_presented) {
        md = json_2_metadata((char*)md_json, md_json_len);
        for (int i = 0; i < md->num_of_safetynet_jws; ++i) {
            free(md->safetynet_jws[i]);
        }
        free(md->safetynet_jws);
        md->num_of_safetynet_jws = 0;
        md->is_safetynet_presented = 0;
        md_json = metadata_2_json_without_frame_id(md);
        md_json_len = strlen((char*)md_json);
    }

    // Decode signature
    size_t vid_sig_length = 0;
    unsigned char* vid_sig = decode_signature(vid_sig_buf, vid_sig_buf_length, &vid_sig_length);

    // Set up parameters for the case where output is multi
    int max_frames = 999; // Assume there are at most 999 frames
    int max_frame_digits = num_digits(max_frames);
    size_t sig_size = 384; // TODO: Remove hardcoded sig size
    size_t md_size = md_json_len + 16 + 46 + 1;

    // Parameters to be acquired from enclave
    // u32* frame_width = (u32*)malloc(sizeof(u32)); 
    // u32* frame_height = (u32*)malloc(sizeof(u32));
    // int* num_of_frames = (int*)malloc(sizeof(int));
    int num_of_frames = md->total_frames;
    int frame_size = sizeof(u8) * md->width * md->height * 3;
    size_t total_size_of_raw_rgb_buffer = frame_size * md->total_frames;
    u8* output_rgb_buffer = (u8*)malloc(total_size_of_raw_rgb_buffer + 1);
    if (!output_rgb_buffer) {
        printf("[decoder:TestApp]: No memory left (RGB)\n");
        close_app(0);
    }
    size_t total_size_of_sig_buffer = sig_size * md->total_frames;
    u8* output_sig_buffer = (u8*)malloc(total_size_of_sig_buffer + 1);
    if (!output_sig_buffer) {
        printf("[decoder:TestApp]: No memory left (SIG)\n");
        close_app(0);
    }
    size_t total_size_of_md_buffer = md_size * md->total_frames;
    u8* output_md_buffer = (u8*)malloc(total_size_of_md_buffer + 1);
    if (!output_md_buffer) {
        printf("[decoder:TestApp]: No memory left (MD)\n");
        close_app(0);
    }

    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start);
    alt_eval_file << duration.count() << ", ";

    start = high_resolution_clock::now();

    int ret = 0;
    // printf("[decoder:TestApp]: Going to call t_sgxver_prepare_decoder with size_of_contentBuffer: %d...\n", contentSize);
    sgx_status_t status = t_sgxver_prepare_decoder(global_eid, &ret,
                                                  contentBuffer, contentSize, 
                                                  original_md_json, original_md_json_len,
                                                  vendor_pub, vendor_pub_len,
                                                  camera_cert, camera_cert_len,
                                                  vid_sig, vid_sig_length, md->is_safetynet_presented);
    // printf("[decoder: TestApp]: t_sgxver_prepare_decoder: [%d]\n", ret);

    // status = t_sgxver_decode_content(global_eid, &ret,
    //                                               contentBuffer, contentSize, 
    //                                               md_json, md_json_len,
    //                                               vendor_pub, vendor_pub_len,
    //                                               camera_cert, camera_cert_len,
    //                                               vid_sig, vid_sig_length,
    //                                               frame_width, frame_height, &num_of_frames, 
    //                                               output_rgb_buffer, output_sig_buffer, output_md_buffer);

    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start);
    alt_eval_file << duration.count() << ", ";

    auto start_s = high_resolution_clock::now();

    if (ret != 1) {
        printf("[decoder:TestApp]: Failed to prepare decoding video with error code: [%d]\n", ret);
        close_app(0);
    }

    // printf("[decoder:TestApp]: After decoding, we know the frame width: %d, frame height: %d, and there are a total of %d frames.\n", 
    //     *frame_width, *frame_height, *num_of_frames);

    // Clean signle frame info each time before getting something new...

    u8* temp_output_rgb_buffer = output_rgb_buffer;
    u8* temp_output_sig_buffer = output_sig_buffer;
    u8* temp_output_md_buffer = output_md_buffer;

    // Prepare buf for sending message
    int size_of_msg_buf = SIZEOFPACKAGEFORNAME;
    char* msg_buf = (char*) malloc(size_of_msg_buf);

    // Prepare sending cert to all bundle-filter enclaves
    memset(msg_buf, 0, size_of_msg_buf);
    memcpy(msg_buf, "cert", 4);

    // printf("Going to prepare all tcp clients...\n");

    // Prepare all tcp clients
    if(set_num_of_pair_of_output() != 0){
        printf("[decoder:TestApp]: Failed to do set_num_of_pair_of_output\n");
        close_app(0);
    }
    // fprintf(stderr, "[Evaluation]: Decoder is going to connect to next filter(s) at: %ld\n", high_resolution_clock::now());
    // printf("[decoder:TestApp]: After receiving, we have num_of_pair_of_output: [%d]\n", num_of_pair_of_output);
    if(setup_tcp_clients_auto() != 0){
        printf("[decoder:TestApp]: Failed to do setup_tcp_clients_auto\n");
        close_app(0);
    }

    // Set up connection with encoder
    if (setup_connection_with_encoder_using_scheduler() != 0) {
        printf("[decoder:TestApp]: Failed to do setup_connection_with_encoder_using_scheduler\n");
        close_app(0);
    }

    // Get audio related data from enclave and send to encoder
    pthread_t thread_4_encoder_sender;

    // printf("[decoder:TestApp]: Going to create thread for get_and_send_audio_related_data_and_metadata_to_encoder...\n");
    if(pthread_create(&thread_4_encoder_sender, NULL, get_and_send_audio_related_data_and_metadata_to_encoder, (void *)0) != 0){
        printf("[decoder:TestApp]: pthread for get_and_send_audio_related_data_and_metadata_to_encoder created failed...quiting...\n");
        close_app(0);
    }

    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start_s);
    alt_eval_file << duration.count() << ", ";

    // Init for single frame info
    u8* single_frame_buf = (u8*)malloc(frame_size);
    u8* single_frame_md_json = (u8*)malloc(md_size);
    u8* single_frame_sig = (u8*)malloc(sig_size);

    // Start sending frames 
    for(int i = 0; i < num_of_frames; ++i){

        // printf("[decoder:TestApp]: Sending frame: %d\n", i);

        // Clean signle frame info each time before getting something new...
        memset(single_frame_buf, 0, frame_size);
        memset(single_frame_md_json, 0, md_size);
        memset(single_frame_sig, 0, sig_size);

        // printf("[decoder:TestApp]: Going to decode frame: %d\n", i);

        sgx_status_t status = t_sgxver_decode_single_frame(global_eid, &ret,
                                                        single_frame_buf, frame_size,
                                                        single_frame_md_json, md_size,
                                                        single_frame_sig, sig_size);

        if(ret == -1 && i + 1 < num_of_frames){
            printf("[decoder:TestApp]: Finished decoding video on incorrect frame: [%d], where total frame is: [%d]...\n", i, num_of_frames);
            close_app(0);
        } else if(ret != 0 && ret != -1){
            printf("[decoder:TestApp]: Failed to decode video on frame: [%d]\n", i);
            close_app(0);
        }

        printf("[decoder:TestApp]: Decoded frame: %d\n", i);

        string frame_num = to_string(i);
        
        // Send frame
        // char* b64_frame = NULL;
        // size_t b64_frame_size = 0;
        // Base64Encode(temp_output_rgb_buffer, frame_size, &b64_frame, &b64_frame_size);
        memset(msg_buf, 0, size_of_msg_buf);
        memcpy(msg_buf, "frame", 5);
        // printf("Going to send frame %d's name...\n", i);

        start = high_resolution_clock::now();

        send_message_to_next_enclave(msg_buf, size_of_msg_buf, current_sending_target_id);
        // printf("Very first set of image pixel: %d, %d, %d\n", temp_output_rgb_buffer[0], temp_output_rgb_buffer[1], temp_output_rgb_buffer[2]);
        // int last_pixel_position = 1280 * 720 * 3 - 3;
        // printf("Very last set of image pixel: %d, %d, %d\n", temp_output_rgb_buffer[last_pixel_position], temp_output_rgb_buffer[last_pixel_position + 1], temp_output_rgb_buffer[last_pixel_position + 2]);
        // printf("Going to send frame %d's info...\n", i);
        // send_buffer(temp_output_rgb_buffer, frame_size, current_sending_target_id);
        send_buffer_to_next_enclave(single_frame_buf, frame_size, current_sending_target_id);

        end = high_resolution_clock::now();
        duration = duration_cast<microseconds>(end - start);
        eval_file << duration.count() << ", ";

        // free(b64_frame);
        // temp_output_rgb_buffer += frame_size;

        // Send signature
        // char* b64_sig = NULL;
        // size_t b64_sig_size = 0;
        // Base64Encode(temp_output_sig_buffer, sig_size, &b64_sig, &b64_sig_size);
        memset(msg_buf, 0, size_of_msg_buf);
        memcpy(msg_buf, "sig", 3);
        // printf("Going to send frame %d's sig's name...\n", i);

        start = high_resolution_clock::now();

        send_message_to_next_enclave(msg_buf, size_of_msg_buf, current_sending_target_id);
        // printf("signature(%d) going to be sent is: [%s]\n", b64_sig_size, b64_sig);
        // printf("Going to send frame %d's sig's info...\n", i);
        // send_buffer(temp_output_sig_buffer, sig_size, current_sending_target_id);
        send_buffer_to_next_enclave(single_frame_sig, sig_size, current_sending_target_id);

        end = high_resolution_clock::now();
        duration = duration_cast<microseconds>(end - start);
        eval_file << duration.count() << ", ";
        
        //free(b64_sig);
        // temp_output_sig_buffer += sig_size;

        // Send metadata
        memset(msg_buf, 0, size_of_msg_buf);
        memcpy(msg_buf, "meta", 4);
        // printf("Going to send frame %d's md's name...\n", i);
        // int md_size_for_sending = md_size + 1;
        // char* md_for_print = (char*) malloc(md_size_for_sending);
        // memcpy(md_for_print, temp_output_md_buffer, md_size_for_sending);
        // md_for_print[md_size_for_sending - 1] = '\0';
        // printf("metadata(%d) going to be sent is: [%s]\n", md_size_for_sending, md_for_print);
        // printf("Going to send frame %d's md's info...\n", i);

        start = high_resolution_clock::now();

        send_message_to_next_enclave(msg_buf, size_of_msg_buf, current_sending_target_id);
        // send_buffer(temp_output_md_buffer, md_size, current_sending_target_id);
        // printf("[decoder:TestApp]: Going to send md_json(%d): {%s}\n", md_size, single_frame_md_json);
        send_buffer_to_next_enclave(single_frame_md_json, md_size, current_sending_target_id);

        end = high_resolution_clock::now();
        duration = duration_cast<microseconds>(end - start);
        eval_file << duration.count() << "\n";

        //free(md_for_print);
        // temp_output_md_buffer += md_size;

        // Switch to next sending target
        current_sending_target_id = (current_sending_target_id + 1) % num_of_pair_of_output;
    }

    memset(msg_buf, 0, size_of_msg_buf);
    memcpy(msg_buf, "no_more_frame", 13);

    for(int i = 0; i < num_of_pair_of_output; ++i){
        // Send no_more_frame msg
        send_message_to_next_enclave(msg_buf, size_of_msg_buf, i);
    }

    free(msg_buf);

    // After all frames are sent, let's finish sending audio_data
    void *result_of_send_to_encoder;
    pthread_join(thread_4_encoder_sender, &result_of_send_to_encoder);
    if(*((int*)result_of_send_to_encoder) != 0){
        printf("[decoder:TestApp]: No correct audio data is sent...\n");
        close_app(0);
    }
    free(result_of_send_to_encoder);

    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start_s);
    alt_eval_file << duration.count();

    // Free everything
    // printf("[decoder:TestApp]: Going to call free at the end of decoder...\n");
    // if(frame_width)
    //     free(frame_width);
    // if(frame_height)
    //     free(frame_height);
    // if(num_of_frames)
    //     free(num_of_frames);
    if(original_md->is_safetynet_presented){
        free_metadata(original_md);
        free(original_md_json);
    }
    if(contentBuffer)
        free(contentBuffer);
    if(output_rgb_buffer)
        free(output_rgb_buffer);
    if(output_sig_buffer)
        free(output_sig_buffer);
    if(output_md_buffer)
        free(output_md_buffer);
    if(vendor_pub)
        free(vendor_pub);
    if(camera_cert)
        free(camera_cert);
    if(vid_sig_buf)
        free(vid_sig_buf);
    if(vid_sig)
        free(vid_sig);
    if(md_json)
        free(md_json);
    if(md)
        free_metadata(md);
    
    for(int i = 0; i < num_of_pair_of_output; ++i){
        tcp_clients[i]->exit();
        delete tcp_clients[i];
    }
    free(tcp_clients);

    // if(!ret){
    //     system("cd ../../../filter_blur/sgx/filter_enclave/run_enclave/; ./client 127.0.0.1 60");
    // }

    return;
}

void request_process_loop(int fd, int argc, char** argv)
{
	struct sockaddr src_addr;
	socklen_t src_addrlen = sizeof(src_addr);
	unsigned char buf[200];
	uint32_t recv_time[2];
	pid_t pid;

    // while (recvfrom(fd, buf,
    //         200, 0,
    //         &src_addr,
    //         &src_addrlen)
    //     < 200 );  /* invalid request */

    // gettime64(recv_time);

    // auto start = high_resolution_clock::now();
    // auto stop = high_resolution_clock::now();
    // auto duration = duration_cast<microseconds>(stop - start);
    // cout << "decoding with parameters: " << (char*)buf << " takes time: " << duration.count() << endl; 
    // cout << "decoding takes time: " << duration.count() << endl; 
}

void sgx_server(int argc, char** argv)
{
	int s;
	struct sockaddr_in sinaddr;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == -1) {
		perror("[decoder:TestApp]: Can not create socket.");
		die(NULL);
	}

	memset(&sinaddr, 0, sizeof(sinaddr));
	sinaddr.sin_family = AF_INET;
	sinaddr.sin_port = htons(124);
	sinaddr.sin_addr.s_addr = INADDR_ANY;

	if (0 != bind(s, (struct sockaddr *)&sinaddr, sizeof(sinaddr))) {
		perror("Bind error");
		die(NULL);
	}

	// log_ntp_event(	"[decoder:TestApp]: \n========================================\n"
	// 		"= Server started, waiting for requests =\n"
	// 		"========================================\n");

	request_process_loop(s, argc, argv);
	close(s);
}

int start_enclave(int argc, char *argv[])
{
	// printf("[decoder:TestApp]: enclave initialization started\n");
    
        /* Changing dir to where the executable is.*/
    /*
        char absolutePath[MAX_PATH];
        char *ptr = NULL;
    
        ptr = realpath(dirname(argv[0]), absolutePath);
    
        if (ptr == NULL || chdir(absolutePath) != 0)
        	return 1;
    
        evp_pkey = EVP_PKEY_new();
        FILE *f = fopen(argv[1], "rb");
        if(f == NULL){
            cout << "File is not read successfully..." << endl;
            return -1;
        }
        evp_pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
        if(evp_pkey == NULL){
            cout << "Key is not read successfully..." << endl;
            return -2;
        }
    */

    /* Initialize the enclave */
    if (initialize_enclave() < 0)
        return 1; 
}

void wait_wrapper(int s)
{

	wait(&s);
}

/* Application entry */
int main(int argc, char *argv[], char **env)
{

    if(argc < 2){
        printf("[decoder:TestApp]: argc: %d\n", argc);
        // printf("%s, %s, %s, %s...\n", argv[0], argv[1], argv[2], argv[3]);
        printf("[decoder:TestApp]: Usage: ./TestApp [port_to_report]\n");
        return 1;
    }

    // num_of_pair_of_output += (argc - 4) / 2;

    // Open file to store evaluation results
    mkdir("../../../evaluation/eval_result", 0777);
    eval_file.open("../../../evaluation/eval_result/eval_decoder.csv");
    if (!eval_file.is_open()) {
        printf("[decoder:TestApp]: Could not open eval file.\n");
        return 1;
    }

    alt_eval_file.open("../../../evaluation/eval_result/eval_decoder_one_time.csv");
    if (!alt_eval_file.is_open()) {
        printf("[decoder:TestApp]: Could not open alt_eval_file file.\n");
        return 1;
    }

    // For time of initializing sgx enclave and doing RA
    auto start = high_resolution_clock::now();

	/* initialize and start the enclave in here */
	start_enclave(argc, argv);

    auto end = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(end - start);
    alt_eval_file << duration.count() << ", "; 

    size_of_cert = 4 * 4096;
    der_cert = (unsigned char *)malloc(size_of_cert);

    start = high_resolution_clock::now();

    // print_error_message((sgx_status_t)16385);
    t_create_key_and_x509(global_eid, der_cert, size_of_cert, &size_of_cert, sizeof(size_t));
    
    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start);
    alt_eval_file << duration.count() << ", ";

	/* create the server waiting for the verification request from the client */
	int s;
	signal(SIGCHLD,wait_wrapper);
    do_decoding(argc, argv);

    free(der_cert);
    t_free(global_eid);

     // Close eval file
    eval_file.close();
    alt_eval_file.close();

	/* after verification we destroy the enclave */
    sgx_destroy_enclave(global_eid);
	return 0;
}
