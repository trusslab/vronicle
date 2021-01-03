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
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fstream>
#include <bits/stdc++.h> 
#include <sys/stat.h> 
#include <sys/types.h>
#include <time.h>

#include <unistd.h>
#include <pwd.h>
#include <libgen.h>
// #include <pthread.h>

# define MAX_PATH FILENAME_MAX
# define SIZEOFHASH 256
# define SIZEOFSIGN 512
# define SIZEOFPUKEY 2048
# define TARGET_NUM_FILES_RECEIVED 3

#include <sgx_urts.h>

#include "TestApp.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h> /* gettimeofday() */
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <time.h> /* for time() and ctime() */

#include "metadata.h"

// For TCP module
#include <ctime>
#include <cerrno>
#include <cstring>
#include "tcp_module/TCPServer.h"
#include "tcp_module/TCPClient.h"

// For TCP module
TCPServer tcp_server;
TCPClient tcp_client;
int is_connected_to_next_module = 0;
pthread_t msg1[MAX_CLIENT];
int num_message = 0;
int time_send   = 1;
int num_of_times_received = 0;
int size_of_msg_buf = 100;
char* msg_buf;
pthread_t sender_msg;

// For Multi Filter_Bundle
int is_multi_bundles_enabled = -1;
int current_frame_id = -1;

// For incoming data
long size_of_ias_cert = 0;
char *ias_cert = NULL;
long md_json_len_i = 0;
char* md_json_i = NULL;
long raw_signature_length_i = 0;
char* raw_signature_i = NULL;
long raw_frame_buf_len_i = 0;
char* raw_frame_buf_i = NULL;
int is_finished_receiving = 0;

// For incoming data when being processed (Cache for incoming data)
long md_json_len = 0;
char* md_json = NULL;
long raw_signature_length = 0;
char* raw_signature = NULL;
long raw_frame_buf_len = 0;
char* raw_frame_buf = NULL;

// For outgoing data
unsigned char *der_cert;
size_t size_of_cert;

// For processing data
int frame_size_p;
pixel* processed_pixels_p;
size_t size_of_processed_img_signature_p;
unsigned char* processed_img_signature_p;
size_t out_md_json_len_p;
char* out_md_json_p;

// Cache for sending processed data
int frame_size;
pixel* processed_pixels;
size_t size_of_processed_img_signature;
unsigned char* processed_img_signature;
size_t out_md_json_len;
char* out_md_json;

using namespace std;

#include <chrono> 
using namespace std::chrono;

int is_previous_ias_verified = 0;

// For evaluation
ofstream eval_file;
ofstream alt_eval_file;

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

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
    // printf("token_path: %s\n", token_path);
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

    *actual_base64_len = (*bufferPtr).length;
  // printf("Inside Base64Encode we have data(length: %d){%s}\n", (*bufferPtr).length, (*bufferPtr).data);

    *base64Text=(*bufferPtr).data;
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

void sha256_hash_string (unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65])
{
    int i = 0;

    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
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

void print_public_key(EVP_PKEY* evp_pkey){
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
}

void print_private_key(EVP_PKEY* evp_pkey){
	// private key - string
	int len = i2d_PrivateKey(evp_pkey, NULL);
	printf("For privatekey, the size of buf is: %d\n", len);
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

unsigned char* public_key_to_str(EVP_PKEY* evp_pkey, int* len_of_publickey){
	// public key - string
    // Remember to deallocate the return after using
	int len = i2d_PublicKey(evp_pkey, NULL);
    *len_of_publickey = len + 1;
	unsigned char *buf = (unsigned char *) malloc (*len_of_publickey);
	unsigned char *tbuf = buf;
	i2d_PublicKey(evp_pkey, &tbuf);

	return buf;
}

void print_unsigned_chars(unsigned char* chars_to_print, int len){
	printf ("{\"(Outside enclave)unsigned_chars\":\"");
	int i;
	for (i = 0; i < len; i++) {
	    printf("%02x", (unsigned char) chars_to_print[i]);
	}
	printf("\"}\n");
}

int str_to_hash(char* str_for_hashing, int size_of_str_for_hashing, char* hash_out){
    // Return 0 on success, otherwise, return 1

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str_for_hashing, size_of_str_for_hashing);
    SHA256_Final(hash, &sha256);

    sha256_hash_string(hash, hash_out);
    return 0;
}

void close_app(int signum) {
	printf("There is a SIGINT error happened...exiting......(%d)\n", signum);
	tcp_server.closed();
	tcp_client.exit();
	exit(0);
}

void * received(void * m)
{
    // pthread_detach(pthread_self());
    
    // auto start = high_resolution_clock::now();

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
                // printf("no_more_frame received...finished processing...\n");
                free(reply_msg);
                is_finished_receiving = 1;
                return 0;
            } else {
                // printf("The file_name is not valid: %s\n", file_name);
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

int send_buffer(void* buffer, long buffer_lenth){
    // Return 0 on success, return 1 on failure

	// Send size of buffer
	// printf("Sending buffer size: %d\n", buffer_lenth);
	tcp_client.Send(&buffer_lenth, sizeof(long));
    // printf("Going to wait for receive...\n");
	string rec = tcp_client.receive_exact(REPLYMSGSIZE);
    // printf("Going to wait for receive(finished)...\n");
	if( rec != "" )
	{
		// cout << rec << endl;
	}
	// sleep(1);

    long remaining_size_of_buffer = buffer_lenth;
    void* temp_buffer = buffer;
    int is_finished = 0;

	while(1)
	{
        if(remaining_size_of_buffer > SIZEOFPACKAGE_HIGH){
		    tcp_client.Send(temp_buffer, SIZEOFPACKAGE_HIGH);
            remaining_size_of_buffer -= SIZEOFPACKAGE_HIGH;
            temp_buffer += SIZEOFPACKAGE_HIGH;
        } else {
		    tcp_client.Send(temp_buffer, remaining_size_of_buffer);
            is_finished = 1;
        }
        // printf("(inside)Going to wait for receive...just send buffer with size: %d\n", remaining_size_of_buffer);
		string rec = tcp_client.receive_exact(REPLYMSGSIZE);
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

void send_message(char* message, int msg_size){
    // printf("[filter_brightness:TestApp]: send_message: message: (%s), msg_size: (%d)\n", message, msg_size);
	tcp_client.Send(message, msg_size);
    // printf("[filter_brightness:TestApp]: (send_message)Going to wait for receive...\n");
	string rec = tcp_client.receive_exact(REPLYMSGSIZE);
    // printf("[filter_brightness:TestApp]: (send_message)Got rec: (%s)...\n", rec.c_str());
	if( rec != "" )
	{
		// cout << "send_message received: " << rec << endl;
	}
}

void send_frame_id(int frame_id){
    string frame_id_str = std::to_string(frame_id);
    string rec = "wrong";
    while(rec == "wrong"){
        tcp_client.Send(frame_id_str);
        // printf("[filter_brightness:TestApp]: (send_frame_id)Going to wait for receive...\n");
        rec = tcp_client.receive_exact(REPLYMSGSIZE);
        // printf("[filter_brightness:TestApp]: (send_frame_id)received: (%s)...\n", rec.c_str());
    }
    // printf("(send_frame_id)Going to wait for receive(finished)...\n");
	if( rec != "" )
	{
		// cout << "send_frame_id received: " << rec << endl;
	}
}

void* send_frame_info_to_next_enclave(void* m){

    if(is_multi_bundles_enabled){
        send_frame_id(current_frame_id);
    }

    // Send processed frame
    memset(msg_buf, 0, size_of_msg_buf);
    memcpy(msg_buf, "frame", 5);
    send_message(msg_buf, size_of_msg_buf);
    send_buffer(processed_pixels, frame_size);

    // End of send processed frame

    // Send processed filter singature

    // char* b64_sig = NULL;
    // size_t b64_sig_size = 0;
    // Base64Encode(processed_img_signature, size_of_processed_img_signature, &b64_sig, &b64_sig_size);
    memset(msg_buf, 0, size_of_msg_buf);
    memcpy(msg_buf, "sig", 3);
    send_message(msg_buf, size_of_msg_buf);
    // printf("signature going to be sent is: [%s]\n", b64_sig);
    send_buffer(processed_img_signature, size_of_processed_img_signature);
    // free(b64_sig);

    // End of send processed filter singature

    // Send metadata

    memset(msg_buf, 0, size_of_msg_buf);
    memcpy(msg_buf, "meta", 4);
    // printf("Sending metadata(%d): [%s]\n", out_md_json_len, out_md_json);
    send_message(msg_buf, size_of_msg_buf);
    send_buffer(out_md_json, out_md_json_len);

    // End of send metadata

    // Free Everything
    free(processed_pixels);
    free(processed_img_signature);
    free(out_md_json);
}

int verification_reply(
	struct sockaddr *saddr_p,
	socklen_t saddrlen,
	unsigned char recv_buf[],
	uint32_t recv_time[],
    char** argv)
{
    // Return 0 for finish successfully for a single frame; 1 for failure
	// fflush(stdout);
    int ret = 1;

    int path_len = 200;
    
    auto start = high_resolution_clock::now();

    // Parse metadata
    if (md_json[md_json_len - 1] == '\0') md_json_len--;
    if (md_json[md_json_len - 1] == '\0') md_json_len--;
    // printf("md_json(%ld) going to be used is: [%s]\n", md_json_len, md_json);
    metadata* md = json_2_metadata(md_json, md_json_len);
    if (!md) {
        printf("Failed to parse metadata\n");
        return 1;
    }

    // Set up some basic parameters
    frame_size_p = md->width * md->height * 3 * sizeof(unsigned char);

    // Parse Signature
    // printf("raw_signature(%d) going to be used is: [%s]\n", raw_signature_length, raw_signature);
    // size_t vid_sig_length = 0;
    // unsigned char* vid_sig = decode_signature(raw_signature, raw_signature_length, &vid_sig_length);
    size_t vid_sig_length = (size_t)raw_signature_length;
    unsigned char* vid_sig = (unsigned char*)raw_signature;

    // Parse Raw Image
    // printf("Image pixels: %d, %d, %ld should all be the same...\n", sizeof(pixel) * md->width * md->height, frame_size_p * sizeof(char), raw_frame_buf_len);
    pixel* image_pixels = (pixel*)malloc(frame_size_p * sizeof(char));
    if (!image_pixels) {
        printf("No memory left(image_pixels)\n");
        return 1;
    }

    // size_t vid_frame_length = 0;
    // unsigned char* vid_frame = decode_signature(raw_frame_buf, raw_frame_buf_len, &vid_frame_length);

    memcpy(image_pixels, raw_frame_buf, raw_frame_buf_len);
    // printf("Very first set of image pixel: %d, %d, %d\n", image_pixels[0].r, image_pixels[0].g, image_pixels[0].b);
    // int last_pixel_position = md->height * md->width - 1;
    // printf("Very last set of image pixel: %d, %d, %d\n", image_pixels[last_pixel_position].r, image_pixels[last_pixel_position].g, image_pixels[last_pixel_position].b);

    // Prepare processed Image
    processed_pixels_p = (pixel*)malloc(sizeof(pixel) * md->height * md->width);
    if (!processed_pixels_p) {
        printf("No memory left(processed_pixels_p)\n");
        return 1;
    }
    // Prepare for signature output and its hash
    size_of_processed_img_signature_p = 384;
    processed_img_signature_p = (unsigned char*)malloc(size_of_processed_img_signature_p);
    if (!processed_img_signature_p) {
        printf("No memory left\n");
        return 1;
    }

    // Prepare buffer for metadata output
    out_md_json_len_p = md_json_len + 48;
    out_md_json_p = (char*)malloc(out_md_json_len_p);
    memset(out_md_json_p, 0, out_md_json_len_p);
    if (!out_md_json_p) {
        printf("No memory left(out_md_json_p)\n");
        return 1;
    }

    auto end = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(end - start);
    eval_file << duration.count() << ", "; 

    // Going to get into enclave
    start = high_resolution_clock::now();

    sgx_status_t status = t_sgxver_call_apis(
        global_eid, &ret,
        image_pixels, sizeof(pixel) * md->width * md->height,
        md_json, md_json_len, 
        vid_sig, vid_sig_length, 
        processed_pixels_p,
        out_md_json_p, out_md_json_len_p, 
        processed_img_signature_p, size_of_processed_img_signature_p);

    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start);
    eval_file << duration.count() << ", "; 

    if (status != SGX_SUCCESS) {
        printf("Call to t_sgxver_call_apis has failed.\n");
        return 1;    //Test failed
    }

    if (ret != 0) {
        printf("Runtime result verification failed: %d\n", ret);
        return 1;
    }

    
    start = high_resolution_clock::now();

    // Make sure the previous sending is completed
    if(num_of_times_received > 1){
        pthread_join(sender_msg, NULL);
    }

    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start);
    eval_file << duration.count() << ", "; 
    
    start = high_resolution_clock::now();

    // Copy processed data to cache for sending
    frame_size = frame_size_p;
    processed_pixels = (pixel*)malloc(frame_size);
    memcpy(processed_pixels, processed_pixels_p, frame_size);

    size_of_processed_img_signature = size_of_processed_img_signature_p;
    processed_img_signature = (unsigned char*)malloc(size_of_processed_img_signature);
    memcpy(processed_img_signature, processed_img_signature_p, size_of_processed_img_signature);

    out_md_json_len = out_md_json_len_p;
    out_md_json = (char*)malloc(out_md_json_len);
    memcpy(out_md_json, out_md_json_p, out_md_json_len);

    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start);
    eval_file << duration.count() << ", "; 

    current_frame_id = md->frame_id;

    // Placeholder for sending frame info
    if(pthread_create(&sender_msg, NULL, send_frame_info_to_next_enclave, (void *)0) != 0){
        printf("pthread for sending created failed...quiting...\n");
        return 1;
    }

    // Free Everything (for video_provenance project)
    // printf("Going to free everything in verification_reply...\n");
    start = high_resolution_clock::now();

    if(raw_frame_buf){
        free(raw_frame_buf);
        raw_frame_buf = NULL;
    }
    if(image_pixels)
        free(image_pixels);
    if(processed_pixels_p)
        free(processed_pixels_p);
    if(raw_signature){
        free(raw_signature);
        raw_signature = NULL;
    }
    if(processed_img_signature_p)
        free(processed_img_signature_p);
    if(md)
        free_metadata(md);
    if(md_json){
        free(md_json);
        md_json = NULL;
    }
    if(out_md_json_p)
        free(out_md_json_p);
    // if(vid_sig)
    //     free(vid_sig);
    // if(vid_frame)
    //     free(vid_frame);

    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start);
    eval_file << duration.count() << endl;

	return 0;
}


void request_process_loop(char** argv)
{
	struct sockaddr src_addr;
	socklen_t src_addrlen = sizeof(src_addr);
	unsigned char buf[48];
	uint32_t recv_time[2];
	pid_t pid;

    
    // Register signal handlers
    std::signal(SIGINT, close_app);
	std::signal(SIGPIPE, sigpipe_handler);

    // First we receive IAS certificate and verify it
    
    auto start = high_resolution_clock::now();
    
    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(stop - start);

    pthread_t msg;
    // Receive ias cert
    // if( tcp_server.setup(atoi(argv[1]),opts) == 0) {
    //     printf("[filter_brightness:TestApp]: tcp_server setup completed...\n");
    //     tcp_server.accepted();
    //     cerr << "[filter_brightness:TestApp]: Accepted" << endl;

        
    // }
    // else
    //     cerr << "Errore apertura socket" << endl;

    start = high_resolution_clock::now();

    if(pthread_create(&msg, NULL, received, (void *)0) != 0){
        printf("[filter_brightness:TestApp]: pthread for receiving created failed...quiting...\n");
        return;
    }
    pthread_join(msg, NULL);

    stop = high_resolution_clock::now();
    duration = duration_cast<microseconds>(stop - start);
    alt_eval_file << duration.count() << ", ";

    // printf("[filter_brightness:TestApp]: ias cert received successfully...\n");

    start = high_resolution_clock::now();

    // Verify certificate in enclave
    int ret;
    sgx_status_t status_of_verification = t_verify_cert(global_eid, &ret, ias_cert, (size_t)size_of_ias_cert);

    stop = high_resolution_clock::now();
    duration = duration_cast<microseconds>(stop - start);
    alt_eval_file << duration.count() << ", ";

    if (status_of_verification != SGX_SUCCESS) {
        cout << "Failed to read IAS certificate file" << endl;
        free(ias_cert);
        return;
    }
    free(ias_cert);


    // printf("ias certificate verified successfully, going to start receving and processing frames...\n");
	// tcp_server.closed();
    
    start = high_resolution_clock::now();

    // Prepare buf for sending message
    msg_buf = (char*) malloc(size_of_msg_buf);

    // Prepare tcp client
    // printf("Setting up tcp client...\n");
    tcp_client.setup(argv[2], atoi(argv[3]));

    // printf("Going to first send der_cert through tcp client...\n");

    // Send certificate
    if(is_multi_bundles_enabled){
        // printf("[filter_brightness:TestApp]: multi_bundles_enabled detected, before sending cert, going to first send current_frame_id, which is: (%d)\n", current_frame_id);
        send_frame_id(current_frame_id);
        // printf("[filter_brightness:TestApp]: Pass frame_id verification for sending cert...\n");
    }
    memset(msg_buf, 0, size_of_msg_buf);
    memcpy(msg_buf, "cert", 4);
    // printf("[filter_brightness:TestApp]: Going to send cert file name...\n");
    send_message(msg_buf, size_of_msg_buf);
    // printf("[filter_brightness:TestApp]: Going to send cert data...\n");
    send_buffer(der_cert, size_of_cert);
    // printf("[filter_brightness:TestApp]: cert is sent for filter(%s)...\n", argv[1]);

    stop = high_resolution_clock::now();
    duration = duration_cast<microseconds>(stop - start);
    alt_eval_file << duration.count() << ", ";

    free(der_cert);

    // if( tcp_server.setup(atoi(argv[1]),opts) != 0){
    //     printf("Second time of setting up tcp server failed...\n");
    // }
    
    auto start_of_processing = high_resolution_clock::now();

    if(pthread_create(&msg, NULL, received, (void *)0) != 0){
        printf("pthread for receiving created failed...quiting...\n");
        return;
    }

    while(1) {
        // Receive frame info
        // tcp_server.accepted();
        // cerr << "Accepted" << endl;
        
        start = high_resolution_clock::now();
        
        pthread_join(msg, NULL);
        // printf("Now on frame: %d, with is_finished_receiving: %d\n", num_of_times_received, is_finished_receiving);
        if(is_finished_receiving || raw_frame_buf_i == NULL || md_json_i == NULL || raw_signature_i == NULL){
            // printf("No more frame to be processed...\n");
            // If we have already processed some frames, we need to join the sender thread to make sure the last frame info is sent correctly
            if(num_of_times_received > 0){
                pthread_join(sender_msg, NULL);
            }
            break;
        }

        stop = high_resolution_clock::now();
        duration = duration_cast<microseconds>(stop - start);
        eval_file << duration.count() << ", ";
        
        ++num_of_times_received;
        // printf("Now on frame: %d\n", num_of_times_received);
        
        start = high_resolution_clock::now();

        // Transfer incoming_data to incoming_data_when_being_processed
        raw_frame_buf_len = raw_frame_buf_len_i;
        raw_frame_buf = (char*) malloc((raw_frame_buf_len + 1) * sizeof(char));
        memcpy(raw_frame_buf, raw_frame_buf_i, raw_frame_buf_len + 1);
        free(raw_frame_buf_i);
        raw_frame_buf_len_i = 0;
        raw_frame_buf_i = NULL;

        md_json_len = md_json_len_i;
        md_json = (char*) malloc((md_json_len) * sizeof(char));
        memcpy(md_json, md_json_i, md_json_len);
        free(md_json_i);
        md_json_len_i = 0;
        md_json_i = NULL;

        raw_signature_length = raw_signature_length_i;
        raw_signature = (char*) malloc((raw_signature_length + 1) * sizeof(char));
        memcpy(raw_signature, raw_signature_i, raw_signature_length + 1);
        free(raw_signature_i);
        raw_signature_length_i = 0;
        raw_signature_i = NULL;

        stop = high_resolution_clock::now();
        duration = duration_cast<microseconds>(stop - start);
        eval_file << duration.count() << ", ";

        if(pthread_create(&msg, NULL, received, (void *)0) != 0){
            printf("pthread for receiving created failed...quiting...\n");
            return;
        }
        // printf("Going to process frame %d\n", num_of_times_received);
        // Note that all info about processed frame is sent in verification_reply
        // printf("Going to process and send frame: %d\n", num_of_times_received - 1);
        int process_status = verification_reply(&src_addr , src_addrlen, buf, recv_time, argv);
        if(process_status != 0){
            printf("frame process error...exiting...\n");
            break;
        }
        // md_json = NULL;
        // printf("frame %d processed successfully\n", num_of_times_received);
    }

    stop = high_resolution_clock::now();
    duration = duration_cast<microseconds>(stop - start_of_processing);
    alt_eval_file << duration.count();
    
    free(msg_buf);
}

int start_enclave(int argc, char *argv[])
{
	// printf("enclave initialization started\n");

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

    // fprintf(stderr, "[Evaluation]: Filter blur enclave started initialization at: %ld\n", high_resolution_clock::now());

    if(argc < 5){
        printf("Usage: ./TestApp [incoming_port] [outgoing_ip_addr] [outgoing_port] [is_multi_bundles_enabled]\n");
        return 1;
    }
    
    is_multi_bundles_enabled = atoi(argv[4]);
    
    // First set up incoming server
    vector<int> opts = { SO_REUSEPORT, SO_REUSEADDR };
    if(!tcp_server.setup(atoi(argv[1]),opts) == 0) {
        // printf("[filter_brightness:TestApp]: tcp_server setup completed with port: (%s)...\n", argv[1]);
        cerr << "Errore apertura socket" << endl;
        exit(1);
        // cerr << "[filter_brightness:TestApp]: Accepted" << endl;
    }
        

    // Open file to store evaluation results
    mkdir("../../../evaluation/eval_result", 0777);
    eval_file.open("../../../evaluation/eval_result/eval_filter_brightness.csv");
    if (!eval_file.is_open()) {
        printf("Could not open eval file.\n");
        return 1;
    }

    alt_eval_file.open("../../../evaluation/eval_result/eval_filter_brightness_one_time.csv");
    if (!alt_eval_file.is_open()) {
        printf("Could not open alt_eval_file file.\n");
        return 1;
    }
    
	/* initialize and start the enclave in here */
    auto start = high_resolution_clock::now();
	start_enclave(argc, argv);
    auto end = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(end - start);
    alt_eval_file << duration.count() << ", "; 

    size_of_cert = 4 * 4096;
    der_cert = (unsigned char *)malloc(size_of_cert);

    start = high_resolution_clock::now();

    t_create_key_and_x509(global_eid, der_cert, size_of_cert, &size_of_cert, sizeof(size_t));
    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start);
    alt_eval_file << duration.count() << ", ";

    // fprintf(stderr, "[Evaluation]: Filter blur enclave finished initialization at: %ld\n", high_resolution_clock::now());
    
    // Accept client
    tcp_server.accepted();

	/* create the server waiting for the verification request from the client */
	int s;
	signal(SIGCHLD,wait_wrapper);
	request_process_loop(argv);

    t_free(global_eid);

    // Close eval file
    eval_file.close();
    alt_eval_file.close();

	/* after verification we destroy the enclave */
    sgx_destroy_enclave(global_eid);
	return 0;
}


