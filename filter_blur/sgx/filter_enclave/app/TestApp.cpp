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
pthread_t msg1[MAX_CLIENT];
int num_message = 0;
int time_send   = 1;
int num_of_times_received = 0;
int size_of_msg_buf = 100;
char* msg_buf;

// For incoming data
long size_of_ias_cert = 0;
char *ias_cert = NULL;
long md_json_len = 0;
char* md_json = NULL;
long raw_signature_length = 0;
char* raw_signature = NULL;
long raw_frame_buf_len = 0;
char* raw_frame_buf = NULL;

// For outgoing data
unsigned char *der_cert;
size_t size_of_cert;

using namespace std;

#include <chrono> 
using namespace std::chrono;

ofstream eval_file;
int is_previous_ias_verified = 0;

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

int read_raw_file_b(const char* file_name, int frame_size, pixel** image_pixels){
    // Return 0 on success, return 1 on failure
    // cout << "Going to read raw file: " << file_name << endl;

    FILE* input_raw_file = fopen(file_name, "rb");
    if(input_raw_file == NULL){
        return 1;
    }
    fseek(input_raw_file, 0, SEEK_SET);

    *image_pixels = (pixel*)malloc(frame_size);
    memset(*image_pixels, 0, frame_size);

    if(!fread(*image_pixels, frame_size, 1, input_raw_file)){
        return 1;
    }

    return 0;
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

int save_processed_frame_b(pixel* processed_pixels, int frame_size, char* path_to_save){
    // Return 0 on success; otherwise, return 1
    // First create the folder if not created

    // To-Do: delete the following two lines after making path_to_save flexible
    char* dirname = "../../../video_data/processed_raw";
    mkdir(dirname, 0777);
    
    // Save data
    printf("Going to save %s...\n", path_to_save);
    FILE* output_file = fopen(path_to_save, "wb");
    if(output_file == NULL){
        printf("path_to_save: %s failed to save...\n", path_to_save);
        return 1;
    }
    
    fwrite(processed_pixels, frame_size, 1, output_file);

    fclose(output_file);

    return 0;
}

int save_char_array_to_file(char* str_to_save, char* frame_id){
    // Return 0 on success; otherwise, return 1
    char* dirname = "../video_data/processed_raw_str_enclave";
    mkdir(dirname, 0777);

    char processed_raw_file_name[50];
    snprintf(processed_raw_file_name, 50, "../video_data/processed_raw_str_enclave/processed_raw_%s", frame_id);

    FILE* output_file = fopen(processed_raw_file_name, "w+");
    if(output_file == NULL){
        return 1;
    }

    int results = fputs(str_to_save, output_file);
    if (results == EOF) {
        return 1;
    }

    fclose(output_file);

    return 0;
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

int read_file_as_hash(char* file_path, char* hash_out){
    // Return 0 on success, otherwise, return 1
    FILE *file = fopen(file_path, "rb");
    if(file == NULL){
        return 1;
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    const int bufSize = 32768;
    unsigned char* buffer = (unsigned char*)malloc(bufSize);
    int bytesRead = 0;
    if(!buffer) return ENOMEM;
    while((bytesRead = fread(buffer, 1, bufSize, file)))
    {
        SHA256_Update(&sha256, buffer, bytesRead);
    }
    SHA256_Final(hash, &sha256);

    sha256_hash_string(hash, hash_out);
    fclose(file);
    free(buffer);
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

int verify_hash(char* hash_of_file, unsigned char* signature, size_t size_of_siganture, EVP_PKEY* public_key){
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

    printf("hash_of_file to be verified: %s\n", hash_of_file);

	ret = EVP_VerifyUpdate(mdctx, (void*)hash_of_file, 65);
	if(ret != 1){
		printf("EVP_VerifyUpdate error. \n");
        exit(1);
	}

	ret = EVP_VerifyFinal(mdctx, signature, size_of_siganture, public_key);
	printf("EVP_VerifyFinal result: %d\n", ret);

	// Below part is for freeing data
	// For freeing evp_md_ctx
	EVP_MD_CTX_free(mdctx);

    return ret;
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

int save_signature(unsigned char* signature, int len_of_sign, char* frame_id){
    // Return 0 on success, otherwise, return 1

    char* base64_signature;

    // printf("The base64_signature before assigning signauture is (length: %d): %s\n", strlen(base64_signature), base64_signature);
    int len_of_base64encoded_str;
    Base64Encode(signature, len_of_sign, &base64_signature, (size_t*)&len_of_base64encoded_str);
    // base64_signature = base64_encode(signature, (size_t)len_of_sign, (size_t*)&len_of_base64encoded_str);

    // printf("The base64_signature after assigning signauture of length %d is (length: %d): %s\n", strlen(base64_signature), len_of_sign, base64_signature);
    // printf("The base64_signature after assigning signauture of length %d is (length: %d): %s\n", len_of_base64encoded_str, len_of_sign, base64_signature);

    char* dirname = "../../../video_data/processed_raw_sign";
    mkdir(dirname, 0777);

    char processed_raw_sign_file_name[200];
    snprintf(processed_raw_sign_file_name, 200, "../../../video_data/processed_raw_sign/processed_raw_sign_%s", frame_id);

    ofstream signature_file;
    signature_file.open(processed_raw_sign_file_name);
    if (!signature_file.is_open()){
        return 1;
    }
    signature_file.write(base64_signature, len_of_base64encoded_str);
    signature_file.close();

    free(base64_signature);

    return 0;
}

void close_app(int signum) {
	printf("There is a SIGINT error happened...exiting......(%d)\n", signum);
	tcp_server.closed();
	tcp_client.exit();
	exit(0);
}

void * received_cert(void * m)
{
    // pthread_detach(pthread_self());
	usleep(100);
		
	// std::signal(SIGPIPE, sigpipe_handler);
	vector<descript_socket*> desc;

	int current_mode = 0;	// 0 means awaiting reading file's nickname; 1 means awaiting file size; 2 means awaiting file content
	long remaining_file_size = 0;
    void* current_writing_location = NULL;

    // Set uniformed msg to skip sleeping
    int size_of_reply = 100;
    char* reply_msg = (char*) malloc(size_of_reply);

	while(1)
	{
        
		desc = tcp_server.getMessage();
		for(unsigned int i = 0; i < desc.size(); i++) {
			if( desc[i]->message != NULL )
			{ 
				// if(!desc[i]->enable_message_runtime) 
				// {
				// 	desc[i]->enable_message_runtime = true;
			    //             if( pthread_create(&msg1[num_message], NULL, send_client, (void *) desc[i]) == 0) {
				// 		cerr << "ATTIVA THREAD INVIO MESSAGGI" << endl;
				// 	}
				// 	num_message++;
				// 	// start message background thread
				// }

				// printf("current_mode is: %d, with remaining size: %ld\n", current_mode, remaining_file_size);

				if(current_mode == 0){
                    string file_name = desc[i]->message;
                    // printf("Got new file_name: %s\n", file_name.c_str());
                    if (file_name != "cert"){
                        printf("The file_name is not valid: %s\n", file_name);
                        free(reply_msg);
                        return 0;
                    }
					current_mode = 1;
				} else if (current_mode == 1){
					memcpy(&size_of_ias_cert, desc[i]->message, 8);
					memcpy(&remaining_file_size, desc[i]->message, 8);
					// printf("File size got: %ld\n", remaining_file_size);
                    ias_cert = (char*) malloc(size_of_ias_cert * sizeof(char));
                    current_writing_location = ias_cert;
					current_mode = 2;
				} else {
					// printf("Remaining message size: %ld, where we recevied packet with size: %d, and it is going to be written in file_indicator: %d\n", remaining_file_size, desc[i]->size_of_packet, current_file_indicator);
					// printf("Message with size: %d, with content: %s to be written...\n", current_message_size, desc[i]->message.c_str());
					if(remaining_file_size > desc[i]->size_of_packet){
                        memcpy(current_writing_location, desc[i]->message, desc[i]->size_of_packet);
                        current_writing_location += desc[i]->size_of_packet;
						remaining_file_size -= desc[i]->size_of_packet;
					} else {
                        memcpy(current_writing_location, desc[i]->message, remaining_file_size);
						remaining_file_size = 0;
						current_mode = 0;
				        tcp_server.clean(i);
                        memset(reply_msg, 0, size_of_reply);
                        memcpy(reply_msg, "received from received_cert 1", 29);
                        tcp_server.Send(reply_msg, size_of_reply, desc[i]->id);
                        free(reply_msg);
						return 0;
					}
				}
                memset(reply_msg, 0, size_of_reply);
                memcpy(reply_msg, "received from received_cert 0", 29);
                tcp_server.Send(reply_msg, size_of_reply, desc[i]->id);
				tcp_server.clean(i);
			}
		}
		usleep(100);
	}
    free(reply_msg);
	return 0;
}

void * received(void * m)
{
    // pthread_detach(pthread_self());
	usleep(500);
	// std::signal(SIGPIPE, sigpipe_handler);
	vector<descript_socket*> desc;

	int current_mode = 0;	// 0 means awaiting reading file's nickname; 1 means awaiting file size; 2 means awaiting file content
    int current_file_indicator = -1;   // 0 means frame; 1 means metadata; 2 means signature
    void* current_writing_location = NULL;
    long* current_writing_size = NULL;
	long remaining_file_size = 0;

	int num_of_files_received = 0;

    // Set uniformed msg to skip sleeping
    int size_of_reply = 100;
    char* reply_msg = (char*) malloc(size_of_reply);

    // For debug
    int one_round_of_not_hit = 0;
    int last_round_of_size = 0;

	while(1)
	{
        // printf("In received...\n");
		desc = tcp_server.getMessage();
        // printf("Got message..\n");
		for(unsigned int i = 0; i < desc.size(); i++) {
            // if(!one_round_of_not_hit){
            //     printf("(Abnormal)Checking i: %d out of %d, where i's packet_size is: %d\n", i, desc.size(), desc[i]->size_of_packet);
            //     if(i + 1 == desc.size()){
            //         if(last_round_of_size == desc.size()){
            //             one_round_of_not_hit = 1;
            //         } else {
            //             last_round_of_size = desc.size();
            //         }
            //     }
            // }
			if( desc[i]->message != NULL )
			{ 
                one_round_of_not_hit = 0;
                last_round_of_size = 0;
				// printf("current_mode is: %d, with remaining size: %ld\n", current_mode, remaining_file_size);

				if(current_mode == 0){

                    string file_name = desc[i]->message;
                    // printf("Got new file_name: %s\n", file_name.c_str());
                    if(file_name == "frame"){
                        current_file_indicator = 0;
                        current_writing_size = &raw_frame_buf_len;
                    } else if (file_name == "meta"){
                        current_file_indicator = 1;
                        current_writing_size = &md_json_len;
                    } else if (file_name == "sig"){
                        current_file_indicator = 2;
                        current_writing_size = &raw_signature_length;
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
                    memset(reply_msg, 0, size_of_reply);
                    memcpy(reply_msg, "received from received 0", 24);
                    tcp_server.Send(reply_msg, size_of_reply, desc[i]->id);
				} else if (current_mode == 1){
                    memcpy(current_writing_size, desc[i]->message, 8);
					memcpy(&remaining_file_size, desc[i]->message, 8);
					// printf("File size got: %ld, which should be equal to: %ld\n", remaining_file_size, *current_writing_size);
                    // printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!current file indicator is: %d\n", current_file_indicator);
                    switch(current_file_indicator){
                        case 0:
                            raw_frame_buf = (char*) malloc((*current_writing_size + 1) * sizeof(char));
                            current_writing_location = raw_frame_buf;
                            break;
                        case 1:
                            md_json = (char*) malloc(*current_writing_size * sizeof(char));
                            current_writing_location = md_json;
                            break;
                        case 2:
                            raw_signature = (char*) malloc((*current_writing_size + 1) * sizeof(char));
                            current_writing_location = raw_signature;
                            break;
                        default:
                            printf("No file indicator is set, aborted...\n");
                            free(reply_msg);
                            return 0;
                    }
					current_mode = 2;
                    memset(reply_msg, 0, size_of_reply);
                    memcpy(reply_msg, "received from received 2", 24);
                    tcp_server.Send(reply_msg, size_of_reply, desc[i]->id);
				} else {
					// printf("Remaining message size: %ld, where we recevied packet with size: %d, and it is going to be written in file_indicator: %d\n", remaining_file_size, desc[i]->size_of_packet, current_file_indicator);
					// printf("Message with size: %d, with content: %s to be written...\n", current_message_size, desc[i]->message.c_str());
                    // printf("Received data with size: %d (%d), where remaining data is: %d\n", SIZEOFPACKAGE_HIGH, desc[i]->size_of_packet, remaining_file_size);
                    // if(desc[i]->size_of_packet == 0){
                    //     printf("The problematic msg is: [%s]\n", desc[i]->message);
				    //     tcp_server.clean(i);
		            //     usleep(50);
                    //     continue;
                    // }
					if(remaining_file_size > desc[i]->size_of_packet){
                        // printf("!!!!!!!!!!!!!!!!!!!Going to write data to current file location: %d\n", current_file_indicator);
                        memcpy(current_writing_location, desc[i]->message, desc[i]->size_of_packet);
                        current_writing_location += desc[i]->size_of_packet;
						remaining_file_size -= desc[i]->size_of_packet;
                        memset(reply_msg, 0, size_of_reply);
                        memcpy(reply_msg, "received from received 3", 24);
                        tcp_server.Send(reply_msg, size_of_reply, desc[i]->id);
					} else {
                        // printf("!!!!!!!!!!!!!!!!!!!Last write to the current file location: %d\n", current_file_indicator);
                        memcpy(current_writing_location, desc[i]->message, remaining_file_size);
						remaining_file_size = 0;
						current_mode = 0;
						++num_of_files_received;
                        // printf("num_of_files_received: %d\n", num_of_files_received);
						if(num_of_files_received == TARGET_NUM_FILES_RECEIVED){
				            tcp_server.clean(i);
                            memset(reply_msg, 0, size_of_reply);
                            memcpy(reply_msg, "received from received 1", 24);
                            tcp_server.Send(reply_msg, size_of_reply, desc[i]->id);
                            // printf("One time finished...going to call free for reply_msg and return...\n");
                            free(reply_msg);
							return 0;
						}
                        memset(reply_msg, 0, size_of_reply);
                        memcpy(reply_msg, "received from received 4", 24);
                        tcp_server.Send(reply_msg, size_of_reply, desc[i]->id);
					}
				}
				tcp_server.clean(i);
			}
		}
		usleep(500);
	}
    free(reply_msg);
	return 0;
}

int send_buffer(void* buffer, long buffer_lenth){
    // Return 0 on success, return 1 on failure
	
    usleep(100);

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
	usleep(100);

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
		// sleep(1);
		usleep(100);
	}

    return 0;
}

void send_message(char* message, int msg_size){
    usleep(50);
	tcp_client.Send(message, msg_size);
    // printf("(send_message)Going to wait for receive...\n");
	string rec = tcp_client.receive_exact(REPLYMSGSIZE);
    // printf("(send_message)Going to wait for receive(finished)...\n");
	if( rec != "" )
	{
		// cout << "send_message received: " << rec << endl;
	}
	// sleep(1);
	usleep(50);
}

int verification_reply(
	int socket_fd,
	struct sockaddr *saddr_p,
	socklen_t saddrlen,
	unsigned char recv_buf[],
	uint32_t recv_time[],
    char** argv)
{
    // Return 0 for finish successfully for a single frame; 1 for failure
	// fflush(stdout);
    int ret = 1;
    char* raw_file_sig_path  = argv[2];
    char* raw_file_path      = argv[3];
    char* raw_md_path        = argv[4];
    char* output_md_path     = argv[5];

    int path_len = 200;

    // // Read metadata
    // long md_json_len = 0;
    // char input_md_path[path_len];
    // snprintf(input_md_path, path_len, "%s%s.json", raw_md_path, (char*)recv_buf);
    // printf("Going to read meatadata: %s\n", input_md_path);
    // char* md_json = read_file_as_str(input_md_path, &md_json_len);
    // if (!md_json) {
    //     printf("Failed to read metadata\n");
    //     return 1;
    // }

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
    int frame_size = md->width * md->height * 3 * sizeof(unsigned char);

    // Parse Signature
    // printf("raw_signature going to be used is: [%s]\n", raw_signature);
    auto start = high_resolution_clock::now();
    size_t vid_sig_length = 0;
    unsigned char* vid_sig = decode_signature(raw_signature, raw_signature_length, &vid_sig_length);
    auto end = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(end - start);
    eval_file << duration.count() << ", "; 

    // Parse Raw Image
    // printf("Image pixels: %d, %d, %ld should all be the same...\n", sizeof(pixel) * md->width * md->height, frame_size * sizeof(char), raw_frame_buf_len);
    start = high_resolution_clock::now();
    pixel* image_pixels = (pixel*)malloc(frame_size * sizeof(char));
    if (!image_pixels) {
        printf("No memory left(image_pixels)\n");
        return 1;
    }

    size_t vid_frame_length = 0;
    unsigned char* vid_frame = decode_signature(raw_frame_buf, raw_frame_buf_len, &vid_frame_length);

    memcpy(image_pixels, vid_frame, vid_frame_length);
    // printf("Very first set of image pixel: %d, %d, %d\n", image_pixels[0].r, image_pixels[0].g, image_pixels[0].b);
    // int last_pixel_position = md->height * md->width - 1;
    // printf("Very last set of image pixel: %d, %d, %d\n", image_pixels[last_pixel_position].r, image_pixels[last_pixel_position].g, image_pixels[last_pixel_position].b);
    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start);
    eval_file << duration.count() << ", "; 

    // Prepare processed Image
    start = high_resolution_clock::now();
    pixel* processed_pixels;
    processed_pixels = (pixel*)malloc(sizeof(pixel) * md->height * md->width);
    if (!processed_pixels) {
        printf("No memory left(processed_pixels)\n");
        return 1;
    }
    // Prepare for signature output and its hash
    size_t size_of_processed_img_signature = 384;
    unsigned char* processed_img_signature = (unsigned char*)malloc(size_of_processed_img_signature);
    if (!processed_img_signature) {
        printf("No memory left\n");
        return 1;
    }
    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start);
    eval_file << duration.count() << ", "; 

    // Prepare buffer for metadata output
    size_t out_md_json_len = md_json_len + 48;
    char* out_md_json = (char*)malloc(out_md_json_len + 1);
    memset(out_md_json, 0, out_md_json_len + 1);
    if (!out_md_json) {
        printf("No memory left(out_md_json)\n");
        return 1;
    }

    // Going to get into enclave
    start = high_resolution_clock::now();

    sgx_status_t status = t_sgxver_call_apis(
        global_eid, &ret,
        image_pixels, sizeof(pixel) * md->width * md->height,
        md_json, md_json_len, 
        vid_sig, vid_sig_length, 
        processed_pixels,
        out_md_json, out_md_json_len, 
        processed_img_signature, size_of_processed_img_signature);

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

    // Send processed frame
    start = high_resolution_clock::now();

    memset(msg_buf, 0, size_of_msg_buf);
    memcpy(msg_buf, "frame", 5);
    send_message(msg_buf, size_of_msg_buf);
    send_buffer(processed_pixels, frame_size);

    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start);
    eval_file << duration.count() << ", "; 
    // End of send processed frame

    // Send processed filter singature
    start = high_resolution_clock::now();

    char* b64_sig = NULL;
    size_t b64_sig_size = 0;
    Base64Encode(processed_img_signature, size_of_processed_img_signature, &b64_sig, &b64_sig_size);
    memset(msg_buf, 0, size_of_msg_buf);
    memcpy(msg_buf, "sig", 3);
    send_message(msg_buf, size_of_msg_buf);
    // printf("signature going to be sent is: [%s]\n", b64_sig);
    send_buffer(b64_sig, b64_sig_size);
    free(b64_sig);

    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start);
    eval_file << duration.count() << ", "; 
    // End of send processed filter singature

    // Send metadata
    memset(msg_buf, 0, size_of_msg_buf);
    memcpy(msg_buf, "meta", 4);
    // printf("Sending metadata(%d): [%s]\n", out_md_json_len, out_md_json);
    send_message(msg_buf, size_of_msg_buf);
    send_buffer(out_md_json, out_md_json_len);
    // End of send metadata

    // Free Everything (for video_provenance project)
    // printf("Going to free everything in verification_reply...\n");
    start = high_resolution_clock::now();

    if(raw_frame_buf){
        free(raw_frame_buf);
        raw_frame_buf = NULL;
    }
    if(image_pixels)
        free(image_pixels);
    if(processed_pixels)
        free(processed_pixels);
    if(raw_signature){
        free(raw_signature);
        raw_signature = NULL;
    }
    if(processed_img_signature)
        free(processed_img_signature);
    if(md)
        free(md);
    if(md_json){
        free(md_json);
        md_json = NULL;
    }
    if(out_md_json)
        free(out_md_json);
    if(vid_sig)
        free(vid_sig);
    if(vid_frame)
        free(vid_frame);

    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start);
    eval_file << duration.count() << ", ";

	return 0;
}


void request_process_loop(int fd, char** argv)
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
    pthread_t msg;
    // Receive ias cert
    vector<int> opts = { SO_REUSEPORT, SO_REUSEADDR };
    if( tcp_server.setup(atoi(argv[1]),opts) == 0) {
        if( pthread_create(&msg, NULL, received_cert, (void *)0) == 0)
        {
            while(1) {
                tcp_server.accepted();
                cerr << "Accepted" << endl;
                pthread_join(msg, NULL);
                printf("ias cert received successfully...\n");
                break;
            }
        }
    }
    else
        cerr << "Errore apertura socket" << endl;

    // Verify certificate in enclave
    int ret;
    sgx_status_t status_of_verification = t_verify_cert(global_eid, &ret, ias_cert, (size_t)size_of_ias_cert);

    if (status_of_verification != SGX_SUCCESS) {
        cout << "Failed to read IAS certificate file" << endl;
        free(ias_cert);
        return;
    }
    free(ias_cert);

    printf("ias certificate verified successfully, going to start receving and processing frames...\n");
	// tcp_server.closed();

    // Prepare buf for sending message
    msg_buf = (char*) malloc(size_of_msg_buf);

    // Prepare tcp client
    printf("Setting up tcp client...\n");
    tcp_client.setup(argv[2], atoi(argv[3]));

    printf("Going to first send der_cert through tcp client...\n");
    // Send certificate
    memset(msg_buf, 0, size_of_msg_buf);
    memcpy(msg_buf, "cert", 4);
    send_message(msg_buf, size_of_msg_buf);
    send_buffer(der_cert, size_of_cert);
    free(der_cert);

    // if( tcp_server.setup(atoi(argv[1]),opts) != 0){
    //     printf("Second time of setting up tcp server failed...\n");
    // }

    while(1) {
        // Receive frame info
        if( pthread_create(&msg, NULL, received, (void *)0) == 0)
        {
            // tcp_server.accepted();
            // cerr << "Accepted" << endl;
            ++num_of_times_received;
            printf("Going to receive frame: %d\n", num_of_times_received - 1);
            pthread_join(msg, NULL);
            if(md_json == NULL){
                printf("No more frame to be processed...\n");
                break;
            }
            // printf("Going to process frame %d\n", num_of_times_received);
            auto start = high_resolution_clock::now();
            // Note that all info about processed frame is sent in verification_reply
            printf("Going to process and send frame: %d\n", num_of_times_received - 1);
            int process_status = verification_reply(fd, &src_addr , src_addrlen, buf, recv_time, argv);
            if(process_status != 0){
                printf("frame process error...exiting...\n");
                break;
            }
            auto stop = high_resolution_clock::now();
            auto duration = duration_cast<microseconds>(stop - start);
            eval_file << duration.count() << endl; 
            // md_json = NULL;
            // printf("frame %d processed successfully\n", num_of_times_received);
        } else {
            printf("pthread created failed...\n");
        }
    }
    
    free(msg_buf);
}


void sgx_server(char** argv)
{
	int s;
	struct sockaddr_in sinaddr;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == -1) {
		perror("Can not create socket.");
		die(NULL);
	}

	memset(&sinaddr, 0, sizeof(sinaddr));
	sinaddr.sin_family = AF_INET;
	sinaddr.sin_port = htons(123);
	sinaddr.sin_addr.s_addr = INADDR_ANY;

	if (0 != bind(s, (struct sockaddr *)&sinaddr, sizeof(sinaddr))) {
		perror("Bind error");
		die(NULL);
	}

	log_ntp_event(	"\n========================================\n"
			"= Server started, waiting for requests =\n"
			"========================================\n");

	request_process_loop(s, argv);
	close(s);
}

int start_enclave(int argc, char *argv[])
{
	printf("enclave initialization started\n");
    
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

    if(argc < 4){
        printf("Usage: ./TestApp [incoming_port] [outgoing_ip_addr] [outgoing_port]\n");
        return 1;
    }

    // Open file to store evaluation results
    eval_file.open("../video_data/eval_filter.csv");
    if (!eval_file.is_open()) {
        printf("Could not open eval file.\n");
        return 1;
    }
    
	/* initialize and start the enclave in here */
    auto start = high_resolution_clock::now();
	start_enclave(argc, argv);
    auto end = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(end - start);
    eval_file << duration.count() << ", "; 

    size_of_cert = 4 * 4096;
    der_cert = (unsigned char *)malloc(size_of_cert);
    start = high_resolution_clock::now();
    t_create_key_and_x509(global_eid, der_cert, size_of_cert, &size_of_cert, sizeof(size_t));
    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start);
    eval_file << duration.count() << ", ";

	/* create the server waiting for the verification request from the client */
	int s;
	signal(SIGCHLD,wait_wrapper);
	sgx_server(argv);

    t_free(global_eid);

    // Close eval file
    eval_file.close();

	/* after verification we destroy the enclave */
    sgx_destroy_enclave(global_eid);
	return 0;
}


