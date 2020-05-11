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
#include <pthread.h>

# define MAX_PATH FILENAME_MAX
# define SIZEOFHASH 256
# define SIZEOFSIGN 512
# define SIZEOFPUKEY 2048

#include <sgx_urts.h>

#include "TestApp.h"

#include <evp.h>
#include <pem.h>

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

#include "mysql_connection.h"

#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>

using namespace std;

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

int read_raw_file(const char* file_name){
    // Return 0 on success, return 1 on failure
    cout << "Going to read raw file: " << file_name << endl;
    FILE* input_raw_file = fopen(file_name, "r");
    if(input_raw_file == NULL){
        return 1;
    }
    char buff[257]; // Plus one for eof
    int counter_for_image_info = 0; // First two are width and height
    int counter_for_checking_if_all_rgb_values_read_properly = 0;
    char* info;
    while(fgets(buff, 257, input_raw_file) != NULL){
        // printf("buff: %s\n", buff);
        info = strtok(buff, ",");
        while(info != NULL){
            // printf("Info: %d\n", atoi(info));
            if(counter_for_image_info == 0){
                image_width = atoi(info);
                ++counter_for_image_info;
            } else if (counter_for_image_info == 1){
                image_height = atoi(info);
                ++counter_for_image_info;
                printf("The image has width: %d, and height: %d.\n", image_width, image_height);
                image_buffer = (unsigned char*)malloc(sizeof(unsigned char) * image_width * image_height * 3);
            } else {
                if(counter_for_checking_if_all_rgb_values_read_properly + 10 >= image_width * image_height * 3){
                    // printf("Current counter: %d, current limit: %d.\n", counter_for_checking_if_all_rgb_values_read_properly, image_width * image_height * 3);
                    // printf("Current info: %d\n", atoi(info));
                }
                image_buffer[counter_for_checking_if_all_rgb_values_read_properly++] = atoi(info);
            }
            info = strtok(NULL, ",");
        }
        // printf("Current buff: %s\n", buff);
    }
    if(image_buffer == NULL || image_height == 0 || image_width == 0 || 
        counter_for_checking_if_all_rgb_values_read_properly != image_width * image_height * 3){
            return 1;
        }
    printf("The very first pixel has RGB value: (%d, %d, %d).\n", image_buffer[0], image_buffer[1], image_buffer[2]);

    int total_number_of_pixels = image_width * image_height;
    image_pixels = unsigned_chars_to_pixels(image_buffer, total_number_of_pixels);

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


void* thread_test_func(void* p)
{
	new_thread_func(global_eid);
	return NULL;
}

int ucreate_thread()
{
	pthread_t thread;
	int res = pthread_create(&thread, NULL, thread_test_func, NULL);
	return res;
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

int save_processed_frame(pixel* processed_pixels, char* frame_id){
    // Return 0 on success; otherwise, return 1
    // First create the folder if not created
    char* dirname = "data/processed_raw";
    mkdir(dirname, 0777);
    
    // Save data
    int total_number_of_rgb_values = image_width * image_height * 3;

    char processed_raw_file_name[50];
    snprintf(processed_raw_file_name, 50, "data/processed_raw/processed_raw_%s", frame_id);

    FILE* output_file = fopen(processed_raw_file_name, "w+");
    if(output_file == NULL){
        return 1;
    }

    free(image_buffer);
    image_buffer = pixels_to_unsigned_chars(processed_pixels, total_number_of_rgb_values / 3);
    
    fprintf(output_file, "%07d,%07d,", image_width, image_height);
    for(int i = 0; i < total_number_of_rgb_values - 1; ++i){
        fprintf(output_file, "%03d,", image_buffer[i]);
    }
    fprintf(output_file, "%03d", image_buffer[total_number_of_rgb_values - 1]);
    fclose(output_file);

    return 0;
}

int save_char_array_to_file(char* str_to_save, char* frame_id){
    // Return 0 on success; otherwise, return 1
    char* dirname = "data/processed_raw_str_enclave";
    mkdir(dirname, 0777);

    char processed_raw_file_name[50];
    snprintf(processed_raw_file_name, 50, "data/processed_raw_str_enclave/processed_raw_%s", frame_id);

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
                   char** base64Text) {
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
    *str_len = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* str_to_return = (char*)malloc(*str_len);

    fread(str_to_return, 1, *str_len, file);

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

    printf("The base64_signature before assigning signauture is (length: %d): %s\n", strlen(base64_signature), base64_signature);

    Base64Encode(signature, len_of_sign, &base64_signature);

    printf("The base64_signature after assigning signauture of length %d is (length: %d): %s\n", strlen(base64_signature), len_of_sign, base64_signature);

    char* dirname = "data/processed_raw_sign";
    mkdir(dirname, 0777);

    char processed_raw_sign_file_name[50];
    snprintf(processed_raw_sign_file_name, 50, "data/processed_raw_sign/processed_raw_sign_%s", frame_id);

    ofstream signature_file;
    signature_file.open(processed_raw_sign_file_name);
    if (!signature_file.is_open()){
        return 1;
    }
    signature_file.write(base64_signature, strlen(base64_signature));
    signature_file.close();

    return 0;
}

int verification_reply(
	int socket_fd,
	struct sockaddr *saddr_p,
	socklen_t saddrlen,
	unsigned char recv_buf[],
	uint32_t recv_time[],
    char** argv)
{
	fflush(stdout);

    printf("Here is the recv_buf: %s, %s\n", recv_buf, (char*)recv_buf);

    // Read Public Key
    char absolutePath[MAX_PATH];
    char *ptr = NULL;

    ptr = realpath(dirname(argv[0]), absolutePath);

    if (ptr == NULL || chdir(absolutePath) != 0)
        return 1;

    long original_pub_key_str_len;
    char* original_pub_key_str = read_file_as_str(argv[1], &original_pub_key_str_len);

    // Read Filter Private Key
    long filter_pri_key_str_len;
    char* filter_pri_key_str = read_file_as_str(argv[2], &filter_pri_key_str_len);

    // Read Signature
    unsigned char* raw_signature;
    size_t raw_signature_length;

    char raw_file_signature_name[50];
    snprintf(raw_file_signature_name, 50, "data/out_raw_sign/camera_sign_%s", (char*)recv_buf);

    raw_signature = read_signature(raw_file_signature_name, &raw_signature_length);
    cout << "(outside enclave)size of raw signature is: " << raw_signature_length << endl;
    cout << "(outside enclave)signature: " << (char*)raw_signature << endl;

    // Read Raw Image
    char raw_file_name[50];
    snprintf(raw_file_name, 50, "data/out_raw/out_raw_%s", (char*)recv_buf);

    int result_of_reading_raw_file = read_raw_file(raw_file_name);
    cout << "Raw file read result: " << result_of_reading_raw_file << endl;

    // Read Raw Image Hash
    int size_of_hoorf = 65;
    char* hash_of_original_raw_file = (char*) malloc(size_of_hoorf);
    read_file_as_hash(raw_file_name, hash_of_original_raw_file);
    cout << "Hash of the input image file: " << hash_of_original_raw_file << endl;

    // Prepare processed Image
    pixel* processed_pixels;
    processed_pixels = (pixel*)malloc(sizeof(pixel) * image_height * image_width);

    // Allocate char array for encalve to create signature of processed pixels
    long size_of_char_array_for_processed_img_sign = image_height * image_width * 3 * 4 + 16;
    printf("size_of_char_array_for_processed_img_sign: %d\n", size_of_char_array_for_processed_img_sign);
    char* char_array_for_processed_img_sign = (char*)malloc(size_of_char_array_for_processed_img_sign);

    // Prepare for signature output and its hash
    int size_of_processed_img_signature = 512;
    unsigned char* processed_img_signature = (unsigned char*)malloc(size_of_processed_img_signature);
    int size_of_actual_processed_img_signature;
    int size_of_hoprf = 65;
    char* hash_of_processed_raw_file = (char*) malloc(size_of_hoorf);

    // Going to get into enclave
    int runtime_result = -1;
    sgx_status_t status = t_sgxver_call_apis(
        global_eid, image_pixels, sizeof(pixel) * image_width * image_height, image_width, image_height, 
        hash_of_original_raw_file, size_of_hoorf, raw_signature, raw_signature_length, 
        original_pub_key_str, original_pub_key_str_len, processed_pixels, &runtime_result, sizeof(int), 
        char_array_for_processed_img_sign, size_of_char_array_for_processed_img_sign, 
        hash_of_processed_raw_file, size_of_hoprf, 
        filter_pri_key_str, filter_pri_key_str_len,
        processed_img_signature, size_of_processed_img_signature, 
        &size_of_actual_processed_img_signature, sizeof(int));
    if (status != SGX_SUCCESS) {
        printf("Call to t_sgxver_call_apis has failed.\n");
        return 1;    //Test failed
    }

    if (runtime_result != 0) {
        printf("Runtime result verification failed: %d\n", runtime_result);
        return 1;
    }

    cout << "Enclave has successfully run with runtime_result: " << runtime_result << endl;
    printf("After successful run of encalve, the first pixel is(passed into enclave): R: %d; G: %d; B: %d\n", image_pixels[0].r, image_pixels[0].g, image_pixels[0].b);
    printf("After successful run of encalve, the first pixel is(got out of enclave): R: %d; G: %d; B: %d\n", processed_pixels[0].r, processed_pixels[0].g, processed_pixels[0].b);
    // cout << "After successful run of encalve, the first pixel is(passed into enclave): R: " << image_pixels[0].r << "; G: " << image_pixels[0].g << "; B: " << image_pixels[0].b << endl;
    // cout << "After successful run of encalve, the first pixel is(got out of enclave): R: " << processed_pixels[0].r << "; G: " << processed_pixels[0].g << "; B: " << processed_pixels[0].b << endl;

    // Save processed frame
    int result_of_frame_saving = save_processed_frame(processed_pixels, (char*) recv_buf);
    if(result_of_frame_saving != 0){
        return 1;
    }
    // cout << "processed frame saved with id: " << (char*) recv_buf << "; with result: " << result << endl;
    // char hash_temp[65];
    // str_to_hash(char_array_for_processed_img_sign, size_of_char_array_for_processed_img_sign, hash_temp);
    // cout << "(Outside Enclave)hash of char_array_for_processed_img_sign: " << hash_temp << endl;
    // save_char_array_to_file(char_array_for_processed_img_sign, (char*) recv_buf);

    // Save processed filter singature
    int result_of_filter_sign_saving = save_signature(processed_img_signature, size_of_actual_processed_img_signature, (char*) recv_buf);
    if(result_of_filter_sign_saving != 0){
        return 1;
    }

    // Free Everything (for video_provenance project)
    free(image_pixels);
    free(processed_pixels);
    free(image_buffer);
    free(hash_of_original_raw_file);
    free(raw_signature);
    free(original_pub_key_str);
    free(char_array_for_processed_img_sign);
    free(hash_of_processed_raw_file);
    free(processed_img_signature);
    free(filter_pri_key_str);

	return 0;
}


void request_process_loop(int fd, char** argv)
{
	struct sockaddr src_addr;
	socklen_t src_addrlen = sizeof(src_addr);
	unsigned char buf[48];
	uint32_t recv_time[2];
	pid_t pid;

	while (1) {
		while (recvfrom(fd, buf,
				48, 0,
				&src_addr,
				&src_addrlen)
			< 48 );  /* invalid request */

		gettime64(recv_time);

        if(strcmp((char*) buf, "no_more_frame") == 0){
            printf("No more frame detected, ending encalve server...\n");
            break;
        }

		verification_reply(fd, &src_addr , src_addrlen, buf, recv_time, argv);
	}
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
	/* initialize and start the enclave in here */
	start_enclave(argc, argv);

	/* create the server waiting for the verification request from the client */
	int s;
	signal(SIGCHLD,wait_wrapper);
	sgx_server(argv);

	/* after verification we destroy the enclave */
    sgx_destroy_enclave(global_eid);
	return 0;
}


