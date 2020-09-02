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

unsigned char* read_signature(const char* sign_file_name, size_t* signatureLength){
    // Return signature on success, otherwise, return NULL
    // Need to free the return after finishing using
    FILE* signature_file = fopen(sign_file_name, "r");
    if(signature_file == NULL){
        printf("Failed to read video signature from file: %s\n", sign_file_name);
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
    str_to_return[*str_len - 1] = '\0';

    fclose(file);
    return str_to_return;
}

void createContentBuffer(char* contentPath, u8** pContentBuffer, size_t* pContentSize) {
    struct stat sb;
    if (stat(contentPath, &sb) == -1) {
      perror("stat failed");
      exit(1);
    }

    *pContentSize = sb.st_size;
    *pContentBuffer = (u8*)malloc(*pContentSize);
}

void loadContent(char* contentPath, u8* contentBuffer, size_t contentSize) {
    FILE *input = fopen(contentPath, "r");
    if (input == NULL) {
      perror("open failed");
      exit(1);
    }

    off_t offset = 0;
    while (offset < contentSize) {
      offset += fread(contentBuffer + offset, sizeof(u8), contentSize - offset, input);
    }

    fclose(input);
}

void do_decoding(
    int socket_fd,
	struct sockaddr *saddr_p,
	socklen_t saddrlen,
	unsigned char recv_buf[],
	uint32_t recv_time[],
    int argc,
    char** argv)
{

    // Set up some basic parameters
    char* input_vendor_pub_path = argv[1];
    char* input_cert_path = argv[2];
    char* input_sig_path = argv[3];
    char* input_md_path = argv[4];
    char* input_video_path = argv[5];
    char* output_file_path = argv[6];
    char* output_sig_path = argv[7];

    printf("input_video_path: %s, input_vendor_pub_path: %s, output_file_base_path: %s, input_sig_path: %s, input_cert_path: %s, output_sig_path: %s\n", input_video_path, input_vendor_pub_path, output_file_path, input_sig_path, input_cert_path, output_sig_path);

    // Read camera vendor public key
    long vendor_pub_len = 0;
    char* vendor_pub = read_file_as_str(input_vendor_pub_path, &vendor_pub_len);
    if (!vendor_pub) {
        printf("Failed to read camera vendor public key\n");
        return;
    }

    // Read camera certificate
    long camera_cert_len = 0;
    char* camera_cert = read_file_as_str(input_cert_path, &camera_cert_len);
    if (!camera_cert) {
        printf("Failed to read camera certificate\n");
        return;
    }

    // Read video signature
    size_t vid_sig_length = 0;
    unsigned char* vid_sig = read_signature(input_sig_path, &vid_sig_length);
    if (!vid_sig) {
        printf("Failed to read video signature\n");
        return;
    }

    // Read metadata
    long md_json_len = 0;
    char* md_json = read_file_as_str(input_md_path, &md_json_len);
    if (!md_json) {
        printf("Failed to read metadata\n");
        return;
    }

    // Parse metadata
    metadata* md = json_2_metadata(md_json);

    // Set up parameters for the case where output is multi
    // Assume there are at most 999 frames
    size_t sig_size = 384; // TODO: Remove hardcoded sig size
    int length_of_base_frame_file_name = (int)strlen(output_file_path);
    int size_of_current_frame_file_name = sizeof(char) * length_of_base_frame_file_name + sizeof(char) * 3;
    char current_frame_file_name[size_of_current_frame_file_name];
    int length_of_base_sig_file_name = (int)strlen(output_sig_path);
    int size_of_current_sig_file_name = sizeof(char) * length_of_base_sig_file_name + sizeof(char) * 3;
    char current_sig_file_name[size_of_current_sig_file_name];

    FILE* rgb_output_file = NULL;
    FILE* sig_output_file = NULL;

    // Parameters to be acquired from enclave
    u32* frame_width = (u32*)malloc(sizeof(u32)); 
    u32* frame_height = (u32*)malloc(sizeof(u32));
    int* num_of_frames = (int*)malloc(sizeof(int));
    int frame_size = sizeof(u8) * md->width * md->height * 3;
    size_t total_size_of_raw_rgb_buffer = frame_size * md->total_frames;
    u8* output_rgb_buffer = (u8*)malloc(total_size_of_raw_rgb_buffer + 1);
    size_t total_size_of_sig_buffer = sig_size * md->total_frames;
    u8* output_sig_buffer = (u8*)malloc(total_size_of_sig_buffer + 1);

    u8* contentBuffer;
    size_t contentSize;
    createContentBuffer(input_video_path, &contentBuffer, &contentSize);

    loadContent(input_video_path, contentBuffer, contentSize);
    int ret = 0;
    sgx_status_t status = t_sgxver_decode_content(global_eid, &ret,
                                                  contentBuffer, contentSize, 
                                                  md_json, md_json_len - 1,
                                                  vendor_pub, vendor_pub_len,
                                                  camera_cert, camera_cert_len,
                                                  vid_sig, vid_sig_length,
                                                  frame_width, frame_height, num_of_frames, 
                                                  output_rgb_buffer, output_sig_buffer);

    if (ret) {
        printf("Failed to decode video\n");
    }
    else {
        printf("After enclave, we know the frame width: %d, frame height: %d, and there are a total of %d frames.\n", 
            *frame_width, *frame_height, *num_of_frames);

        u8* temp_output_rgb_buffer = output_rgb_buffer;
        u8* temp_output_sig_buffer = output_sig_buffer;

        // To-Do: make the following two lines flexible
        char* dirname = "../video_data/raw_for_process";
        mkdir(dirname, 0777);
        dirname = "../video_data/sig";
        mkdir(dirname, 0777);

        for(int i = 0; i < *num_of_frames; ++i){
            // Write frame to file
            memset(current_frame_file_name, 0, size_of_current_frame_file_name);
            memcpy(current_frame_file_name, output_file_path, sizeof(char) * length_of_base_frame_file_name);
            sprintf(current_frame_file_name + sizeof(char) * length_of_base_frame_file_name, "%d", i);
            printf("Now writing frame to file: %s\n", current_frame_file_name);
            rgb_output_file = fopen(current_frame_file_name, "wb");
            fwrite(temp_output_rgb_buffer, frame_size, 1, rgb_output_file);
            temp_output_rgb_buffer += frame_size;
            fclose(rgb_output_file);

            // Write signature to file
            memset(current_sig_file_name, 0, size_of_current_sig_file_name);
            memcpy(current_sig_file_name, output_sig_path, sizeof(char) * length_of_base_sig_file_name);
            sprintf(current_sig_file_name + sizeof(char) * length_of_base_sig_file_name, "%d", i);
            char* b64_sig = NULL;
            size_t b64_sig_size = 0;
            Base64Encode(temp_output_sig_buffer, sig_size, &b64_sig, &b64_sig_size);
            temp_output_sig_buffer += sig_size;
            printf("Now writing sig to file: %s\n", current_sig_file_name);
            sig_output_file = fopen(current_sig_file_name, "wb");
            fwrite(b64_sig, b64_sig_size, 1, sig_output_file);
            fclose(sig_output_file);
            free(b64_sig);
        }
    }

    // Free everything
    if(frame_width)
        free(frame_width);
    if(frame_height)
        free(frame_height);
    if(num_of_frames)
        free(num_of_frames);
    if(contentBuffer)
        free(contentBuffer);
    if(output_rgb_buffer)
        free(output_rgb_buffer);
    if(output_sig_buffer)
        free(output_sig_buffer);

    return;
}

void request_process_loop(int fd, int argc, char** argv)
{
	struct sockaddr src_addr;
	socklen_t src_addrlen = sizeof(src_addr);
	unsigned char buf[200];
	uint32_t recv_time[2];
	pid_t pid;

    while (recvfrom(fd, buf,
            200, 0,
            &src_addr,
            &src_addrlen)
        < 200 );  /* invalid request */

    gettime64(recv_time);

    auto start = high_resolution_clock::now();
    do_decoding(fd, &src_addr , src_addrlen, buf, recv_time, argc, argv);
    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(stop - start);
    cout << "decoding with parameters: " << (char*)buf << " takes time: " << duration.count() << endl; 
}

void sgx_server(int argc, char** argv)
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

	request_process_loop(s, argc, argv);
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

    if(argc < 7){
        printf("Usage: ./TestApp [path_to_camera_vendor_pubkey] [path_to_camera_cert] [path_to_video_sig] [path_to_metadata] [path_to_video] [path_to_output_frame_file] [path_to_output_sig_file]\n");
        return 1;
    }

	/* initialize and start the enclave in here */
	start_enclave(argc, argv);

    size_t size_of_cert = 4 * 4096;
    unsigned char *der_cert = (unsigned char *)malloc(size_of_cert);
    auto start = high_resolution_clock::now();
    t_create_key_and_x509(global_eid, der_cert, size_of_cert, &size_of_cert, sizeof(size_t));
    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(stop - start);
    cout << "Conducting RA took time: " << duration.count() << endl; 
    char* cert_file_name = "../video_data/decoder_cert.der";
    FILE* cert_file = fopen(cert_file_name, "wb");
    fwrite(der_cert, size_of_cert, 1, cert_file);
    fclose(cert_file);

	/* create the server waiting for the verification request from the client */
	int s;
	signal(SIGCHLD,wait_wrapper);
	sgx_server(argc, argv);

    t_free(global_eid);

	/* after verification we destroy the enclave */
    sgx_destroy_enclave(global_eid);
	return 0;
}
