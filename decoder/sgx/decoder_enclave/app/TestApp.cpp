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
# define TARGET_NUM_FILES_RECEIVED 4
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

// For data
long contentSize = 0;
u8* contentBuffer = NULL;
long camera_cert_len = 0;
char* camera_cert = NULL;
long vid_sig_buf_length = 0;
char* vid_sig_buf = NULL;
long md_json_len = 0;
char* md_json = NULL;

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
    memset(str_to_return, 0, *str_len);
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

void loadContent(char* contentPath, u8* contentBuffer, long contentSize) {
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

void close_app(int signum) {
	printf("There is a SIGINT error happened...exiting......(%d)\n", signum);
	tcp_server.closed();
	tcp_client.exit();
	exit(0);
}

void * send_client(void * m) {
        struct descript_socket *desc = (struct descript_socket*) m;

	while(1) {
		if(!tcp_server.is_online() && tcp_server.get_last_closed_sockets() == desc->id) {
			cerr << "Connessione chiusa: stop send_clients( id:" << desc->id << " ip:" << desc->ip << " )"<< endl;
			break;
		}
		std::time_t t = std::time(0);
		std::tm* now = std::localtime(&t);
		int hour = now->tm_hour;
		int min  = now->tm_min;
		int sec  = now->tm_sec;

		std::string date = 
			    to_string(now->tm_year + 1900) + "-" +
			    to_string(now->tm_mon + 1)     + "-" +
			    to_string(now->tm_mday)        + " " +
			    to_string(hour)                + ":" +
			    to_string(min)                 + ":" +
			    to_string(sec)                 + "\r\n";
		// cerr << date << endl;
		tcp_server.Send(date, desc->id);
		// sleep(time_send);
		usleep(3000);
	}
	pthread_exit(NULL);
    printf("send_client finsihed...\n");
	return 0;
}

void * received(void * m)
{
    // pthread_detach(pthread_self());
		
	// std::signal(SIGPIPE, sigpipe_handler);
	vector<descript_socket*> desc;

	int current_mode = 0;	// 0 means awaiting reading file's nickname; 1 means awaiting file size; 2 means awaiting file content
    int current_file_indicator = -1;   // 0 means video; 1 means metadata; 2 means signature; 3 means certificate 
    void* current_writing_location = NULL;
    long* current_writing_size = NULL;
	long remaining_file_size = 0;

	int num_of_files_received = 0;

	while(1)
	{
		desc = tcp_server.getMessage();
		for(unsigned int i = 0; i < desc.size(); i++) {
			if( desc[i]->message != NULL )
			{ 
				if(!desc[i]->enable_message_runtime) 
				{
					desc[i]->enable_message_runtime = true;
			                if( pthread_create(&msg1[num_message], NULL, send_client, (void *) desc[i]) == 0) {
						cerr << "ATTIVA THREAD INVIO MESSAGGI" << endl;
					}
					num_message++;
					// start message background thread
				}

				// cout << "id:      " << desc[i]->id      << endl
				//      << "ip:      " << desc[i]->ip      << endl
				//      << "message: " << desc[i]->message << endl
				//      << "socket:  " << desc[i]->socket  << endl
				//      << "enable:  " << desc[i]->enable_message_runtime << endl;

				// printf("current_mode is: %d, with remaining size: %ld\n", current_mode, remaining_file_size);

				if(current_mode == 0){
					// printf("Trying to create new file: %s\n", desc[i]->message);
					// char* dirname = "../video_data/src_encoded_video/";
        			// mkdir(dirname, 0777);
					// int size_of_output_actual_path = (strlen(desc[i]->message) + strlen(dirname) + 1) * sizeof(char);
					// char output_actual_path[size_of_output_actual_path];
					// memset(output_actual_path, 0, size_of_output_actual_path);
            		// memcpy(output_actual_path, dirname, sizeof(char) * strlen(dirname));
            		// sprintf(output_actual_path + sizeof(char) * strlen(dirname), "%s", desc[i]->message);
					// printf("File is going to be saved at: %s\n", output_actual_path);
					// output_file = fopen(output_actual_path, "wb");
					// if(output_file == NULL){
					// 	printf("file cannot be created...\n");
					// 	return 0;
					// }
					// printf("Checking if remaining size is 0: %ld\n", remaining_file_size);

                    string file_name = desc[i]->message;
                    // printf("Got new file_name: %s\n", file_name.c_str());
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
                        printf("The file_name is not valid: %s\n", file_name);
                        return 0;
                    }
					current_mode = 1;
				} else if (current_mode == 1){
                    memcpy(current_writing_size, desc[i]->message, 8);
					memcpy(&remaining_file_size, desc[i]->message, 8);
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
                            printf("No file indicator is set, aborted...\n");
                            return 0;
                    }
					current_mode = 2;
				} else {
					// printf("Remaining message size: %ld, where we recevied packet with size: %d, and it is going to be written in file_indicator: %d\n", remaining_file_size, desc[i]->size_of_packet, current_file_indicator);
					// printf("Message with size: %d, with content: %s to be written...\n", current_message_size, desc[i]->message.c_str());
					if(remaining_file_size > desc[i]->size_of_packet){
                        // printf("!!!!!!!!!!!!!!!!!!!Going to write data to current file location: %d\n", current_file_indicator);
                        memcpy(current_writing_location, desc[i]->message, desc[i]->size_of_packet);
                        current_writing_location += desc[i]->size_of_packet;
						remaining_file_size -= desc[i]->size_of_packet;
					} else {
                        // printf("!!!!!!!!!!!!!!!!!!!Last write to the current file location: %d\n", current_file_indicator);
                        memcpy(current_writing_location, desc[i]->message, remaining_file_size);
						remaining_file_size = 0;
						current_mode = 0;
						++num_of_files_received;
						if(num_of_files_received == TARGET_NUM_FILES_RECEIVED){
							return 0;
						}
					}
				}
				tcp_server.clean(i);
			}
		}
		usleep(1000);
	}
	return 0;
}

int send_buffer(void* buffer, long buffer_lenth){
    // Return 0 on success, return 1 on failure

	// Send size of buffer
	printf("Sending buffer size: %d\n", buffer_lenth);
	tcp_client.Send(&buffer_lenth, sizeof(long));
    // printf("Going to wait for receive...\n");
	string rec = tcp_client.receive();
    // printf("Going to wait for receive(finished)...\n");
	if( rec != "" )
	{
		// cout << rec << endl;
	}
	// sleep(1);
	usleep(500);

    long remaining_size_of_buffer = buffer_lenth;
    void* temp_buffer = buffer;
    int is_finished = 0;

	while(1)
	{
        if(remaining_size_of_buffer > SIZEOFPACKAGE){
		    tcp_client.Send(temp_buffer, SIZEOFPACKAGE);
            remaining_size_of_buffer -= SIZEOFPACKAGE;
            temp_buffer += SIZEOFPACKAGE;
        } else {
		    tcp_client.Send(temp_buffer, remaining_size_of_buffer);
            is_finished = 1;
        }
        // printf("(inside)Going to wait for receive...\n");
		string rec = tcp_client.receive();
        // printf("(inside)Going to wait for receive(finished)...\n");
		if( rec != "" )
		{
			// cout << "send_buffer received: " << rec << endl;
		}
        if(is_finished){
            break;
        }
		// sleep(1);
		usleep(500);
	}

    return 0;
}

void send_message(string message){
	tcp_client.Send(message);
    // printf("(send_message)Going to wait for receive...\n");
	string rec = tcp_client.receive();
    // printf("(send_message)Going to wait for receive(finished)...\n");
	if( rec != "" )
	{
		// cout << "send_message received: " << rec << endl;
	}
	// sleep(1);
	usleep(500);
}

void send_message(char* message, int msg_size){
	tcp_client.Send(message, msg_size);
    // printf("(send_message)Going to wait for receive...\n");
	string rec = tcp_client.receive();
    // printf("(send_message)Going to wait for receive(finished)...\n");
	if( rec != "" )
	{
		// cout << "send_message received: " << rec << endl;
	}
	// sleep(1);
	usleep(500);
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
    // char* input_cert_path = argv[2];
    // char* input_sig_path = argv[3];
    // char* input_md_path = argv[4];
    // char* input_video_path = argv[5];
    // char* output_file_path = argv[6];
    // char* output_sig_path = argv[7];
    // char* output_md_path = argv[8];

    printf("input_vendor_pub_path: %s, incoming port: %s, outgoing address: %s, outgoing port: %s\n", argv[1], argv[2], argv[3], argv[4]);

    // Read camera vendor public key
    long vendor_pub_len = 0;
    char* vendor_pub = read_file_as_str(input_vendor_pub_path, &vendor_pub_len);
    if (!vendor_pub) {
        printf("Failed to read camera vendor public key\n");
        return;
    }

    // Register signal handlers
    std::signal(SIGINT, close_app);
	std::signal(SIGPIPE, sigpipe_handler);

    // Start TCPServer for receving incoming data
    pthread_t msg;
    vector<int> opts = { SO_REUSEPORT, SO_REUSEADDR };
    if( tcp_server.setup(atoi(argv[2]),opts) == 0) {
		if( pthread_create(&msg, NULL, received, (void *)0) == 0)
		{
			while(1) {
				tcp_server.accepted();
				++num_of_times_received;
				printf("num_of_times_received: %d\n", num_of_times_received);
				if(num_of_times_received == TARGET_NUM_TIMES_RECEIVED){
					pthread_join(msg, NULL);
					printf("All files received successfully...\n");
					break;
				}
				cerr << "Accepted" << endl;
			}
		}
	}
	else
		cerr << "Errore apertura socket" << endl;

    // Parse metadata
    printf("md_json(%ld): %s\n", md_json_len, md_json);
    if (md_json[md_json_len - 1] == '\0') md_json_len--;
    if (md_json[md_json_len - 1] == '\0') md_json_len--;
    metadata* md = json_2_metadata(md_json, md_json_len);
    if (!md) {
        printf("Failed to parse metadata\n");
        return;
    }

    // Decode signature
    size_t vid_sig_length = 0;
    unsigned char* vid_sig = decode_signature(vid_sig_buf, vid_sig_buf_length, &vid_sig_length);

    // Set up parameters for the case where output is multi
    int max_frames = 999; // Assume there are at most 999 frames
    int max_frame_digits = num_digits(max_frames);
    size_t sig_size = 384; // TODO: Remove hardcoded sig size
    size_t md_size = md_json_len + 16 + 46 + 1;

    // int length_of_base_frame_file_name = (int)strlen(output_file_path);
    // int size_of_current_frame_file_name = sizeof(char) * length_of_base_frame_file_name + sizeof(char) * max_frame_digits;
    // char current_frame_file_name[size_of_current_frame_file_name];
    // int length_of_base_sig_file_name = (int)strlen(output_sig_path);
    // int size_of_current_sig_file_name = sizeof(char) * length_of_base_sig_file_name + sizeof(char) * max_frame_digits;
    // char current_sig_file_name[size_of_current_sig_file_name];
    // int length_of_base_md_file_name = (int)strlen(output_md_path);
    // int size_of_current_md_file_name = sizeof(char) * length_of_base_md_file_name + sizeof(char) * max_frame_digits;
    // char current_md_file_name[size_of_current_md_file_name];

    // FILE* rgb_output_file = NULL;
    // FILE* sig_output_file = NULL;
    // FILE* md_output_file = NULL;

    // Parameters to be acquired from enclave
    u32* frame_width = (u32*)malloc(sizeof(u32)); 
    u32* frame_height = (u32*)malloc(sizeof(u32));
    int* num_of_frames = (int*)malloc(sizeof(int));
    int frame_size = sizeof(u8) * md->width * md->height * 3;
    size_t total_size_of_raw_rgb_buffer = frame_size * md->total_frames;
    u8* output_rgb_buffer = (u8*)malloc(total_size_of_raw_rgb_buffer + 1);
    if (!output_rgb_buffer) {
        printf("No memory left (RGB)\n");
        return;
    }
    size_t total_size_of_sig_buffer = sig_size * md->total_frames;
    u8* output_sig_buffer = (u8*)malloc(total_size_of_sig_buffer + 1);
    if (!output_sig_buffer) {
        printf("No memory left (SIG)\n");
        return;
    }
    size_t total_size_of_md_buffer = md_size * md->total_frames;
    u8* output_md_buffer = (u8*)malloc(total_size_of_md_buffer + 1);
    if (!output_md_buffer) {
        printf("No memory left (MD)\n");
        return;
    }

    int ret = 0;
    sgx_status_t status = t_sgxver_decode_content(global_eid, &ret,
                                                  contentBuffer, contentSize, 
                                                  md_json, md_json_len,
                                                  vendor_pub, vendor_pub_len,
                                                  camera_cert, camera_cert_len,
                                                  vid_sig, vid_sig_length,
                                                  frame_width, frame_height, num_of_frames, 
                                                  output_rgb_buffer, output_sig_buffer, output_md_buffer);

    if (ret) {
        printf("Failed to decode video\n");
    }
    else {
        printf("After enclave, we know the frame width: %d, frame height: %d, and there are a total of %d frames.\n", 
            *frame_width, *frame_height, *num_of_frames);

        u8* temp_output_rgb_buffer = output_rgb_buffer;
        u8* temp_output_sig_buffer = output_sig_buffer;
        u8* temp_output_md_buffer = output_md_buffer;

        // // To-Do: make the following two lines flexible
        // char* dirname = "../../../video_data/raw_for_process";
        // mkdir(dirname, 0777);
        // dirname = "../../../video_data/raw_for_process_sig";
        // mkdir(dirname, 0777);
        // dirname = "../../../video_data/raw_for_process_metadata";
        // mkdir(dirname, 0777);

        // Prepare buf for sending message
        int size_of_msg_buf = 100;
        char* msg_buf = (char*) malloc(size_of_msg_buf);

        // Prepare tcp client
        tcp_client.setup(argv[3], atoi(argv[4]));

        // Send certificate
        memset(msg_buf, 0, size_of_msg_buf);
        memcpy(msg_buf, "cert", 4);
        send_message(msg_buf, size_of_msg_buf);
        send_buffer(der_cert, size_of_cert);

        // Start sending frames 
        for(int i = 0; i < *num_of_frames; ++i){
            string frame_num = to_string(i);

            printf("Sending frame_num: %d\n", i);
            
            // Send frame
            memset(msg_buf, 0, size_of_msg_buf);
            memcpy(msg_buf, "frame", 5);
            send_message(msg_buf, size_of_msg_buf);
            // printf("Very first set of image pixel: %d, %d, %d\n", temp_output_rgb_buffer[0], temp_output_rgb_buffer[1], temp_output_rgb_buffer[2]);
            // int last_pixel_position = 1280 * 720 * 3 - 3;
            // printf("Very last set of image pixel: %d, %d, %d\n", temp_output_rgb_buffer[last_pixel_position], temp_output_rgb_buffer[last_pixel_position + 1], temp_output_rgb_buffer[last_pixel_position + 2]);
            send_buffer(temp_output_rgb_buffer, frame_size);
            temp_output_rgb_buffer += frame_size;

            // Send signature
            char* b64_sig = NULL;
            size_t b64_sig_size = 0;
            Base64Encode(temp_output_sig_buffer, sig_size, &b64_sig, &b64_sig_size);
            temp_output_sig_buffer += sig_size;
            memset(msg_buf, 0, size_of_msg_buf);
            memcpy(msg_buf, "sig", 3);
            send_message(msg_buf, size_of_msg_buf);
            printf("signature going to be sent is: [%s]\n", b64_sig);
            send_buffer(b64_sig, b64_sig_size);
            free(b64_sig);

            // Send metadata
            memset(msg_buf, 0, size_of_msg_buf);
            memcpy(msg_buf, "meta", 4);
            send_message(msg_buf, size_of_msg_buf);
            // int md_size_for_sending = md_size + 1;
            // char* md_for_print = (char*) malloc(md_size_for_sending);
            // memcpy(md_for_print, temp_output_md_buffer, md_size_for_sending);
            // md_for_print[md_size_for_sending - 1] = '\0';
            // printf("metadata(%d) going to be sent is: [%s]\n", md_size_for_sending, md_for_print);
            // send_buffer(md_for_print, md_size_for_sending);
            send_buffer(temp_output_md_buffer, md_size);
            // free(md_for_print);
            temp_output_md_buffer += md_size;

            // // Write frame to file
            // memset(current_frame_file_name, 0, size_of_current_frame_file_name);
            // memcpy(current_frame_file_name, output_file_path, sizeof(char) * length_of_base_frame_file_name);
            // sprintf(current_frame_file_name + sizeof(char) * length_of_base_frame_file_name, "%d", i);
            // printf("Now writing frame to file: %s\n", current_frame_file_name);
            // rgb_output_file = fopen(current_frame_file_name, "wb");
            // fwrite(temp_output_rgb_buffer, frame_size, 1, rgb_output_file);
            // temp_output_rgb_buffer += frame_size;
            // fclose(rgb_output_file);

            // // Write signature to file
            // memset(current_sig_file_name, 0, size_of_current_sig_file_name);
            // memcpy(current_sig_file_name, output_sig_path, sizeof(char) * length_of_base_sig_file_name);
            // sprintf(current_sig_file_name + sizeof(char) * length_of_base_sig_file_name, "%d", i);
            // char* b64_sig = NULL;
            // size_t b64_sig_size = 0;
            // Base64Encode(temp_output_sig_buffer, sig_size, &b64_sig, &b64_sig_size);
            // temp_output_sig_buffer += sig_size;
            // printf("Now writing sig to file: %s, b64_sig: %s, b64_sig_len: %li\n", current_sig_file_name, b64_sig, b64_sig_size);
            // sig_output_file = fopen(current_sig_file_name, "wb");
            // fwrite(b64_sig, b64_sig_size, 1, sig_output_file);
            // fclose(sig_output_file);
            // free(b64_sig);

            // // Write metadata to file
            // memset(current_md_file_name, 0, size_of_current_md_file_name);
            // memcpy(current_md_file_name, output_md_path, sizeof(char) * length_of_base_md_file_name);
            // sprintf(current_md_file_name + sizeof(char) * length_of_base_md_file_name, "%d.json", i);
            // printf("Now writing metadata to file: %s\n", current_md_file_name);
            // md_output_file = fopen(current_md_file_name, "wb");
            // fwrite(temp_output_md_buffer, md_size, 1, md_output_file);
            // temp_output_md_buffer += md_size;
            // fclose(md_output_file);
        }

        // Send no_more_frame msg
        memset(msg_buf, 0, size_of_msg_buf);
        memcpy(msg_buf, "no_more_frame", 13);
        send_message(msg_buf, size_of_msg_buf);
        free(msg_buf);

    }

    // Free everything
    printf("Going to call free at the end of decoder...\n");
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

    auto start = high_resolution_clock::now();
    do_decoding(fd, &src_addr , src_addrlen, buf, recv_time, argc, argv);
    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(stop - start);
    // cout << "decoding with parameters: " << (char*)buf << " takes time: " << duration.count() << endl; 
    cout << "decoding takes time: " << duration.count() << endl; 
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
	sinaddr.sin_port = htons(124);
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

    if(argc < 5){
        printf("Usage: ./TestApp [path_to_camera_vendor_pubkey] [incoming_port] [outgoing_ip_address] [outgoing_port]\n");
        return 1;
    }

	/* initialize and start the enclave in here */
	start_enclave(argc, argv);

    size_of_cert = 4 * 4096;
    der_cert = (unsigned char *)malloc(size_of_cert);
    auto start = high_resolution_clock::now();
    t_create_key_and_x509(global_eid, der_cert, size_of_cert, &size_of_cert, sizeof(size_t));
    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(stop - start);
    cout << "Conducting RA took time: " << duration.count() << endl; 
    // char* cert_file_name = "../video_data/decoder_cert.der";
    // FILE* cert_file = fopen(cert_file_name, "wb");
    // fwrite(der_cert, size_of_cert, 1, cert_file);
    // fclose(cert_file);

	/* create the server waiting for the verification request from the client */
	int s;
	signal(SIGCHLD,wait_wrapper);
	sgx_server(argc, argv);

    t_free(global_eid);

	/* after verification we destroy the enclave */
    sgx_destroy_enclave(global_eid);
	return 0;
}
