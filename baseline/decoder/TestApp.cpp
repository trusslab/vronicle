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
# define TARGET_NUM_TIMES_RECEIVED 2
# define TARGET_NUM_FILES_RECEIVED 1
// #define SIZEOFPACKAGE 40000

#include "TestApp.h"

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

#include "../common/metadata.h"

#include "h264bsd_dec/src/h264bsd_decoder.h"
#include "h264bsd_dec/src/h264bsd_util.h"
#include "yuvconverter.h"

#include "basetype.h"

// For TCP module
#include <ctime>
#include <cerrno>
#include <cstring>
#include "../tcp_module/TCPServer.h"
#include "../tcp_module/TCPClient.h"

// For TCP module
TCPServer tcp_server;   // For direct use
TCPClient tcp_client_rec;    // For scheduler use
TCPClient **tcp_clients;
pthread_t msg1[MAX_CLIENT];
int num_message = 0;
int time_send   = 1;
int num_of_times_received = 0;
int size_of_msg_buf_for_rec = REPLYMSGSIZE;
char* msg_buf_for_rec;

// For multi bundle-filter enclaves
int num_of_pair_of_output = -1;
int current_sending_target_id = 0;
vector<pair<string, int>*> output_filters_info;

// For data
long contentSize = 0;
u8* contentBuffer = NULL;
long md_json_len = 0;
char* md_json = NULL;

int is_decoding_finished = 0;

// For Decoding use
char* s_md_json;
long s_md_json_len;
u32 status;
storage_t storage;
u8* byteStrm;
u32 readBytes;
u32 len;
int numPics = 0;
size_t frame_size_in_rgb = 0;
u8* pic;
u32 picId, isIdrPic, numErrMbs;
u32 topOffset, leftOffset, width = 0, height = 0, croppingFlag;
metadata* tmp;
unsigned char* data_buf = NULL;
// Obtain signature length and allocate memory for signature
int tmp_total_digests = 0;

using namespace std;

#include <chrono> 
using namespace std::chrono;

unsigned char* image_buffer = NULL;	/* Points to large array of R,G,B-order data */
unsigned char* pure_input_image_str = NULL; /* for signature verification purpose */
pixel* image_pixels;    /* also RGB, but all 3 vales in a single instance (used for processing filter) */
int image_height = 0;	/* Number of rows in image */
int image_width = 0;		/* Number of columns in image */

char* hash_of_file;  /* temp test */

// For evaluation
ofstream eval_file;
ofstream alt_eval_file;

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
      perror("[decoder]: stat failed");
      exit(1);
    }

    *pContentSize = sb.st_size;
    *pContentBuffer = (u8*)malloc(*pContentSize);
}

void loadContent(char* contentPath, u8* contentBuffer, long contentSize) {
    FILE *input = fopen(contentPath, "r");
    if (input == NULL) {
      perror("[decoder]: open failed");
      exit(1);
    }

    off_t offset = 0;
    while (offset < contentSize) {
      offset += fread(contentBuffer + offset, sizeof(u8), contentSize - offset, input);
    }

    fclose(input);
}

void close_app(int signum) {
	printf("[decoder]: There is a SIGINT error happened...exiting......(%d)\n", signum);
	tcp_server.closed();
    tcp_client_rec.exit();
    for(int i = 0; i < num_of_pair_of_output; ++i){
	    tcp_clients[i]->exit();
    }
	exit(0);
}

void * received(void * m)
{
    // Assume there is a connection for tcp_server
    // Will use the latest connected one

	int current_mode = 0;	// 0 means awaiting reading file's nickname; 1 means awaiting file size; 2 means awaiting file content
    int current_file_indicator = -1;   // 0 means video; 1 means metadata; 2 means signature; 3 means certificate 
    char* current_writing_location = NULL;
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
            // printf("[decoder]: Got new file_name: %s\n", file_name.c_str());
            if(file_name == "vid"){
                current_file_indicator = 0;
                current_writing_size = &contentSize;
            } else if (file_name == "meta"){
                current_file_indicator = 1;
                current_writing_size = &md_json_len;
            } else {
                printf("[decoder]: The file_name is not valid: %s\n", file_name.c_str());
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
                    current_writing_location = (char*)contentBuffer;
                    break;
                case 1:
                    md_json = (char*) malloc(*current_writing_size * sizeof(char));
                    current_writing_location = md_json;
                    break;
                default:
                    printf("[decoder]: No file indicator is set, aborted...\n");
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

int send_buffer(void* buffer, long buffer_lenth, int sending_target_id){
    // Return 0 on success, return 1 on failure

	// Send size of buffer
	tcp_clients[sending_target_id]->Send(&buffer_lenth, sizeof(long));
	string rec = tcp_clients[sending_target_id]->receive_exact(REPLYMSGSIZE);
	if( rec != "" )
	{
		// cout << rec << endl;
	}

    long remaining_size_of_buffer = buffer_lenth;
    char* temp_buffer = (char*)buffer;
    int is_finished = 0;

	while(1)
	{
        if(remaining_size_of_buffer > SIZEOFPACKAGE_HIGH){
		    tcp_clients[sending_target_id]->Send(temp_buffer, SIZEOFPACKAGE_HIGH);
            remaining_size_of_buffer -= SIZEOFPACKAGE_HIGH;
            temp_buffer += SIZEOFPACKAGE_HIGH;
        } else {
		    tcp_clients[sending_target_id]->Send(temp_buffer, remaining_size_of_buffer);
            is_finished = 1;
        }
        // printf("(inside)Going to wait for receive...just send buffer with size: %d\n", remaining_size_of_buffer);
		string rec = tcp_clients[sending_target_id]->receive_exact(REPLYMSGSIZE);
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

void send_message(char* message, int msg_size, int sending_target_id){
	tcp_clients[sending_target_id]->Send(message, msg_size);
    // printf("(send_message)Going to wait for receive...\n");
	string rec = tcp_clients[sending_target_id]->receive_exact(REPLYMSGSIZE);
    // printf("(send_message)Going to wait for receive(finished)...\n");
	if( rec != "" )
	{
		// cout << "send_message received: " << rec << endl;
	}
}

int check_and_change_to_main_scheduler(){
    // Return 0 on success, otherwise return 1

    // printf("[decoder]: In check_and_change_to_main_scheduler, going to receive...\n");
    string scheduler_mode = tcp_client_rec.receive_name();
    // printf("[decoder]: In check_and_change_to_main_scheduler, received: {%s}\n", scheduler_mode.c_str());
    int mode_of_scheduler = 0;  // 0 means main; 1 means helper
    // printf("[decoder]: In check_and_change_to_main_scheduler, is it main: {%d}\n", scheduler_mode == "main");
    if(scheduler_mode == "main"){
        mode_of_scheduler = 0;
    } else if (scheduler_mode == "helper"){
        mode_of_scheduler = 1;
    } else {
        return 1;
    }

    // printf("[decoder]: In check_and_change_to_main_scheduler, going to reply...mode_of_scheduler = [%d]\n", mode_of_scheduler);
    char* reply_to_scheduler = (char*)malloc(REPLYMSGSIZE);
    memset(reply_to_scheduler, 0, REPLYMSGSIZE);
    memcpy(reply_to_scheduler, "ready", 5);
    tcp_client_rec.Send(reply_to_scheduler, REPLYMSGSIZE);
    // printf("[decoder]: In check_and_change_to_main_scheduler, reply finished...\n");

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
        bool connection_result = tcp_client_rec.setup(ip_addr.c_str(), atoi(port.c_str()));

        if(!connection_result){
            printf("[decoder]: Connection cannot be established with main scheduler...\n");
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
        printf("[decoder]: num_of_pair_of_output with main scheduler invalid: [%ld]...\n", new_num);
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

    for(int i = 0; i < num_of_pair_of_output; ++i){
        tcp_clients[i] = new TCPClient();
        // printf("[decoder]: Setting up tcp client with args: %s, %s...\n", argv[2 + i * 2], argv[3 + i * 2]);

        ip_addr = tcp_client_rec.receive_name();
        memset(reply_to_scheduler, 0, REPLYMSGSIZE);
        memcpy(reply_to_scheduler, "ready", 5);
        tcp_client_rec.Send(reply_to_scheduler, REPLYMSGSIZE);
        port = tcp_client_rec.receive_name();
        memset(reply_to_scheduler, 0, REPLYMSGSIZE);
        memcpy(reply_to_scheduler, "ready", 5);
        tcp_client_rec.Send(reply_to_scheduler, REPLYMSGSIZE);

        // printf("[decoder]: In setup_tcp_clients_auto, going to connect to next filter_enclave with ip: {%s} and port: {%s}\n", ip_addr.c_str(), port.c_str());

        bool result_of_connection_setup = tcp_clients[i]->setup(ip_addr.c_str(), atoi(port.c_str()));
        if(!result_of_connection_setup){
            free(reply_to_scheduler);
            return 1;
        }
    }
    free(reply_to_scheduler);
    return 0;
}

int prepare_decoder(
	void* input_content_buffer, long size_of_input_content_buffer, 
	void* md_json, long md_json_len) {
	// Return 1 on success, return 0 on fail, return -1 on error, return -2 on already verified

	// Prepare Decoder
	status = h264bsdInit(&storage, HANTRO_FALSE);

	if (status != HANTRO_OK) {
		// fprintf(stderr, "h264bsdInit failed\n");
		printf("h264bsdInit failed\n");
		return 0;
	}

	len = size_of_input_content_buffer;
	byteStrm = (u8*)malloc(len);
	memset(byteStrm, 0, len);
	memcpy(byteStrm, input_content_buffer, len);

	s_md_json_len = md_json_len;
	s_md_json = (char*)malloc(s_md_json_len);
	memset(s_md_json, 0, s_md_json_len);
	memcpy(s_md_json, md_json, s_md_json_len);

	return 1;
}

int decode_single_frame(
	void* decoded_frame, long size_of_decoded_frame, 
	void* output_md_json, long size_of_output_json) {
	
	// Return 0 on success; return -1 on finish all decoding; otherwise fail...

	if(is_decoding_finished){
		printf("[decoder]: decoding is already finished...\n");
		return 1;
	}

	u8* decoded_frame_temp = (u8*)decoded_frame;
	memset(decoded_frame_temp, 0, size_of_decoded_frame);
	char* output_md_json_temp = (char*)output_md_json;
	memset(output_md_json_temp, 0, size_of_output_json);

	int is_single_frame_successfully_decoded = 0;

	// For some temp variables
	size_t real_size_of_output_md_json = 0;
	int res = -1;
	char* output_json_n = NULL;
	u8* pic_rgb = NULL;
    const char* dummy_mrenclave = "11111111111111111111111111111111111111111111";

	while (len > 0 && !is_single_frame_successfully_decoded) {
		u32 result = h264bsdDecode(&storage, byteStrm, len, 0, &readBytes);
		// printf("[decoder]: readBytes: [%d], frame_size: [%d]\n", readBytes, frame_size_in_rgb);
		len -= readBytes;
		byteStrm += readBytes;

		switch (result) {
			case H264BSD_PIC_RDY:
				// Extract frame
				pic = h264bsdNextOutputPicture(&storage, &picId, &isIdrPic, &numErrMbs);
				++numPics;
				if(!frame_size_in_rgb){
					printf("No valid video header detected, exiting...\n");
					exit(1);
				}

				// Convert frame to RGB packed format
				yuv420_prog_planar_to_rgb_packed(pic, decoded_frame_temp, width, height);

				// Generate metadata
				tmp = json_2_metadata((char*)s_md_json, s_md_json_len);
				if (!tmp) {
					printf("Failed to parse metadata\n");
					exit(1);
				}
				tmp->frame_id = numPics - 1;
				tmp_total_digests = tmp->total_digests;
				tmp->total_digests = tmp_total_digests + 1;
				tmp->digests = (char**)malloc(sizeof(char*) * 1);
				tmp->digests[0] = (char*)malloc(45);
				memset(tmp->digests[0], 0, 45);
				memcpy(tmp->digests[0], dummy_mrenclave, 45);
				output_json_n = metadata_2_json(tmp);
				// printf("[decode:TestEnclave]: We now have output_json_n[%ld]: {%s}\n", strlen(output_json_n), output_json_n);

				// Check size of md_json
				real_size_of_output_md_json = strlen(output_json_n);
				if(real_size_of_output_md_json != (size_t)size_of_output_json){
					printf("[decode:TestEnclave]: Incorrect md_json size...real_size_of_output_md_json: [%ld]; size_of_output_json: [%ld]\n", real_size_of_output_md_json, size_of_output_json);
					return 1;
				}
				memcpy(output_md_json_temp, output_json_n, real_size_of_output_md_json);
				// printf("[decode:TestEnclave]: We now have output_json_n[%d]: {%s}\n", real_size_of_output_md_json, output_md_json_temp);

				// Clean up
				free_metadata(tmp);
				free(output_json_n);
				free(data_buf);

				is_single_frame_successfully_decoded = 1;

				break;
			case H264BSD_HDRS_RDY:
				// printf("[decoder]: in H264BSD_HDRS_RDY ...\n");
				// Obtain frame parameters
				h264bsdCroppingParams(&storage, &croppingFlag, &leftOffset, &width, &topOffset, &height);
				if (!croppingFlag) {
				width = h264bsdPicWidth(&storage) * 16;
				height = h264bsdPicHeight(&storage) * 16;
				}
				// Allocate memory for frame
				if(!frame_size_in_rgb){
					frame_size_in_rgb = width * height * 3;
					if(size_of_decoded_frame != frame_size_in_rgb){
						printf("[decoder]: Incorrect size...size_of_decoded_frame: [%ld]; frame_size_in_rgb: [%ld]...\n", size_of_decoded_frame, frame_size_in_rgb);
						return 1;
					}
					InitConvt(width, height);
				}
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

	if(len <= 0){
		h264bsdShutdown(&storage);
		is_decoding_finished = 1;
		return -1;
	}
	
	return 0;
}

void do_decoding(
    int argc,
    char** argv)
{
    // printf("[decoder]: incoming port: %s, outgoing address: %s, outgoing port: %s\n", argv[1], argv[2], argv[3]);

    // Register signal handlers
    std::signal(SIGINT, close_app);
	std::signal(SIGPIPE, sigpipe_handler);

    // Init evaluation
    auto start = high_resolution_clock::now();
    auto end = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(end - start);

    // declaring argument of time() 

    // ctime() used to give the present time 

    // Prepare buf for sending message
    msg_buf_for_rec = (char*) malloc(size_of_msg_buf_for_rec);

    // Prepare tcp client
    // printf("[decoder]: Setting up tcp client...\n");
    bool connection_result = tcp_client_rec.setup("127.0.0.1", atoi(argv[1]));

    if(!connection_result){
        printf("[decoder]: Connection cannot be established...\n");
        return;
    }

    // Determine if the current scheduler is in main mode or in helper mode
    // If in helper mode, be ready to change tcp_client for connecting the main scheduler
    // printf("Going to do check_and_change_to_main_scheduler...\n");
    check_and_change_to_main_scheduler();
    // printf("check_and_change_to_main_scheduler finished...\n");

    time_t my_time = time(NULL); 
    // printf("[decoder]: Receiving started at: %s", ctime(&my_time));
    
    memset(msg_buf_for_rec, 0, size_of_msg_buf_for_rec);
    memcpy(msg_buf_for_rec, "ready", 5);
    tcp_client_rec.Send(msg_buf_for_rec, REPLYMSGSIZE);
    // printf("[decoder]: reply is sent...\n");

    start = high_resolution_clock::now();

    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start);
    alt_eval_file << duration.count() << ", ";

    // Start receiving other data
    while(num_of_times_received != TARGET_NUM_TIMES_RECEIVED){
        // printf("[decoder]: Start receiving data...\n");
        string name_of_current_file = tcp_client_rec.receive_name();
        // printf("[decoder]: Got new data: {%s}\n", name_of_current_file.c_str());
        void* current_writting_location;
        long current_writting_location_size;
        // printf("[decoder]: Got new file name: %s\n", name_of_current_file.c_str());
        memset(msg_buf_for_rec, 0, size_of_msg_buf_for_rec);
        memcpy(msg_buf_for_rec, "ready", 5);
        // printf("[decoder]: Going to send reply message...\n");
        tcp_client_rec.Send(msg_buf_for_rec, size_of_msg_buf_for_rec);
        // printf("[decoder]: Reply to scheduler is sent...\n");
        if (name_of_current_file == "vid"){

            contentSize = tcp_client_rec.receive_size_of_data();
            
            contentBuffer = (unsigned char*) malloc(contentSize);
            current_writting_location_size = contentSize;
            current_writting_location = contentBuffer;

        } else if (name_of_current_file == "meta"){
            // printf("[decoder]: Going to receive size of data...\n");
            md_json_len = tcp_client_rec.receive_size_of_data();
            
            // printf("[decoder]: size of data received(%ld)...\n", md_json_len);
            
            md_json = (char*) malloc(md_json_len);
            current_writting_location_size = md_json_len;
            current_writting_location = md_json;

        } else {
            printf("[decoder]: Received invalid file name: [%s]\n", name_of_current_file.c_str());
            return;
        }

        memset(msg_buf_for_rec, 0, size_of_msg_buf_for_rec);
        memcpy(msg_buf_for_rec, "ready", 5);
        tcp_client_rec.Send(msg_buf_for_rec, size_of_msg_buf_for_rec);

        // printf("[decoder]: Going to try receive data for size: %ld\n", current_writting_location_size);
        try_receive_something(current_writting_location, current_writting_location_size);
        ++num_of_times_received;
    }

    // Free
    free(msg_buf_for_rec);

    start = high_resolution_clock::now();

    // Parse metadata
    // printf("md_json(%ld): %s\n", md_json_len, md_json);
    if (md_json[md_json_len - 1] == '\0') md_json_len--;
    if (md_json[md_json_len - 1] == '\0') md_json_len--;
    metadata* md = json_2_metadata(md_json, md_json_len);
    if (!md) {
        printf("[decoder]: Failed to parse metadata\n");
        return;
    }

    // Set up parameters for the case where output is multi
    int max_frames = 999; // Assume there are at most 999 frames
    int max_frame_digits = num_digits(max_frames);
    size_t md_size = md_json_len + 16 + 46;

    // Parameters to be acquired from enclave
    // u32* frame_width = (u32*)malloc(sizeof(u32)); 
    // u32* frame_height = (u32*)malloc(sizeof(u32));
    // int* num_of_frames = (int*)malloc(sizeof(int));
    int num_of_frames = md->total_frames;
    int frame_size = sizeof(u8) * md->width * md->height * 3;
    size_t total_size_of_raw_rgb_buffer = frame_size * md->total_frames;
    u8* output_rgb_buffer = (u8*)malloc(total_size_of_raw_rgb_buffer + 1);
    if (!output_rgb_buffer) {
        printf("[decoder]: No memory left (RGB)\n");
        return;
    }
    size_t total_size_of_md_buffer = md_size * md->total_frames;
    u8* output_md_buffer = (u8*)malloc(total_size_of_md_buffer + 1);
    if (!output_md_buffer) {
        printf("[decoder]: No memory left (MD)\n");
        return;
    }

    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start);
    alt_eval_file << duration.count() << ", ";

    int res = 0;

    // Prepare decoder
    start = high_resolution_clock::now();
    res = prepare_decoder(contentBuffer, contentSize, 
                          md_json, md_json_len);

    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start);
    alt_eval_file << duration.count() << ", ";

    auto start_s = high_resolution_clock::now();

    if (res != 1) {
        printf("[decoder]: Failed to prepare decoding video with error code: [%d]\n", res);
        close_app(0);
    }
    else {
        // printf("[decoder]: After decoding, we know the frame width: %d, frame height: %d, and there are a total of %d frames.\n", 
        //     *frame_width, *frame_height, *num_of_frames);

        // Clean signle frame info each time before getting something new...

        u8* temp_output_rgb_buffer = output_rgb_buffer;
        u8* temp_output_md_buffer = output_md_buffer;

        // Prepare buf for sending message
        int size_of_msg_buf = 100;
        char* msg_buf = (char*) malloc(size_of_msg_buf);

        // printf("Going to prepare all tcp clients...\n");

        // Prepare all tcp clients
        if(set_num_of_pair_of_output() != 0){
            printf("[decoder]: Failed to do set_num_of_pair_of_output\n");
            return;
        }
        // printf("[decoder]: After receiving, we have num_of_pair_of_output: [%d]\n", num_of_pair_of_output);
        if(setup_tcp_clients_auto() != 0){
            printf("[decoder]: Failed to do setup_tcp_clients_auto\n");
            return;
        }

        end = high_resolution_clock::now();
        duration = duration_cast<microseconds>(end - start_s);
        alt_eval_file << duration.count() << ", ";

        // Init for single frame info
        u8* single_frame_buf = (u8*)malloc(frame_size);
        u8* single_frame_md_json = (u8*)malloc(md_size);

        // Start sending frames 
        for(int i = 0; i < num_of_frames; ++i){

            // printf("[decoder]: Sending frame: %d\n", i);

            // Clean signle frame info each time before getting something new...
            memset(single_frame_buf, 0, frame_size);
            memset(single_frame_md_json, 0, md_size);

            res = decode_single_frame(single_frame_buf, frame_size,
                                      single_frame_md_json, md_size);

            if(res == -1 && i + 1 < num_of_frames){
                printf("[decoder]: Finished decoding video on incorrect frame: [%d], where total frame is: [%d]...\n", i, num_of_frames);
                close_app(0);
            } else if(res != 0 && res != -1){
                printf("[decoder]: Failed to decode video on frame: [%d]\n", i);
                close_app(0);
            }

            string frame_num = to_string(i);
            
            // Send frame
            // char* b64_frame = NULL;
            // size_t b64_frame_size = 0;
            // Base64Encode(temp_output_rgb_buffer, frame_size, &b64_frame, &b64_frame_size);
            memset(msg_buf, 0, size_of_msg_buf);
            memcpy(msg_buf, "frame", 5);
            // printf("Going to send frame %d's name...\n", i);

            start = high_resolution_clock::now();

            send_message(msg_buf, size_of_msg_buf, current_sending_target_id);
            // printf("Very first set of image pixel: %d, %d, %d\n", temp_output_rgb_buffer[0], temp_output_rgb_buffer[1], temp_output_rgb_buffer[2]);
            // int last_pixel_position = 1280 * 720 * 3 - 3;
            // printf("Very last set of image pixel: %d, %d, %d\n", temp_output_rgb_buffer[last_pixel_position], temp_output_rgb_buffer[last_pixel_position + 1], temp_output_rgb_buffer[last_pixel_position + 2]);
            // printf("Going to send frame %d's info...\n", i);
            // send_buffer(temp_output_rgb_buffer, frame_size, current_sending_target_id);
            send_buffer(single_frame_buf, frame_size, current_sending_target_id);

            end = high_resolution_clock::now();
            duration = duration_cast<microseconds>(end - start);
            eval_file << duration.count() << ", ";

            // free(b64_frame);
            // temp_output_rgb_buffer += frame_size;

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

            send_message(msg_buf, size_of_msg_buf, current_sending_target_id);
            // send_buffer(temp_output_md_buffer, md_size, current_sending_target_id);
            send_buffer(single_frame_md_json, md_size, current_sending_target_id);

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
            send_message(msg_buf, size_of_msg_buf, i);
        }

        free(msg_buf);

    }

    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start_s);
    alt_eval_file << duration.count();

    // Free everything
    // printf("[decoder]: Going to call free at the end of decoder...\n");
    // if(frame_width)
    //     free(frame_width);
    // if(frame_height)
    //     free(frame_height);
    // if(num_of_frames)
    //     free(num_of_frames);
    if(contentBuffer)
        free(contentBuffer);
    if(output_rgb_buffer)
        free(output_rgb_buffer);
    if(output_md_buffer)
        free(output_md_buffer);
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

void wait_wrapper(int s)
{
	wait(&s);
}

/* Application entry */
int main(int argc, char *argv[], char **env)
{

    if(argc < 2){
        printf("[decoder]: argc: %d\n", argc);
        // printf("%s, %s, %s, %s...\n", argv[0], argv[1], argv[2], argv[3]);
        printf("[decoder]: Usage: ./TestApp [incoming_port] \n");
        return 1;
    }

    // num_of_pair_of_output += (argc - 4) / 2;

    // Open file to store evaluation results
    mkdir("../evaluation/eval_result", 0777);
    eval_file.open("../evaluation/eval_result/eval_decoder.csv");
    if (!eval_file.is_open()) {
        printf("[decoder]: Could not open eval file.\n");
        return 1;
    }

    alt_eval_file.open("../evaluation/eval_result/eval_decoder_one_time.csv");
    if (!alt_eval_file.is_open()) {
        printf("[decoder]: Could not open alt_eval_file file.\n");
        return 1;
    }

    // For time of initializing sgx enclave and doing RA
    auto start = high_resolution_clock::now();

    auto end = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(end - start);
    alt_eval_file << duration.count() << ", "; 

    start = high_resolution_clock::now();
    
    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start);
    alt_eval_file << duration.count() << ", "; 

	/* create the server waiting for the verification request from the client */
	int s;
	signal(SIGCHLD,wait_wrapper);
    do_decoding(argc, argv);

    // Close eval file
    eval_file.close();
    alt_eval_file.close();

	return 0;
}
