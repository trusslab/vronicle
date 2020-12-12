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
# define TARGET_NUM_FILES_RECEIVED 3

#include "TestApp.h"

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

#include "../common/metadata.h"
#include "SampleFilters.h"

// For TCP module
#include <ctime>
#include <cerrno>
#include <cstring>
#include "../tcp_module/TCPServer.h"
#include "../tcp_module/TCPClient.h"

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

// For incoming data
long md_json_len_i = 0;
char* md_json_i = NULL;
long raw_frame_buf_len_i = 0;
char* raw_frame_buf_i = NULL;
int is_finished_receiving = 0;

// For incoming data when being processed (Cache for incoming data)
long md_json_len = 0;
char* md_json = NULL;
long raw_frame_buf_len = 0;
char* raw_frame_buf = NULL;

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

// For evaluation
ofstream eval_file;
ofstream alt_eval_file;

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
    char* current_writing_location = NULL;
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
            printf("Got new file_name: %s\n", file_name.c_str());
            if(file_name == "frame"){
                current_file_indicator = 0;
                current_writing_size = &raw_frame_buf_len_i;
            } else if (file_name == "meta"){
                current_file_indicator = 1;
                current_writing_size = &md_json_len_i;
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
    char* temp_buffer = (char*)buffer;
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
	tcp_client.Send(message, msg_size);
    // printf("(send_message)Going to wait for receive...\n");
	string rec = tcp_client.receive_exact(REPLYMSGSIZE);
    // printf("(send_message)Going to wait for receive(finished)...\n");
	if( rec != "" )
	{
		// cout << "send_message received: " << rec << endl;
	}
}

void* send_frame_info_to_next_enclave(void* m){
    // Send processed frame

    memset(msg_buf, 0, size_of_msg_buf);
    memcpy(msg_buf, "frame", 5);
    send_message(msg_buf, size_of_msg_buf);
    send_buffer(processed_pixels, frame_size);

    // End of send processed frame

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
    char* raw_file_sig_path  = argv[2];
    char* raw_file_path      = argv[3];
    char* raw_md_path        = argv[4];
    char* output_md_path     = argv[5];

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

	// Process image
	blur((pixel*)image_pixels, processed_pixels_p, md->width, md->width * md->height, 7);

    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start);
    eval_file << duration.count() << ", "; 

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
    vector<int> opts = { SO_REUSEPORT, SO_REUSEADDR };
    if( tcp_server.setup(atoi(argv[1]),opts) == 0) {
        tcp_server.accepted();
        // cerr << "Accepted" << endl;

        start = high_resolution_clock::now();

        if(pthread_create(&msg, NULL, received, (void *)0) != 0){
            printf("pthread for receiving created failed...quiting...\n");
            return;
        }
        pthread_join(msg, NULL);

        stop = high_resolution_clock::now();
        duration = duration_cast<microseconds>(stop - start);
        alt_eval_file << duration.count() << ", ";

        // printf("ias cert received successfully...\n");
    }
    else
        cerr << "Errore apertura socket" << endl;

    
    start = high_resolution_clock::now();

    // Prepare buf for sending message
    msg_buf = (char*) malloc(size_of_msg_buf);

    // Prepare tcp client
    // printf("Setting up tcp client...\n");
    tcp_client.setup(argv[2], atoi(argv[3]));

    stop = high_resolution_clock::now();
    duration = duration_cast<microseconds>(stop - start);
    alt_eval_file << duration.count() << ", ";

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
        if(is_finished_receiving || raw_frame_buf_i == NULL || md_json_i == NULL){
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
    mkdir("../../../evaluation/eval_result", 0777);
    eval_file.open("../../../evaluation/eval_result/eval_filter_blur.csv");
    if (!eval_file.is_open()) {
        printf("Could not open eval file.\n");
        return 1;
    }

    alt_eval_file.open("../../../evaluation/eval_result/eval_filter_blur_one_time.csv");
    if (!alt_eval_file.is_open()) {
        printf("Could not open alt_eval_file file.\n");
        return 1;
    }

	/* create the server waiting for the verification request from the client */
	int s;
	signal(SIGCHLD,wait_wrapper);
	request_process_loop(argv);

    // Close eval file
    eval_file.close();
    alt_eval_file.close();

	return 0;
}


