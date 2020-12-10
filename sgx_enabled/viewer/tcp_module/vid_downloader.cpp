#include <ctime>
#include <cerrno>
#include <cstring>
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
#include "TCPServer.h"
#include "TCPClient.h"
#include <time.h> /* for time() and ctime() */

# define TARGET_NUM_FILES_RECEIVED 4

TCPClient tcp_client;
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
long vid_buf_len = 0;
char* vid_buf = NULL;

using namespace std;

#include <chrono> 
using namespace std::chrono;

void close_app(int signum) {
	printf("There is a SIGINT error happened...exiting......(%d)\n", signum);
	tcp_client.exit();
	exit(0);
}

void send_message(char* message, int msg_size){
    // usleep(50);
	tcp_client.Send(message, msg_size);
    // printf("(send_message)Going to wait for receive...\n");
	// string rec = tcp_client.receive_exact(REPLYMSGSIZE);
    // // printf("(send_message)Going to wait for receive(finished)...\n");
	// if( rec != "" )
	// {
	// 	// cout << "send_message received: " << rec << endl;
	// }
	// sleep(1);
	// usleep(50);
}

void try_receive_something(void* data_for_storage, long data_size){
    long remaining_data_size = data_size;
    char* temp_data_for_storage = (char*)data_for_storage;
    char* data_received;
    while(remaining_data_size > 0){
        printf("Receiving data with remaining_data_size: %ld\n", remaining_data_size);
        if(remaining_data_size > SIZEOFPACKAGE){
            data_received = tcp_client.receive_exact(SIZEOFPACKAGE);
            memcpy(temp_data_for_storage, data_received, SIZEOFPACKAGE);
            temp_data_for_storage += SIZEOFPACKAGE;
            remaining_data_size -= SIZEOFPACKAGE;
        } else {
            data_received = tcp_client.receive_exact(remaining_data_size);
            memcpy(temp_data_for_storage, data_received, remaining_data_size);
            remaining_data_size = 0;
        }
        free(data_received);
        printf("Received with data and going to receive again after replying...\n");
        memset(msg_buf, 0, size_of_msg_buf);
        memcpy(msg_buf, "ready", 5);
        send_message(msg_buf, size_of_msg_buf);
    }
    return;
}

int main(int argc, char *argv[], char **env)
{
    if(argc < 7){
        printf("Usage: ./TestApp [server_ip_address] [server_port] [cert_out_position] [vid_out_position] [vid_md_position] [vid_sig_out_position]\n");
        return 1;
    }

    // Register signal handlers
    std::signal(SIGINT, close_app);
	std::signal(SIGPIPE, sigpipe_handler);

    // Prepare buf for sending message
    msg_buf = (char*) malloc(size_of_msg_buf);

    // Prepare tcp client
    printf("Setting up tcp client...\n");
    bool connection_result = tcp_client.setup(argv[1], atoi(argv[2]));

    if(!connection_result){
        printf("Connection cannot be established...\n");
        return 1;
    }

    // Start receiving
    while(num_of_times_received != TARGET_NUM_FILES_RECEIVED){
        string name_of_current_file = tcp_client.receive_name();
        void* current_writting_location;
        long current_writting_location_size;
        printf("Got new file name: %s\n", name_of_current_file.c_str());
        memset(msg_buf, 0, size_of_msg_buf);
        memcpy(msg_buf, "ready", 5);
        send_message(msg_buf, size_of_msg_buf);
        if(name_of_current_file == "cert"){

            size_of_ias_cert = tcp_client.receive_size_of_data();

            ias_cert = (char*) malloc(size_of_ias_cert);
            current_writting_location_size = size_of_ias_cert;
            current_writting_location = ias_cert;

        } else if (name_of_current_file == "vid"){

            vid_buf_len = tcp_client.receive_size_of_data();
            
            vid_buf = (char*) malloc(vid_buf_len);
            current_writting_location_size = vid_buf_len;
            current_writting_location = vid_buf;

        } else if (name_of_current_file == "meta"){
            
            md_json_len = tcp_client.receive_size_of_data();
            
            md_json = (char*) malloc(md_json_len);
            current_writting_location_size = md_json_len;
            current_writting_location = md_json;

        } else if (name_of_current_file == "sig"){
            
            raw_signature_length = tcp_client.receive_size_of_data();
            
            raw_signature = (char*) malloc(raw_signature_length);
            current_writting_location_size = raw_signature_length;
            current_writting_location = raw_signature;

        } else {
            printf("Received invalid file name: [%s]\n", name_of_current_file);
            return 1;
        }

        memset(msg_buf, 0, size_of_msg_buf);
        memcpy(msg_buf, "ready", 5);
        send_message(msg_buf, size_of_msg_buf);

        printf("Going to try receive data for size: %ld\n", current_writting_location_size);
        try_receive_something(current_writting_location, current_writting_location_size);
        ++num_of_times_received;
    }

    printf("All files received, going to try save to local...\n");

    // Save cert
    char* cert_file_name = argv[3];
    FILE* cert_file = fopen(cert_file_name, "wb");
    fwrite(ias_cert, size_of_ias_cert, 1, cert_file);
    fclose(cert_file);

    // Save vid
    char* vid_file_name = argv[4];
    FILE* vid_file = fopen(vid_file_name, "wb");
    fwrite(vid_buf, vid_buf_len, 1, vid_file);
    fclose(vid_file);

    // Save metadata
    char* md_file_name = argv[5];
    FILE* md_file = fopen(md_file_name, "wb");
    fwrite(md_json, md_json_len, 1, md_file);
    fclose(md_file);

    // Save signature
    char* sig_file_name = argv[6];
    FILE* sig_file = fopen(sig_file_name, "wb");
    fwrite(raw_signature, raw_signature_length, 1, sig_file);
    fclose(sig_file);


    printf("All files saved successfully...\n");

    free(ias_cert);
    free(vid_buf);
    free(md_json);
    free(raw_signature);

    return 0;
}