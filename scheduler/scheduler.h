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

# define MAX_PATH FILENAME_MAX
# define SIZEOFHASH 256
# define SIZEOFSIGN 512
# define SIZEOFPUKEY 2048
# define TARGET_NUM_TIMES_RECEIVED 4
# define TARGET_NUM_FILES_RECEIVED 1

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

#include "common/metadata.h"
#include "common/basetype.h"

// For TCP module
#include <ctime>
#include <cerrno>
#include <cstring>
#include "tcp_module/TCPServer.h"
#include "tcp_module/TCPClient.h"

typedef struct workflow {
    pthread_t* decoder, *encoder;
    pthread_t** filters;
    int num_of_filters;
} workflow;

typedef struct decoder_args {
    char* path_of_cam_vender_pubkey;
    int incoming_port;
    char* outgoing_ip_addr;
    int outgoing_port;
} decoder_args;

typedef struct filter_args {
    char* filter_name;
    int incoming_port;
    char* outgoing_ip_addr;
    int outgoing_port;
} filter_args;

typedef struct encoder_args {
    int incoming_port;
    int outgoing_port;
} encoder_args;

// For TCP module
TCPServer tcp_server;
TCPServer tcp_server_for_decoder;
TCPClient tcp_client;
pthread_t msg1[MAX_CLIENT];
int num_message = 0;
int time_send   = 1;
int num_of_times_received = 0;

// For receiving data
long contentSize = 0;
u8* contentBuffer = NULL;
long camera_cert_len = 0;
char* camera_cert = NULL;
long vid_sig_buf_length = 0;
char* vid_sig_buf = NULL;
long md_json_len = 0;
char* md_json = NULL;

using namespace std;

#include <chrono> 
using namespace std::chrono;

// For evaluation
ofstream eval_file;
ofstream alt_eval_file;

// To-Do: manage all workflows instead of detaching
int current_num_of_workflows = 0;
workflow** workflows = NULL;
pthread_mutex_t lock_4_workflows;

// To-Do: should manage all workflows dynamically so that we know which ports are free
int self_server_port_marker = 10112;
int encoder_outgoing_port_marker = 41234;   // Reason we have this seperately is Azure currently only have 10111(used by scheduler) and 41234 opened...

// Declare functions as needed
void free_all_workflows();
void send_cancel_request_to_all_workflows();


