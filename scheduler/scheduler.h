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
#include <utility>

#include <time.h> /* for time() and ctime() */

#include "common/metadata.h"
#include "common/basetype.h"

// For TCP module
#include <ctime>
#include <cerrno>
#include <cstring>
#include "tcp_module/TCPServer.h"
#include "tcp_module/TCPClient.h"

typedef struct incoming_data {
    long contentSize = 0;
    u8* contentBuffer = NULL;
    long camera_cert_len = 0;
    char* camera_cert = NULL;
    long vid_sig_buf_length = 0;
    char* vid_sig_buf = NULL;
    long md_json_len = 0;
    char* md_json = NULL;
    pthread_mutex_t individual_access_lock;
} incoming_data;

typedef struct decoder_args {
    // char* path_of_cam_vender_pubkey;
    int incoming_port;
    char* outgoing_ip_addr;
    int outgoing_port;
} decoder_args;

typedef struct decoder_in_pool {
    string ip_addr;
    int incoming_port;
    pthread_t* decoder;
} decoder_in_pool;

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

typedef struct helper_scheduler_info {
    string ip_addr;
    int id_in_current_connection;
    int type = 0;   // TO-DO: use type to dynamically distribute work to different helper_scheduler
    int current_num_of_work = 0;
    pthread_mutex_t individual_access_lock;
} helper_scheduler_info;

typedef struct pre_workflow {
    int incoming_source;
    incoming_data *in_data;
    metadata* md;
    int is_filter_bundle_detected = 0;
} pre_workflow;

typedef struct workflow {
    pthread_t* decoder, *encoder;
    pthread_t** filters;
    int num_of_filters;
} workflow;

// For TCP module
TCPServer tcp_server;
TCPServer tcp_server_for_scheduler_helper;
TCPServer tcp_server_for_decoder;
TCPClient tcp_client;
pthread_t msg1[MAX_CLIENT];
int num_message = 0;
int time_send   = 1;
int num_of_times_received = 0;

// For receiving data
// long contentSize = 0;
// u8* contentBuffer = NULL;
// long camera_cert_len = 0;
// char* camera_cert = NULL;
// long vid_sig_buf_length = 0;
// char* vid_sig_buf = NULL;
// long md_json_len = 0;
// char* md_json = NULL;

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
int main_scheduler_report_port = 10111; // This port is used for helper scheduler to report to be controlled by main scheduler
int self_server_port_marker = 10113;
int encoder_outgoing_port_marker = 41231;   // Reason we have this seperately is Azure currently only have 10111(used by scheduler) and 41234 opened...

// For filter-bundle test only
int is_filter_bundle_detected = 0;
int self_server_port_marker_extra = 20112;
int num_of_filter_in_bundle = 6;

// For mode that current scheduler is running at
int current_scheduler_mode = 0; // 0 is main, 1 is pool of scheduler_helper

// For maintaining pool of scheduler (in helper mode)
pthread_t helper_scheduler_accepter;
vector<helper_scheduler_info*> helper_scheduler_pool;

// For settings of maintaining pool
#define NUM_OF_DECODER_IN_POOL 1

// For maintaining pool of resources
int num_of_free_decoder = 0;
vector<pair<string, int>*> decoder_pool;  // in format (ip, port)
pthread_mutex_t decoder_pool_access_lock;

// For global mutexes
pthread_mutex_t workflow_access_lock;
pthread_mutex_t helper_scheduler_pool_access_lock;
// pthread_mutex_t decoder_pool_access_lock;

// Declare functions as needed
void free_all_workflows();
void free_all_helper_scheduler_info();
void send_cancel_request_to_all_workflows();
void free_incoming_data(incoming_data *in_data_to_be_freed);
void free_pre_workflow(pre_workflow *p_workflow_to_be_freed);
void free_helper_scheduler_info(helper_scheduler_info *hs_info_to_be_freed);


