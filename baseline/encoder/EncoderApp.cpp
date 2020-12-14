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
// #include <pthread.h>

# define MAX_PATH FILENAME_MAX
# define TARGET_NUM_FILES_RECEIVED 2

#include "EncoderApp.h"

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h> /* gettimeofday() */
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "minih264e.h"
#include "../common/metadata.h"
#include <math.h>
#include "yuvconverter.h"

#include <time.h> /* for time() and ctime() */

// For TCP module
#include <ctime>
#include <cerrno>
#include <cstring>
#include "../tcp_module/TCPServer.h"
#include "../tcp_module/TCPClient.h"

// For Multi Incoming Client
// #include <cmath>        // std::abs
int total_num_of_incoming_sources = 1;
int current_communicating_incoming_source = 0;
int current_encoding_frame_client_id = -1;
int current_receiving_frame_num = -1;    // Start with -1, where -1 means ias cert

using namespace std;

#include <chrono> 
using namespace std::chrono;

/* Encoder Related definitions and variables */
#define DEFAULT_GOP 20
#define DEFAULT_QP 33
#define DEFAULT_DENOISE 0
#define DEFAULT_FPS 30
#define DEFAULT_IS_YUYV 0
#define DEFAULT_IS_RGB 0

#define ENABLE_TEMPORAL_SCALABILITY 0
#define MAX_LONG_TERM_FRAMES        8 // used only if ENABLE_TEMPORAL_SCALABILITY==1

#define DEFAULT_MAX_FRAMES  99999

typedef struct
{
    int gen, gop, qp, kbps, max_frames, threads, speed, denoise, stats, psnr, fps, is_yuyv, is_rgb, is_input_multi;
} cmdline;

// PSNR estimation results
typedef struct
{
    double psnr[4];             // PSNR, db
    double kpbs_30fps;          // bitrate, kbps, assuming 30 fps
    double psnr_to_logkbps_ratio;  // cumulative quality metric
    double psnr_to_kbps_ratio;  // another variant of cumulative quality metric
} rd_t;

static struct
{
    // Y,U,V,Y+U+V
    double noise[4];
    double count[4];
    double bytes;
    int frames;
} g_psnr;

H264E_persist_t *enc;
H264E_scratch_t *scratch;
H264E_create_param_t create_param;
H264E_run_param_t run_param;
H264E_io_yuv_t yuv;
H264E_io_yuy2_t yuyv;
uint8_t *buf_in, *buf_save;
uint8_t *yuyv_buf_in, *temp_buf_in, *p;
uint8_t *coded_data, *all_coded_data;
char *input_file, *output_file, *input_file_sig, *output_file_sig, *in_cert_file, *out_cert_file, *in_md_file, *out_md_file;
int sizeof_coded_data, _qp;
int frame_counter;
size_t total_coded_data_size;
unsigned char* total_coded_data;
cmdline *cl;

// TCP Related parameters
int incoming_port = 0;
int port_for_viewer = 0;
TCPServer tcp_server;
TCPServer tcp_server_for_viewer;
pthread_t msg1[MAX_CLIENT];
int num_message = 0;
int time_send   = 1;
int num_of_times_received = 0;
int size_of_msg_buf = 100;
char* msg_buf;

// For incoming data
long md_json_len_i = 0;
char* md_json_i = NULL;
long raw_frame_buf_len_i = 0;
char* raw_frame_buf_i = NULL;

// For incoming data being processed (Cache of incoming data)
long md_json_len = 0;
char* md_json = NULL;
long raw_frame_buf_len = 0;
char* raw_frame_buf = NULL;

// For Outgoing Data
size_t potential_out_md_json_len = -1;

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


void log_request_arrive(uint32_t *ntp_time)
{
	time_t t; 

	if (ntp_time) {
		t = *ntp_time - UTC_NTP;
	} else {
		t = time(NULL);
	}
	printf("[encoder]: A request comes at: %s", ctime(&t));
}


void log_ntp_event(char *msg)
{
	puts(msg);
}

static rd_t psnr_get()
{
    int i;
    rd_t rd;
    double fps = 30;    // Modified for adjusting fps output (Note that this is just for psnr output)
    double realkbps = g_psnr.bytes*8./((double)g_psnr.frames/(fps))/1000;
    double db = 10*log10(255.*255/(g_psnr.noise[0]/g_psnr.count[0]));
    for (i = 0; i < 4; i++)
    {
        rd.psnr[i] = 10*log10(255.*255/(g_psnr.noise[i]/g_psnr.count[i]));
    }
    rd.psnr_to_kbps_ratio = 10*log10((double)g_psnr.count[0]*g_psnr.count[0]*3/2 * 255*255/(g_psnr.noise[0] * g_psnr.bytes));
    rd.psnr_to_logkbps_ratio = db / log10(realkbps);
    rd.kpbs_30fps = realkbps;
    return rd;
}

static void psnr_init()
{
    memset(&g_psnr, 0, sizeof(g_psnr));
}

static void psnr_add(unsigned char *p0, unsigned char *p1, int w, int h, int bytes)
{
    int i, k;
    for (k = 0; k < 3; k++)
    {
        double s = 0;
        for (i = 0; i < w*h; i++)
        {
            int d = *p0++ - *p1++;
            s += d*d;
        }
        g_psnr.count[k] += w*h;
        g_psnr.noise[k] += s;
        if (!k) w >>= 1, h >>= 1;
    }
    g_psnr.count[3] = g_psnr.count[0] + g_psnr.count[1] + g_psnr.count[2];
    g_psnr.noise[3] = g_psnr.noise[0] + g_psnr.noise[1] + g_psnr.noise[2];
    g_psnr.frames++;
    g_psnr.bytes += bytes;
}

static void psnr_print(rd_t rd)
{
    int i;
    printf("[encoder]: %5.0f kbps@30fps  ", rd.kpbs_30fps);
    for (i = 0; i < 3; i++)
    {
        //printf("[encoder]:   %.2f db ", rd.psnr[i]);
        printf("[encoder]:  %s=%.2f db ", i ? (i == 1 ? "UPSNR" : "VPSNR") : "YPSNR", rd.psnr[i]);
    }
    printf("[encoder]:   %6.2f db/rate ", rd.psnr_to_kbps_ratio);
    printf("[encoder]:   %6.3f db/lgrate ", rd.psnr_to_logkbps_ratio);
    printf("[encoder]:   \n");
}

static int str_equal(const char *pattern, char **p)
{
    if (!strncmp(pattern, *p, strlen(pattern)))
    {
        *p += strlen(pattern);
        return 1;
    } else
    {
        return 0;
    }
}

static int read_cmdline_options(int argc, char *argv[])
{
    int i;
    input_file = NULL;
    output_file = NULL;
    cl = (cmdline*)malloc(sizeof(cmdline));
    memset(cl, 0, sizeof(cmdline));
    cl->gop = DEFAULT_GOP;
    cl->qp = DEFAULT_QP;
    cl->max_frames = DEFAULT_MAX_FRAMES;
    cl->kbps = 0;
    //cl->kbps = 2048;
    cl->denoise = DEFAULT_DENOISE;
    cl->fps = DEFAULT_FPS;
    cl->is_yuyv = DEFAULT_IS_YUYV;
    cl->is_rgb = DEFAULT_IS_RGB;
    for (i = 1; i < argc; i++)
    {
        char *p = argv[i];
        if (*p == '-')
        {
            p++;
            if (str_equal(("gen"), &p))
            {
                cl->gen = 1;
            } else if (str_equal(("gop"), &p))
            {
                cl->gop = atoi(p);
            } else if (str_equal(("qp"), &p))
            {
                cl->qp = atoi(p);
            } else if (str_equal(("kbps"), &p))
            {
                cl->kbps = atoi(p);
            } else if (str_equal(("maxframes"), &p))
            {
                cl->max_frames = atoi(p);
            } else if (str_equal(("threads"), &p))
            {
                cl->threads = atoi(p);
            } else if (str_equal(("speed"), &p))
            {
                cl->speed = atoi(p);
            } else if (str_equal(("denoise"), &p))
            {
                cl->denoise = 1;
            } else if (str_equal(("stats"), &p))
            {
                cl->stats = 1;
            } else if (str_equal(("psnr"), &p))
            {
                cl->psnr = 1;
            } else if (str_equal(("fps"), &p))
            {
                cl->fps = atoi(p);
            } else if (str_equal(("is_yuyv"), &p))
            {
                cl->is_yuyv = 1;
            } else if (str_equal(("is_rgb"), &p))
            {
                cl->is_rgb = 1;
            } else if (str_equal(("multi_in"), &p))
            {
                total_num_of_incoming_sources = atoi(p);
            } else
            {
                printf("[encoder]: ERROR: Unknown option %s\n", p - 1);
                return 0;
            }
        } else if (!incoming_port && !cl->gen)
        {
            incoming_port = atoi(p);
        } else if (!port_for_viewer)
        {
            port_for_viewer = atoi(p);
        } else
        {
            printf("[encoder]: ERROR: Unknown option %s\n", p);
            return 0;
        }
    }
    if (!incoming_port && !cl->gen)
    {
        printf("[encoder]: Usage:\n"
               "    encoder [options] <incoming_port> <port_for_viewer>\n"
               "Frame size can be: WxH sqcif qvga svga 4vga sxga xga vga qcif 4cif\n"
               "    4sif cif sif pal ntsc d1 16cif 16sif 720p 4SVGA 4XGA 16VGA 16VGA\n"
               "Options:\n"
               "    -gen            - generate input instead of passing <input.yuv>\n"
               "    -qop<n>         - key frame period >= 0\n"
               "    -qp<n>          - set QP [10..51]\n"
               "    -kbps<n>        - set bitrate (fps=30 assumed)\n"
               "    -maxframes<n>   - encode no more than given number of frames\n"
               "    -threads<n>     - use <n> threads for encode\n"
               "    -speed<n>       - speed [0..10], 0 means best quality\n"
               "    -denoise        - use temporal noise supression\n"
               "    -stats          - print frame statistics\n"
               "    -psnr           - print psnr statistics\n"
               "    -fps<n>         - set target fps of the video, default is 30\n"
               "    -is_yuyv        - if the frames' chroma is in yuyv 4:2:2 packed format(note that psnr might not work when using yuyv)\n"
               "    -is_rgb         - if the frames' chroma is in rgb packed format(note that psnr might not work when using rgb)\n"
               "    -multi_in<n>    - set num of incoming sources(polling)\n");
        return 0;
    }
    return 1;
}

typedef struct
{
    const char *size_name;
    int g_w;
    int h;
} frame_size_descriptor_t;

static const frame_size_descriptor_t g_frame_size_descriptor[] =
{
    {"sqcif",  128,   96},
    { "qvga",  320,  240},
    { "svga",  800,  600},
    { "4vga", 1280,  960},
    { "sxga", 1280, 1024},
    {  "xga", 1024,  768},
    {  "vga",  640,  480},
    { "qcif",  176,  144},
    { "4cif",  704,  576},
    { "4sif",  704,  480},
    {  "cif",  352,  288},
    {  "sif",  352,  240},
    {  "pal",  720,  576},
    { "ntsc",  720,  480},
    {   "d1",  720,  480},
    {"16cif", 1408, 1152},
    {"16sif", 1408,  960},
    { "720p", 1280,  720},
    {"4SVGA", 1600, 1200},
    { "4XGA", 2048, 1536},
    {"16VGA", 2560, 1920},
    {"16VGA", 2560, 1920},
    {NULL, 0, 0},
};

/**
*   Guess image size specification from ASCII string.
*   If string have several specs, only last one taken.
*   Spec may look like "352x288" or "qcif", "cif", etc.
*/
static int guess_format_from_name(const char *file_name, int *w, int *h)
{
    int i = (int)strlen(file_name);
    int found = 0;
    while(--i >= 0)
    {
        const frame_size_descriptor_t *fmt = g_frame_size_descriptor;
        const char *p = file_name + i;
        int prev_found = found;
        found = 0;
        if (*p >= '0' && *p <= '9')
        {
            char * end;
            int width = strtoul(p, &end, 10);
            if (width && (*end == 'x' || *end == 'X') && (end[1] >= '1' && end[1] <= '9'))
            {
                int height = strtoul(end + 1, &end, 10);
                if (height)
                {
                    *w = width;
                    *h = height;
                    found = 1;
                }
            }
        }
        do
        {
            if (!strncmp(file_name + i, fmt->size_name, strlen(fmt->size_name)))
            {
                *w = fmt->g_w;
                *h = fmt->h;
                found = 1;
            }
        } while((++fmt)->size_name);

        if (!found && prev_found)
        {
            return prev_found;
        }
    }
    return found;
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

    // printf("[encoder]: When reading {%s}, the str_len is: %d, the very last char is: %c\n", file_name, *str_len, str_to_return[*str_len - 2]);

    str_to_return[*str_len - 1] = '\0';

    fclose(file);

    return str_to_return;
}

void wait_wrapper(int s)
{
	wait(&s);
}

void close_app(int signum) {
	printf("[encoder]: There is a SIGINT error happened...exiting......(%d)\n", signum);
    tcp_server.closed();
    tcp_server_for_viewer.closed();
	exit(0);
}

void * received(void * m)
{
    // Return 0 on success; otherwise, return 1;
    // Make sure we only run on thread of this function

    // pthread_detach(pthread_self());
    int *result_to_return = (int*)malloc(sizeof(int));
    *result_to_return = 0;

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

    // Check if incoming frame is correct
    if(total_num_of_incoming_sources > 1){
        int is_correct_frame_detected = 0;
        for(int i = 0; i < total_num_of_incoming_sources; ++i){
            // printf("[encoder]: Trying to see if we are receiving correct frame with incoming source: (%d)...\n", current_communicating_incoming_source);
            string rec_frame_id = tcp_server.receive_name_with_id(current_communicating_incoming_source);
            // printf("[encoder]: Got rec_frame_id: (%s), where the correct one should be (%d)...\n", rec_frame_id.c_str(), current_receiving_frame_num);
            if(current_receiving_frame_num != atoi(rec_frame_id.c_str())){
                memset(reply_msg, 0, size_of_reply);
                memcpy(reply_msg, "wrong", 5);
                tcp_server.Send(reply_msg, size_of_reply, current_communicating_incoming_source);
                current_communicating_incoming_source = (current_communicating_incoming_source + 1) % total_num_of_incoming_sources;
                continue;
            }
            memset(reply_msg, 0, size_of_reply);
            memcpy(reply_msg, "ready", 5);
            tcp_server.Send(reply_msg, size_of_reply, current_communicating_incoming_source);
            is_correct_frame_detected = 1;
            break;
        }
        if(!is_correct_frame_detected){
            *result_to_return = 1;
            return result_to_return;
        }
    }

    // printf("[encoder]: Successfully pass frame_id verification, going to start receiving real data...\n");

	while(num_of_files_received < TARGET_NUM_FILES_RECEIVED)
	{
        // printf("[encoder]: current_mode is: %d, with remaining size: %ld\n", current_mode, remaining_file_size);
        if(current_mode == 0){
            string file_name = tcp_server.receive_name_with_id(current_communicating_incoming_source);
            // printf("[encoder]: Got new file_name: %s\n", file_name.c_str());
            if(file_name == "frame"){
                current_file_indicator = 0;
                current_writing_size = &raw_frame_buf_len_i;
            } else if (file_name == "meta"){
                current_file_indicator = 1;
                current_writing_size = &md_json_len_i;
            } else {
                printf("[encoder]: The file_name is not valid: %s\n", file_name.c_str());
                free(reply_msg);
                return result_to_return;
            }
            current_mode = 1;
        } else if (current_mode == 1){
            *current_writing_size = tcp_server.receive_size_of_data_with_id(current_communicating_incoming_source);
            remaining_file_size = *current_writing_size;
            // printf("[encoder]: File size got: %ld, which should be equal to: %ld\n", remaining_file_size, *current_writing_size);
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
                    return result_to_return;
            }
            current_mode = 2;
        } else {
            if(remaining_file_size > SIZEOFPACKAGE_HIGH){
                // printf("!!!!!!!!!!!!!!!!!!!Going to write data to current file location: %d\n", current_file_indicator);
                temp_buf = tcp_server.receive_exact_with_id(SIZEOFPACKAGE_HIGH, current_communicating_incoming_source);
                memcpy(current_writing_location, temp_buf, SIZEOFPACKAGE_HIGH);
                current_writing_location += SIZEOFPACKAGE_HIGH;
                remaining_file_size -= SIZEOFPACKAGE_HIGH;
            } else {
                // printf("!!!!!!!!!!!!!!!!!!!Last write to the current file location: %d\n", current_file_indicator);
                temp_buf = tcp_server.receive_exact_with_id(remaining_file_size, current_communicating_incoming_source);
                memcpy(current_writing_location, temp_buf, remaining_file_size);
                remaining_file_size = 0;
                current_mode = 0;
                ++num_of_files_received;
                // printf("num_of_files_received: %d\n", num_of_files_received);
            }
        }
        memset(reply_msg, 0, size_of_reply);
        memcpy(reply_msg, "ready", 5);
        tcp_server.Send(reply_msg, size_of_reply, current_communicating_incoming_source);
	}
    free(reply_msg);
    ++current_receiving_frame_num;
    current_communicating_incoming_source = (current_communicating_incoming_source + 1) % total_num_of_incoming_sources;
	return result_to_return;
}

int send_buffer_to_viewer(void* buffer, long buffer_lenth){
    // Return 0 on success, return 1 on failure

	// Send size of buffer
	// printf("Sending buffer size: %d\n", buffer_lenth);
	tcp_server_for_viewer.send_to_last_connected_client(&buffer_lenth, sizeof(long));
    // printf("Going to wait for receive...\n");
	string rec = tcp_server_for_viewer.receive_name();
    // printf("Going to wait for receive(finished)...\n");
	if( rec != "" )
	{
		// cout << rec << endl;
	}

    long remaining_size_of_buffer = buffer_lenth;
    char* temp_buffer = (char*)buffer;
    int is_finished = 0;

    // printf("[encoder]: Going to start sending buffer...\n");

	while(1)
	{
        if(remaining_size_of_buffer > SIZEOFPACKAGE){
		    tcp_server_for_viewer.send_to_last_connected_client(temp_buffer, SIZEOFPACKAGE);
            remaining_size_of_buffer -= SIZEOFPACKAGE;
            temp_buffer += SIZEOFPACKAGE;
        } else {
		    tcp_server_for_viewer.send_to_last_connected_client(temp_buffer, remaining_size_of_buffer);
            remaining_size_of_buffer = 0;
            is_finished = 1;
        }
        // printf("[encoder]: (inside)Going to wait for receive...just send buffer with size: %d\n", remaining_size_of_buffer);
		string rec = tcp_server_for_viewer.receive_name();
        // printf("[encoder]: (inside)Going to wait for receive(finished)...\n");
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

void cache_incoming_frame_info(){
    // Make sure when we run this function, the receiving thread is not running at the same time
    md_json_len = md_json_len_i;
    md_json = (char*) malloc(md_json_len * sizeof(char));
    memcpy(md_json, md_json_i, md_json_len);
    free(md_json_i);

    raw_frame_buf_len = raw_frame_buf_len_i;
    raw_frame_buf = (char*) malloc((raw_frame_buf_len + 1) * sizeof(char));
    memcpy(raw_frame_buf, raw_frame_buf_i, raw_frame_buf_len);
    free(raw_frame_buf_i); // this is causing segmentation fault in encoder

    if(current_communicating_incoming_source == 0){
        current_encoding_frame_client_id = total_num_of_incoming_sources - 1;
    } else {
        current_encoding_frame_client_id = (current_communicating_incoming_source - 1) % total_num_of_incoming_sources;  // -1 since we already +1 in received
    }
}

int encoder_init(metadata* md, size_t frame_size)
{
    int g_h = md->height;
    int g_w = md->width;

    create_param.enableNEON = 1;
#if H264E_SVC_API
    create_param.num_layers = 1;
    create_param.inter_layer_pred_flag = 1;
    create_param.inter_layer_pred_flag = 0;
#endif
    create_param.gop = cl->gop;
    create_param.height = g_h;
    create_param.width  = g_w;
    create_param.max_long_term_reference_frames = 0;
#if ENABLE_TEMPORAL_SCALABILITY
    create_param.max_long_term_reference_frames = MAX_LONG_TERM_FRAMES;
#endif
    create_param.fine_rate_control_flag = 0;
    create_param.const_input_flag = cl->psnr ? 0 : 1;
    create_param.vbv_size_bytes = 100000/8;
    create_param.temporal_denoise_flag = cl->denoise;

    // Allocate space for yuv420 (the one used for actually process data)
    buf_in   = (uint8_t*)malloc(frame_size);
    memset(buf_in, 0, frame_size);
    buf_save = (uint8_t*)malloc(frame_size);
    memset(buf_save, 0, frame_size);

    // If yuyv frames are used, allocate space for both the src and temp space for converting chroma format
    if(cl->is_yuyv){
        // Allocate space for temp space
        int temp_frame_size = g_w * g_h * 2;
        temp_buf_in = (uint8_t*)malloc(temp_frame_size * sizeof(uint8_t));
        memset(temp_buf_in, 0, temp_frame_size);
        // printf("[encoder]: yuyv detected\n");
    }

    // If rgb frames are used, allocate space for both the src and temp space for converting chroma format
    if(cl->is_rgb){
        // Init rgbToYuv conversion
        InitConvt(g_w, g_h);
    }

    if (!buf_in || !buf_save)
    {
        printf("[encoder]: ERROR: not enough memory\n");
        return 1;
    }
    enc = NULL;
    scratch = NULL;
    total_coded_data = NULL;
    total_coded_data_size = 0;
    int sizeof_persist = 0, sizeof_scratch = 0, error;
    if (cl->psnr)
        psnr_init();

    error = H264E_sizeof(&create_param, &sizeof_persist, &sizeof_scratch);
    if (error)
    {
        printf("[encoder]: H264E_sizeof error = %d\n", error);
        return 1;
    }
    enc     = (H264E_persist_t *)malloc(sizeof_persist);
    memset(enc, 0, sizeof_persist);
    scratch = (H264E_scratch_t *)malloc(sizeof_scratch);
    memset(scratch, 0, sizeof_scratch);
    error = H264E_init(enc, &create_param);
    if (error)
    {
        printf("[encoder]: H264E_init error = %d\n", error);
        return 1;
    }
    return 0;
}

int encode_frame(uint8_t* frame, size_t frame_size,
                 metadata* md, size_t client_id)
{
    int fps = md->frame_rate;
    int g_w = md->width;
    int g_h = md->height;
    int res = -1;
    frame_counter++;
    // Encode frame
    if (cl->is_yuyv) {
        p = frame;   // Record head adddress

        // temp conversion address
        yuyv.Y = temp_buf_in;
        yuyv.U = yuyv.Y + g_w * g_h;
        yuyv.V = yuyv.U + (g_w * g_h >> 1);   // Y  U  V  =4 : 2 ; 2

        // final incoming yuv data address
        yuv.yuv[0] = buf_in; yuv.stride[0] = g_w;
        yuv.yuv[1] = buf_in + g_w*g_h; yuv.stride[1] = g_w/2;
        yuv.yuv[2] = buf_in + g_w*g_h*5/4; yuv.stride[2] = g_w/2;

        // yuyv to yuv
        int k, j;
        for (k = 0; k < g_h; ++k)
        {
            for (j = 0; j < (g_w >> 1); ++j)
            {
                yuyv.Y[j * 2] = p[4 * j];
                yuyv.U[j] = p[4 * j + 1];
                yuyv.Y[j * 2 + 1] = p[4 * j + 2];
                yuyv.V[j] = p[4 * j + 3];
            }
            p = p + g_w * 2;

            yuyv.Y = yuyv.Y + g_w;
            yuyv.U = yuyv.U + (g_w >> 1);
            yuyv.V = yuyv.V + (g_w >> 1);
        }
        // Now packed is planar
        // reset
        yuyv.Y = temp_buf_in;
        yuyv.U = yuyv.Y + g_w * g_h;
        yuyv.V = yuyv.U + (g_w * g_h >> 1);

        int l;
        for (l = 0; l < g_h / 2; ++l)
        {
            memcpy(yuv.yuv[1], yuyv.U, g_w >> 1);
            memcpy(yuv.yuv[2], yuyv.V, g_w >> 1);

            yuv.yuv[1] = yuv.yuv[1] + (g_w >> 1);
            yuv.yuv[2] = yuv.yuv[2] + (g_w >> 1);

            yuyv.U = yuyv.U + (g_w);
            yuyv.V = yuyv.V + (g_w);
        }

        memcpy(yuv.yuv[0], yuyv.Y, g_w * g_h);

        // reset
        yuv.yuv[0] = buf_in;
        yuv.yuv[1] = buf_in + g_w*g_h;
        yuv.yuv[2] = buf_in + g_w*g_h*5/4;
    } else if (cl->is_rgb) {
        // printf("[encoder]: Processing rgb frame with frame size: %d...\n", frame_size);
        rgb_packed_to_yuv420_prog_planar(frame, buf_in, g_w, g_h);
        yuv.yuv[0] = buf_in; yuv.stride[0] = g_w;
        yuv.yuv[1] = buf_in + g_w*g_h; yuv.stride[1] = g_w/2;
        yuv.yuv[2] = buf_in + g_w*g_h*5/4; yuv.stride[2] = g_w/2;
    } else {
        buf_in = frame;
        yuv.yuv[0] = buf_in; yuv.stride[0] = g_w;
        yuv.yuv[1] = buf_in + g_w*g_h; yuv.stride[1] = g_w/2;
        yuv.yuv[2] = buf_in + g_w*g_h*5/4; yuv.stride[2] = g_w/2;
    }

    // For printing psnr
    if (cl->psnr)
        memcpy(buf_save, buf_in, frame_size);

    run_param.frame_type = 0;
    run_param.encode_speed = cl->speed;
    run_param.target_fps = fps;
    //run_param.desired_nalu_bytes = 100;

    if (cl->kbps)
    {
        printf("[encoder]: kbps is set manually to %i\n", cl->kbps);
        run_param.desired_frame_bytes = cl->kbps*1000/8/30;    // Modified for framerates
        run_param.qp_min = 10;
        run_param.qp_max = 50;
    } else
    {
        run_param.qp_min = run_param.qp_max = cl->qp;
    }

#if ENABLE_TEMPORAL_SCALABILITY
    int level, logmod = 1;
    int j, mod = 1 << logmod;
    static int fresh[200] = {-1,-1,-1,-1};

    run_param.frame_type = H264E_FRAME_TYPE_CUSTOM;

    for (level = logmod; level && (~i & (mod >> level)); level--){}

    run_param.long_term_idx_update = level + 1;
    if (level == logmod && logmod > 0)
        run_param.long_term_idx_update = -1;
    if (level == logmod - 1 && logmod > 1)
        run_param.long_term_idx_update = 0;

    //if (run_param.long_term_idx_update > logmod) run_param.long_term_idx_update -= logmod+1;
    //run_param.long_term_idx_update = logmod - 0 - level;
    //if (run_param.long_term_idx_update > 0)
    //{
    //    run_param.long_term_idx_update = logmod - run_param.long_term_idx_update;
    //}
    run_param.long_term_idx_use    = fresh[level];
    for (j = level; j <= logmod; j++)
    {
        fresh[j] = run_param.long_term_idx_update;
    }
    if (!i)
    {
        run_param.long_term_idx_use = -1;
    }
#endif
    res = H264E_encode(enc, scratch, &run_param, &yuv, &coded_data, &sizeof_coded_data);
    if (res)
    {
        printf("[encoder]: encode_frame: ERROR during encoding\n");
        return res;
    }

    if (cl->psnr)
        psnr_add(buf_save, buf_in, g_w, g_h, sizeof_coded_data);

    // Save encoded frame to global variable
    unsigned char* tmp;
    tmp = (unsigned char*)realloc(total_coded_data, (size_t)(total_coded_data_size + sizeof_coded_data));
    if (tmp)
    {
        memset(tmp + total_coded_data_size, 0, sizeof_coded_data);
        memcpy(tmp + total_coded_data_size, coded_data, sizeof_coded_data);
        total_coded_data_size += sizeof_coded_data;
        total_coded_data = tmp;
    }
    else
    {
        printf("[encoder]: encode_frame: ERROR no memory available\n");
        res = -1;
    }

    return res;
}

/* Application entry */
int main(int argc, char *argv[], char **env)
{
    int i = 0, res = -1;

    // Register signal handlers
    std::signal(SIGINT, close_app);
	std::signal(SIGPIPE, sigpipe_handler);

    // Initialize variables
    if (!read_cmdline_options(argc, argv))
        return 1;

    // Check if incoming_port and port_for_viewer are set correctly
    if(incoming_port <= 0 || port_for_viewer <= 0){
        printf("[encoder]: Incoming port: %d or Port for viewer %d is invalid\n", incoming_port, port_for_viewer);
    }
    // printf("[encoder]: Incoming port: %d; Port for viewer %d\n", incoming_port, port_for_viewer);

    // Open file to store evaluation results
    mkdir("../evaluation/eval_result", 0777);
    eval_file.open("../evaluation/eval_result/eval_encoder.csv");
    if (!eval_file.is_open()) {
        printf("Could not open eval file.\n");
        return 1;
    }

    alt_eval_file.open("../evaluation/eval_result/eval_encoder_one_time.csv");
    if (!alt_eval_file.is_open()) {
        printf("Could not open alt_eval_file file.\n");
        return 1;
    }

    // Receive and verify IAS certificate
    pthread_t msg;

    auto start = high_resolution_clock::now();
    
    vector<int> opts = { SO_REUSEPORT, SO_REUSEADDR };

    if( tcp_server.setup(incoming_port,opts) != 0) {
        cerr << "[encoder]: Errore apertura socket" << endl;
    }

    // Receive and verify all ias certs
    for(int i = 0; i < total_num_of_incoming_sources; ++i){
        // printf("[encoder]: Going to wait for a new client to connect...with i: (%d)\n", i);
        int id_for_recv = tcp_server.accepted();
        // cerr << "[encoder]: Accepted with id: " << id_for_recv << " for i: " << i << endl;
        // Manually set current_receiving_frame_num to -1 as currently we only want to receive all ias certs from all filter bundles
        current_receiving_frame_num = 0;
    }
    
    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(stop - start);
    alt_eval_file << duration.count() << ", ";

    // Set up parameters for the case each frame is in a single file
    // Assume there are at most 999 frames
    int max_frames = 999; // Assume there are at most 999 frames
    int max_frame_digits = num_digits(max_frames);

    start = high_resolution_clock::now();
    
    // Receive the very first frame for setting up Encoder
    void *result_of_rec;

    if( pthread_create(&msg, NULL, received, (void *)0) == 0)
    {
        // tcp_server.accepted();
        // cerr << "Accepted" << endl;
        // printf("num_of_times_received: %d\n", num_of_times_received);
        pthread_join(msg, &result_of_rec);
        if(*((int*)result_of_rec) != 0){
            printf("[encoder]: No correct first frame is received...\n");
            return 1;
        }
        free(result_of_rec);
    } else {
        printf("[Encoder]: pthread created failed...\n");
    }

    // Cache the very first frame

    // printf("Going to cache incoming frame info...\n");
    cache_incoming_frame_info();
    // printf("Incoming frame info cached...\n");

    stop = high_resolution_clock::now();
    duration = duration_cast<microseconds>(stop - start);
    alt_eval_file << duration.count() << ", ";
    
    start = high_resolution_clock::now();

    // Initialize variables in host
    // printf("[encoder]: Before parsing metadata, we have it(%ld): [%s]\n", md_json_len, md_json);
    // Parse metadata
    if (md_json[md_json_len - 1] == '\0') md_json_len--;
    if (md_json[md_json_len - 1] == '\0') md_json_len--;
    // printf("[encoder]: md_json(%ld) going to be used is: [%s]\n", md_json_len, md_json);
    metadata* md = json_2_metadata(md_json, md_json_len);
    if (!md) {
        printf("Failed to parse metadata\n");
        return 1;
    }

    // Use metadata to setup some info
    int g_w = md->width, g_h = md->height;
    int frame_size = 0;
    frame_counter = 0;
    if (cl->is_yuyv) {
        frame_size = g_w * g_h * 2;
    }
    else if (cl->is_rgb) {
        frame_size = g_w * g_h * 3;
    }
    else {
        frame_size = g_w * g_h * 3/2;
    }
    int total_frames = md->total_frames;
    md_json_len = md_json_len + 48 - 17;  // - 17 because of loss of frame_id; TO-DO: make this flexible (Get size dynamically)
    // printf("[encoder]: total_frames: %d\n", total_frames);
    // printf("[encoder]: potential_out_md_json_len: %d\n", potential_out_md_json_len);

    // Try continue receiving next frame
    if(total_frames > 1 && pthread_create(&msg, NULL, received, (void *)0) != 0)
    {
        printf("[Encoder]: pthread created failed for continuing receiving next frame after first frame...\n");
        return 1;
    }

    // Parse frame
    uint8_t* frame = (uint8_t*)raw_frame_buf;

    // Free frame raw
    // free(raw_frame_buf);
    raw_frame_buf = NULL;
    raw_frame_buf_len = 0;

    // Initialize variables
    res = encoder_init(md, frame_size);

    stop = high_resolution_clock::now();
    duration = duration_cast<microseconds>(stop - start);
    alt_eval_file << duration.count() << ", ";
    
    // printf("[encoder]: Going to encode frame 0\n");
    
    start = high_resolution_clock::now();

    // Instead, we encode the very first frame now
    res = encode_frame(frame, frame_size,
                       md, current_encoding_frame_client_id);
    free_metadata(md);
    
    stop = high_resolution_clock::now();
    duration = duration_cast<microseconds>(stop - start);
    alt_eval_file << duration.count() << ", ";

    // printf("[encoder]: Going to encode remaining frames...\n");

    // Encode frames
    for (i = 1; i < total_frames; i++)
    {
        // printf("[encoder]: Going to receive and encode frame %d\n", i);

        start = high_resolution_clock::now();

        // Make sure we already successfully receive the frame
        ++num_of_times_received;
        // printf("[encoder]: num_of_times_received: %d\n", num_of_times_received);
        void *result_of_rec;
        pthread_join(msg, &result_of_rec);
        // printf("[encoder]: the frame is truly received...\n");

        if(*((int*)result_of_rec) != 0){
            printf("[encoder]: No correct first frame is received...\n");
            return 1;
        }
        free(result_of_rec);

        stop = high_resolution_clock::now();
        duration = duration_cast<microseconds>(stop - start);
        eval_file << duration.count() << ", ";

        start = high_resolution_clock::now();
        
        // Cache this frame
        cache_incoming_frame_info();

        stop = high_resolution_clock::now();
        duration = duration_cast<microseconds>(stop - start);
        eval_file << duration.count() << ", ";

        // Continue receiving next frame
        if(i + 1 < total_frames && pthread_create(&msg, NULL, received, (void *)0) != 0)
        {
            printf("pthread created failed for receiving next frame...\n");
            return 1;
        }
        
        start = high_resolution_clock::now();

        // Parse frame
        // memset(frame, 0, frame_size);
        // memcpy(frame, raw_frame_buf, raw_frame_buf_len);
        frame = (uint8_t*)raw_frame_buf;

        // Free frame raw
        // free(raw_frame_buf);
        raw_frame_buf = NULL;
        raw_frame_buf_len = 0;

        stop = high_resolution_clock::now();
        duration = duration_cast<microseconds>(stop - start);
        eval_file << duration.count() << ", ";
        
        start = high_resolution_clock::now();

        // printf("[encoder]: Going to encode frame with client_id: (%d)...\n", current_encoding_frame_client_id);

        // Encode frame in enclave
        metadata* md = json_2_metadata(md_json, md_json_len);
        if (!md) {
            printf("[encoder]: Failed to parse metadata\n");
            return 1;
        }
        res = encode_frame(frame, frame_size,
                           md, current_encoding_frame_client_id);
        free_metadata(md);

        // printf("[encoder]: A frame has been successfully encoded...\n");
        
        stop = high_resolution_clock::now();
        duration = duration_cast<microseconds>(stop - start);
        eval_file << duration.count() << endl;
    }

    // More clean up
    delete frame;

    tcp_server.closed();

    // printf("[encoder]: Encoding completed...going to try sending frames\n");

    // declaring argument of time() 
    time_t my_time = time(NULL); 
  
    // ctime() used to give the present time 
    printf("[encoder]: Encoding completed at: %s", ctime(&my_time));

    if( tcp_server_for_viewer.setup(port_for_viewer,opts) == 0) {
        printf("[encoder]: Ready for viewer to connect...\n");
        tcp_server_for_viewer.accepted();
        cerr << "[encoder]: Accepted viewer" << endl;
    }
    else
        cerr << "[encoder]: Errore apertura socket" << endl;

    // Init msg_buf
    string msg_reply_from_viewer;
    msg_buf = (char*) malloc(size_of_msg_buf);
    
    start = high_resolution_clock::now();

    // Send encoded video
    memset(msg_buf, 0, size_of_msg_buf);
    memcpy(msg_buf, "vid", 3);
    tcp_server_for_viewer.send_to_last_connected_client(msg_buf, size_of_msg_buf);
    msg_reply_from_viewer = tcp_server_for_viewer.receive_name();
    if(msg_reply_from_viewer != "ready"){
        printf("No ready received from viewer but: %s\n", msg_reply_from_viewer.c_str());
        return 1;
    }

    send_buffer_to_viewer(total_coded_data, total_coded_data_size);

    stop = high_resolution_clock::now();
    duration = duration_cast<microseconds>(stop - start);
    alt_eval_file << duration.count() << ", ";

    delete total_coded_data;

    start = high_resolution_clock::now();

    // Send metadata
    if (cl->stats)
    {
        printf ("[encoder]: out_metadata: %s\n", md_json);
    }

    // printf("[encoder]: Going to send metadata(%d): [%s]\n", potential_out_md_json_len, out_md_json);

    memset(msg_buf, 0, size_of_msg_buf);
    memcpy(msg_buf, "meta", 4);
    tcp_server_for_viewer.send_to_last_connected_client(msg_buf, size_of_msg_buf);
    msg_reply_from_viewer = tcp_server_for_viewer.receive_name();
    if(msg_reply_from_viewer != "ready"){
        printf("[encoder]: No ready received from viewer but: %s\n", msg_reply_from_viewer.c_str());
        return 1;
    }

    // printf("[encoder]: Going to send metadata(%d): [%s]\n", potential_out_md_json_len, out_md_json);
    const char* dummy_mrenclave = "11111111111111111111111111111111111111111111";
    int tmp_total_digests = md->total_digests;
	md->total_digests = tmp_total_digests + 1;
	md->digests = (char**)realloc(md->digests, sizeof(char*) * md->total_digests);
	md->digests[tmp_total_digests] = (char*)malloc(45);
	memset(md->digests[tmp_total_digests], 0, 45);
	memcpy(md->digests[tmp_total_digests], dummy_mrenclave, 45);
	char* output_json = metadata_2_json_without_frame_id(md);
    send_buffer_to_viewer(output_json, md_json_len);

    stop = high_resolution_clock::now();
    duration = duration_cast<microseconds>(stop - start);
    alt_eval_file << duration.count() << endl;

    printf("[encoder]: All files sent successfully...going to quit...\n");

    free(md_json);
    free(output_json);

    if (cl->psnr)
        psnr_print(psnr_get());

    // Close eval file
    eval_file.close();
    alt_eval_file.close();

	return 0;
}


