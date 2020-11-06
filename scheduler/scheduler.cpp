#include "scheduler.h"

void close_app(int signum) {
	printf("There is a SIGINT error happened...exiting......(%d)\n", signum);
	tcp_server.closed();
	tcp_client.exit();
    send_cancel_request_to_all_workflows();
    free_all_workflows();
	exit(0);
}

void sigpipe_handler_scheduler(int signum){
	printf("There is a SIGPIPE error happened...exiting......(%d)\n", signum);
	tcp_server.closed();
	tcp_client.exit();
    send_cancel_request_to_all_workflows();
    free_all_workflows();
	exit(0);
}

void * received(void * m)
{
    // Assume there is a connection for tcp_server
    // Will use the latest connected one

	int current_mode = 0;	// 0 means awaiting reading file's nickname; 1 means awaiting file size; 2 means awaiting file content
    int current_file_indicator = -1;   // 0 means video; 1 means metadata; 2 means signature; 3 means certificate 
    void* current_writing_location = NULL;
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
            printf("Got new file_name: %s\n", file_name.c_str());
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

void* do_remaining_receving_jobs(void * m){
    // By design, scheduler will first receive metadata, and then will process & initialize & receive remaining data at the same time
    // Asssume there is a successful connection
    
    pthread_t msg;

    while(1) {

        if(pthread_create(&msg, NULL, received, (void *)0) != 0){
            printf("pthread for receiving created failed...quiting...\n");
            return 0;
        }
        pthread_join(msg, NULL);

        // If the program change, we might need a mutex here, as the other thread is techniqually sharing this global variable with this thread...
        ++num_of_times_received;
        // printf("num_of_times_received: %d\n", num_of_times_received);
        if(num_of_times_received == TARGET_NUM_TIMES_RECEIVED){
            printf("All files received successfully...\n");
            break;
        }
    }
    return 0;
}


int send_buffer(void* buffer, long buffer_lenth){
    // Return 0 on success, return 1 on failure

	// Send size of buffer
	tcp_client.Send(&buffer_lenth, sizeof(long));
	string rec = tcp_client.receive_exact(REPLYMSGSIZE);
	if( rec != "" )
	{
		// cout << rec << endl;
	}

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

void send_message(string message){
	tcp_client.Send(message);
	string rec = tcp_client.receive_exact(SIZEOFPACKAGEFORNAME);
	if( rec != "" )
	{
		// cout << rec << endl;
	}
	// sleep(1);
	// usleep(500);
}

void send_message(char* message, int msg_size){
	tcp_client.Send(message, msg_size);
    // printf("(send_message)Going to wait for receive...\n");
	string rec = tcp_client.receive_exact(SIZEOFPACKAGEFORNAME);
    // printf("(send_message)Going to wait for receive(finished)...\n");
	if( rec != "" )
	{
		// cout << "send_message received: " << rec << endl;
	}
	// sleep(1);
	// usleep(500);
}

void* start_decoder_server(void* args){

    decoder_args* d_args = (decoder_args*) args;

    // pthread_detach(pthread_self());

    string cmd_for_starting_decoder = "cd ../decoder/sgx/decoder_enclave; ./TestApp ";
    cmd_for_starting_decoder += d_args->path_of_cam_vender_pubkey;
    cmd_for_starting_decoder += " ";
    cmd_for_starting_decoder += std::to_string(d_args->incoming_port);
    cmd_for_starting_decoder += " ";
    cmd_for_starting_decoder += d_args->outgoing_ip_addr;
    cmd_for_starting_decoder += " ";
    cmd_for_starting_decoder += std::to_string(d_args->outgoing_port);

    free(args);

    printf("Cmd for starting decoder: %s\n", cmd_for_starting_decoder.c_str());
    system(cmd_for_starting_decoder.c_str());

    return 0;
}

void* start_filter_server(void* args){

    filter_args* f_args = (filter_args*) args;

    // pthread_detach(pthread_self());

    string cmd_for_starting_filter = "cd ../filter_";
    cmd_for_starting_filter += f_args->filter_name;
    cmd_for_starting_filter += "/sgx/filter_enclave; ./TestApp ";
    cmd_for_starting_filter += std::to_string(f_args->incoming_port);
    cmd_for_starting_filter += " ";
    cmd_for_starting_filter += f_args->outgoing_ip_addr;
    cmd_for_starting_filter += " ";
    cmd_for_starting_filter += std::to_string(f_args->outgoing_port);

    free(args);

    printf("Cmd for starting filter: %s\n", cmd_for_starting_filter.c_str());
    system(cmd_for_starting_filter.c_str());

    return 0;
}

void* start_encoder_server(void* args){

    encoder_args* e_args = (encoder_args*) args;

    // pthread_detach(pthread_self());

    string cmd_for_starting_encoder = "cd ../encoder/tee/sgx/encoder_ra; ./EncoderApp -fps10 -is_rgb ";
    cmd_for_starting_encoder += std::to_string(e_args->incoming_port);
    cmd_for_starting_encoder += " ";
    cmd_for_starting_encoder += std::to_string(e_args->outgoing_port);

    free(args);

    printf("Cmd for starting encoder: %s\n", cmd_for_starting_encoder.c_str());
    system(cmd_for_starting_encoder.c_str());

    return 0;
}

void join_everything_inside_workflow(workflow* workflow){
    pthread_join(*(workflow->decoder), NULL);
    pthread_join(*(workflow->encoder), NULL);
    for(int i = 0; i < workflow->num_of_filters; ++i){
        pthread_join(*(workflow->filters[i]), NULL);
    }
}

void send_cancel_request_to_everything_inside_workflow(workflow* workflow){
    pthread_cancel(*(workflow->decoder));
    pthread_cancel(*(workflow->encoder));
    for(int i = 0; i < workflow->num_of_filters; ++i){
        pthread_cancel(*(workflow->filters[i]));
    }
}

void free_everything_inside_workflow(workflow* workflow){
    free(workflow->decoder);
    free(workflow->encoder);
    for(int i = 0; i < workflow->num_of_filters; ++i){
        free(workflow->filters[i]);
    }
    free(workflow->filters);
}

void try_join_all_workflows(){
    for(int i = 0; i < current_num_of_workflows; ++i){
        join_everything_inside_workflow(workflows[i]);
    }
}

void send_cancel_request_to_all_workflows(){
    for(int i = 0; i < current_num_of_workflows; ++i){
        send_cancel_request_to_everything_inside_workflow(workflows[i]);
    }
}

void free_all_workflows(){
    // Note that you need to make sure you've joined all threads before calling this function
    for(int i = 0; i < current_num_of_workflows; ++i){
        free_everything_inside_workflow(workflows[i]);
    }
    free(workflows);
}


int main(int argc, char *argv[], char **env)
{

    if(argc < 2){
        printf("argc: %d\n", argc);
        // printf("%s, %s, %s, %s...\n", argv[0], argv[1], argv[2], argv[3]);
        printf("Usage: ./scheduler [incoming_port] \n");
        return 1;
    }

    // Open file to store evaluation results
    mkdir("../evaluation/eval_result", 0777);
    eval_file.open("../evaluation/eval_result/eval_scheduler.csv");
    if (!eval_file.is_open()) {
        printf("Could not open eval file.\n");
        return 1;
    }

    alt_eval_file.open("../evaluation/eval_result/eval_scheduler_one_time.csv");
    if (!alt_eval_file.is_open()) {
        printf("Could not open alt_eval_file file.\n");
        return 1;
    }

    // Init Evaluation
    auto start = high_resolution_clock::now();
    auto end = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(end - start);

    // Register signal handlers
    std::signal(SIGINT, close_app);
	std::signal(SIGPIPE, sigpipe_handler_scheduler);

    // Start TCPServer for receving incoming data
    pthread_t msg;
    vector<int> opts = { SO_REUSEPORT, SO_REUSEADDR };
    if( tcp_server.setup(atoi(argv[1]),opts) != 0) {
		cerr << "Errore apertura socket" << endl;
	}

    int num_of_times_scheduler_run = 1;
    
    while (num_of_times_scheduler_run)
    {
        --num_of_times_scheduler_run;

        // Accept connection and receive metadata
        tcp_server.accepted();
        
        // declaring argument of time() 
        time_t my_time = time(NULL); 

        // ctime() used to give the present time 
        printf("Receiving started at: %s", ctime(&my_time));
        
        start = high_resolution_clock::now();

        if(pthread_create(&msg, NULL, received, (void *)0) != 0){
            printf("pthread for receiving created failed...quiting...\n");
            return 1;
        }
        pthread_join(msg, NULL);
        ++num_of_times_received;
        
        end = high_resolution_clock::now();
        duration = duration_cast<microseconds>(end - start);
        eval_file << duration.count() << ", ";

        // Start Remaining receiving mission
        if(pthread_create(&msg, NULL, do_remaining_receving_jobs, (void *)0) != 0){
            printf("pthread for remaining receiving created failed...quiting...\n");
            return 1;
        }
        
        start = high_resolution_clock::now();

        // Parse Metadata
        // printf("md_json(%ld): %s\n", md_json_len, md_json);
        if (md_json[md_json_len - 1] == '\0') md_json_len--;
        if (md_json[md_json_len - 1] == '\0') md_json_len--;
        metadata* md = json_2_metadata(md_json, md_json_len);
        if (!md) {
            printf("Failed to parse metadata\n");
            return 1;
        }
        
        end = high_resolution_clock::now();
        duration = duration_cast<microseconds>(end - start);
        eval_file << duration.count() << ", ";
        
        start = high_resolution_clock::now();

        // Assigning port(s)
        int decoder_port = self_server_port_marker++;

        // Start Decoder Server
        decoder_args* d_args = (decoder_args*) malloc(sizeof(decoder_args));    // Using heap to prevent running out of stack memory when scaling up(To-Do: Consider also moving following char array to heap)
        d_args->path_of_cam_vender_pubkey = "../../../keys/camera_vendor_pub";  // To-Do: Make this flexible to different camera vendor
        d_args->incoming_port = decoder_port;
        d_args->outgoing_ip_addr = "127.0.0.1"; // To-Do: Make this flexible to scale up
        d_args->outgoing_port = self_server_port_marker;
        pthread_t* pt_decoder = (pthread_t*) malloc(sizeof(pthread_t));
        if(pthread_create(pt_decoder, NULL, start_decoder_server, d_args) != 0){
            printf("pthread for start_decoder_server created failed...quiting...\n");
            return 1;
        }

        // Start Filter Servers
        pthread_t** pt_filters = (pthread_t**) malloc(md->total_filters * sizeof(pthread_t*));
        for(int i = 0; i < md->total_filters; ++i){
            filter_args* f_args = (filter_args*) malloc(sizeof(filter_args));    // Using heap to prevent running out of stack memory when scaling up(To-Do: Consider also moving following char array to heap)
            f_args->filter_name = (md->filters)[i];
            f_args->incoming_port = self_server_port_marker++;
            f_args->outgoing_ip_addr = "127.0.0.1"; // To-Do: Make this flexible to scale up
            f_args->outgoing_port = self_server_port_marker;
            pt_filters[i] = (pthread_t*) malloc(sizeof(pthread_t));
            if(pthread_create(pt_filters[i], NULL, start_filter_server, f_args) != 0){
                printf("pthread for start_filter_server created failed...quiting...\n");
                return 1;
            }
        }

        // Start Encoder Servers
        encoder_args* e_args = (encoder_args*) malloc(sizeof(encoder_args));    // Using heap to prevent running out of stack memory when scaling up(To-Do: Consider also moving following char array to heap)
        e_args->incoming_port = self_server_port_marker++;
        e_args->outgoing_port = encoder_outgoing_port_marker++;
        pthread_t* pt_encoder = (pthread_t*) malloc(sizeof(pthread_t));
        if(pthread_create(pt_encoder, NULL, start_encoder_server, e_args) != 0){
            printf("pthread for start_encoder_server created failed...quiting...\n");
            return 1;
        }

        // Join the receiver thread
        pthread_join(msg, NULL);
        
        end = high_resolution_clock::now();
        duration = duration_cast<microseconds>(end - start);
        eval_file << duration.count() << ", ";

        // Manage workflows
        pthread_mutex_lock(&lock_4_workflows);
        workflows = (workflow**) realloc(workflows, ++current_num_of_workflows * sizeof(workflow*));
        workflows[current_num_of_workflows - 1] = (workflow*) malloc(sizeof(workflow));
        workflows[current_num_of_workflows - 1]->decoder = pt_decoder;
        workflows[current_num_of_workflows - 1]->encoder = pt_encoder;
        workflows[current_num_of_workflows - 1]->filters = pt_filters;
        workflows[current_num_of_workflows - 1]->num_of_filters = md->total_filters;
        pthread_mutex_unlock(&lock_4_workflows);

        sleep(3);
        
        start = high_resolution_clock::now();

        // Send Data to Decoder
	    bool result_of_client_connection = tcp_client.setup("127.0.0.1", decoder_port);
        if(!result_of_client_connection){
            printf("Connection to decoder failed...\n");
            return 1;
        }
	    char* msg_to_send = (char*)malloc(SIZEOFPACKAGEFORNAME);

        // Send MetaData
        memset(msg_to_send, 0, SIZEOFPACKAGEFORNAME);
		memcpy(msg_to_send, "meta", 4);
		send_message(msg_to_send, SIZEOFPACKAGEFORNAME);
		send_buffer(md_json, md_json_len);
        
        // Send Video
        memset(msg_to_send, 0, SIZEOFPACKAGEFORNAME);
		memcpy(msg_to_send, "vid", 3);
		send_message(msg_to_send, SIZEOFPACKAGEFORNAME);
		send_buffer(contentBuffer, contentSize);

        // Send Signature
        memset(msg_to_send, 0, SIZEOFPACKAGEFORNAME);
		memcpy(msg_to_send, "sig", 3);
		send_message(msg_to_send, SIZEOFPACKAGEFORNAME);
		send_buffer(vid_sig_buf, vid_sig_buf_length);

        // Send Certificate
        memset(msg_to_send, 0, SIZEOFPACKAGEFORNAME);
		memcpy(msg_to_send, "cert", 4);
		send_message(msg_to_send, SIZEOFPACKAGEFORNAME);
		send_buffer(camera_cert, camera_cert_len);
        
        end = high_resolution_clock::now();
        duration = duration_cast<microseconds>(end - start);
        eval_file << duration.count() << ", ";
        
        start = high_resolution_clock::now();

        // Free Everything
        free_metadata(md);
        free(msg_to_send);
        free(contentBuffer);
        contentBuffer = NULL;
        contentSize = 0;
        free(camera_cert);
        camera_cert = NULL;
        camera_cert_len = 0;
        free(vid_sig_buf);
        vid_sig_buf = NULL;
        vid_sig_buf_length = 0;
        free(md_json);
        md_json = NULL;
        md_json_len = 0;

        end = high_resolution_clock::now();
        duration = duration_cast<microseconds>(end - start);
        eval_file << duration.count() << "\n";
    }

    // Close Server & Client
	tcp_server.closed();
	tcp_client.exit();

    // Try join all workflows and free them
    try_join_all_workflows();
    free_all_workflows();

    // Close eval file
    eval_file.close();
    alt_eval_file.close();

	return 0;
}
