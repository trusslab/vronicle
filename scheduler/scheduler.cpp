#include "scheduler.h"

string msg_reply_from_decoder;

void close_app(int signum) {
	printf("There is a SIGINT error happened...exiting......(%d)\n", signum);
	tcp_server.closed();
    tcp_server_for_decoder.closed();
    if(current_scheduler_mode == 0){
        tcp_server_for_scheduler_helper.closed();
        pthread_cancel(helper_scheduler_accepter);
        free_all_helper_scheduler_info();
    }
    send_cancel_request_to_all_workflows();
    free_all_workflows();
    pthread_mutex_destroy(&decoder_pool_access_lock);
    pthread_mutex_destroy(&port_access_lock);
	exit(0);
}

void sigpipe_handler_scheduler(int signum){
	printf("There is a SIGPIPE error happened...exiting......(%d)\n", signum);
	tcp_server.closed();
    tcp_server_for_decoder.closed();
    if(current_scheduler_mode == 0){
        tcp_server_for_scheduler_helper.closed();
        pthread_cancel(helper_scheduler_accepter);
        free_all_helper_scheduler_info();
    }
    send_cancel_request_to_all_workflows();
    free_all_workflows();
    pthread_mutex_destroy(&decoder_pool_access_lock);
    pthread_mutex_destroy(&port_access_lock);
	exit(0);
}

void * received(void * m)
{
    // Assume there is a connection for tcp_server

    // int current_connected_uploader_source = *((int*)m);
    pre_workflow* p_workflow = (pre_workflow*)m;
    // free(m);

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
            string file_name = tcp_server.receive_name_with_id(p_workflow->incoming_source);
            // printf("Got new file_name: %s\n", file_name.c_str());
            pthread_mutex_lock(&(p_workflow->in_data->individual_access_lock));
            if(file_name == "vid"){
                current_file_indicator = 0;
                current_writing_size = &(p_workflow->in_data->contentSize);
            } else if (file_name == "meta"){
                current_file_indicator = 1;
                current_writing_size = &(p_workflow->in_data->md_json_len);
            } else if (file_name == "sig"){
                current_file_indicator = 2;
                current_writing_size = &(p_workflow->in_data->vid_sig_buf_length);
            } else if (file_name == "cert"){
                current_file_indicator = 3;
                current_writing_size = &(p_workflow->in_data->camera_cert_len);
            } else {
                printf("The file_name is not valid: %s\n", file_name);
                free(reply_msg);
                return 0;
            }
            pthread_mutex_unlock(&(p_workflow->in_data->individual_access_lock));
            current_mode = 1;
        } else if (current_mode == 1){
            long size_of_data = tcp_server.receive_size_of_data_with_id(p_workflow->incoming_source);
            *current_writing_size = size_of_data;
            remaining_file_size = size_of_data;
            // printf("File size got: %ld, which should be equal to: %ld\n", remaining_file_size, *current_writing_size);
            // printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!current file indicator is: %d\n", current_file_indicator);
            pthread_mutex_lock(&(p_workflow->in_data->individual_access_lock));
            switch(current_file_indicator){
                case 0:
                    p_workflow->in_data->contentBuffer = (u8*) malloc(*current_writing_size * sizeof(u8));
                    current_writing_location = p_workflow->in_data->contentBuffer;
                    break;
                case 1:
                    p_workflow->in_data->md_json = (char*) malloc(*current_writing_size * sizeof(char));
                    current_writing_location = p_workflow->in_data->md_json;
                    break;
                case 2:
                    p_workflow->in_data->vid_sig_buf = (char*) malloc((*current_writing_size + 1) * sizeof(char));
                    current_writing_location = p_workflow->in_data->vid_sig_buf;
                    break;
                case 3:
                    p_workflow->in_data->camera_cert = (char*) malloc(*current_writing_size * sizeof(char));
                    current_writing_location = p_workflow->in_data->camera_cert;
                    break;
                default:
                    printf("No file indicator is set, aborted...\n");
                    free(reply_msg);
                    return 0;
            }
            pthread_mutex_unlock(&(p_workflow->in_data->individual_access_lock));
            current_mode = 2;
        } else {
            char* data_received;
            if(remaining_file_size > SIZEOFPACKAGE){
                // printf("!!!!!!!!!!!!!!!!!!!Going to write data to current file location: %d\n", current_file_indicator);
                data_received = tcp_server.receive_exact_with_id(SIZEOFPACKAGE, p_workflow->incoming_source);
                pthread_mutex_lock(&(p_workflow->in_data->individual_access_lock));
                memcpy(current_writing_location, data_received, SIZEOFPACKAGE);
                pthread_mutex_unlock(&(p_workflow->in_data->individual_access_lock));
                current_writing_location += SIZEOFPACKAGE;
                remaining_file_size -= SIZEOFPACKAGE;
            } else {
                // printf("???????????????????Last write to the current file location: %d\n", current_file_indicator);
                data_received = tcp_server.receive_exact_with_id(remaining_file_size, p_workflow->incoming_source);
                pthread_mutex_lock(&(p_workflow->in_data->individual_access_lock));
                memcpy(current_writing_location, data_received, remaining_file_size);
                pthread_mutex_unlock(&(p_workflow->in_data->individual_access_lock));
                remaining_file_size = 0;
                current_mode = 0;
                ++num_of_files_received;
            }
		}
        memset(reply_msg, 0, size_of_reply);
        memcpy(reply_msg, "ready", 5);
        tcp_server.Send(reply_msg, size_of_reply, p_workflow->incoming_source);
	}
    free(reply_msg);
	return 0;
}

void *start_receiving_helper_scheduler_report(void * m)
{
    vector<int> opts = { SO_REUSEPORT, SO_REUSEADDR };
    if( tcp_server_for_scheduler_helper.setup(main_scheduler_report_port, opts) != 0) {
        cerr << "(tcp_server_for_scheduler_helper)Errore apertura socket" << endl;
    }

    while(true){
        int current_communicating_helper_scheduler_id = tcp_server_for_scheduler_helper.accepted();
        
        helper_scheduler_info *new_helper_scheduler_info = (helper_scheduler_info*) malloc(sizeof(helper_scheduler_info));
        new_helper_scheduler_info->id_in_current_connection = current_communicating_helper_scheduler_id;
        new_helper_scheduler_info->ip_addr = tcp_server_for_scheduler_helper.get_client_ip(current_communicating_helper_scheduler_id).c_str();
        pthread_mutex_init(&(new_helper_scheduler_info->individual_access_lock), NULL);

        pthread_mutex_lock(&helper_scheduler_pool_access_lock);
        helper_scheduler_pool.push_back(new_helper_scheduler_info);
        pthread_mutex_unlock(&helper_scheduler_pool_access_lock);

        printf("Current num of helper scheduler is increased to: %ld\n", helper_scheduler_pool.size());
    }
    
	return 0;
}

void* do_remaining_receving_jobs(void * m){
    // By design, scheduler will first receive metadata, and then will process & initialize & receive remaining data at the same time
    // Asssume there is a successful connection
    
    pthread_t msg;

    while(1) {

        if(pthread_create(&msg, NULL, received, m) != 0){
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
    // cmd_for_starting_decoder += d_args->path_of_cam_vender_pubkey;
    // cmd_for_starting_decoder += " ";
    cmd_for_starting_decoder += std::to_string(d_args->incoming_port);
    // cmd_for_starting_decoder += " ";
    // cmd_for_starting_decoder += d_args->outgoing_ip_addr.c_str();
    // cmd_for_starting_decoder += " ";
    // cmd_for_starting_decoder += std::to_string(d_args->outgoing_port);


    // if(is_filter_bundle_detected){
    //     int filter_bundle_port_marker = self_server_port_marker_extra;
    //     for(int i = 1; i < num_of_filter_in_bundle; ++i){
    //         cmd_for_starting_decoder += " ";
    //         cmd_for_starting_decoder += d_args->outgoing_ip_addr.c_str();
    //         cmd_for_starting_decoder += " ";
    //         cmd_for_starting_decoder += std::to_string(filter_bundle_port_marker++);
    //     }
    // }

    printf("Cmd for starting decoder: %s\n", cmd_for_starting_decoder.c_str());
    system(cmd_for_starting_decoder.c_str());

    // free(args);

    return 0;
}

void* start_filter_server(void* args){

    filter_args* f_args = (filter_args*) args;

    // pthread_detach(pthread_self());
    string filter_name = f_args->filter_name;

    string cmd_for_starting_filter = "cd ../filter_";
    cmd_for_starting_filter += filter_name;
    cmd_for_starting_filter += "/sgx/filter_enclave; ./TestApp ";
    cmd_for_starting_filter += std::to_string(f_args->incoming_port);
    cmd_for_starting_filter += " ";
    // cmd_for_starting_filter += f_args->outgoing_ip_addr.c_str();
    cmd_for_starting_filter += f_args->outgoing_ip_addr;
    cmd_for_starting_filter += " ";
    cmd_for_starting_filter += std::to_string(f_args->outgoing_port);

    if(f_args->is_filter_bundle_detected){
        cmd_for_starting_filter += " 1 &";
    } else {
        cmd_for_starting_filter += " 0";
    }

    printf("Cmd for starting filter: %s\n", cmd_for_starting_filter.c_str());
    system(cmd_for_starting_filter.c_str());

    if(f_args->is_filter_bundle_detected){
        int filter_bundle_port_marker = self_server_port_marker_extra;
        for(int i = 1; i < num_of_filter_in_bundle; ++i){
            string cmd_for_starting_extra_filter = "cd ../filter_";
            cmd_for_starting_extra_filter += filter_name;
            cmd_for_starting_extra_filter += "/sgx/filter_enclave; ./TestApp ";
            cmd_for_starting_extra_filter += std::to_string(filter_bundle_port_marker++);
            cmd_for_starting_extra_filter += " ";
            // cmd_for_starting_extra_filter += f_args->outgoing_ip_addr.c_str();
            cmd_for_starting_extra_filter += f_args->outgoing_ip_addr;
            cmd_for_starting_extra_filter += " ";
            cmd_for_starting_extra_filter += std::to_string(f_args->outgoing_port);
            cmd_for_starting_extra_filter += " 1 &";
            printf("Cmd for starting extra filter: %s\n", cmd_for_starting_extra_filter.c_str());
            system(cmd_for_starting_extra_filter.c_str());
        }
    }

    free(f_args->outgoing_ip_addr);
    free(args);

    return 0;
}

void* start_encoder_server(void* args){

    encoder_args* e_args = (encoder_args*) args;

    // pthread_detach(pthread_self());

    string cmd_for_starting_encoder = "cd ../encoder/tee/sgx/encoder_ra; ./EncoderApp ";
    cmd_for_starting_encoder += std::to_string(e_args->incoming_port);
    cmd_for_starting_encoder += " ";
    cmd_for_starting_encoder += std::to_string(e_args->outgoing_port);
    cmd_for_starting_encoder += "  -fps10 -is_rgb";

    if(e_args->is_filter_bundle_detected){
        cmd_for_starting_encoder += " -multi_in";
        cmd_for_starting_encoder += std::to_string(num_of_filter_in_bundle);
    }

    printf("Cmd for starting encoder: %s\n", cmd_for_starting_encoder.c_str());
    system(cmd_for_starting_encoder.c_str());

    free(args);

    return 0;
}

void join_everything_inside_workflow(workflow* workflow){
    if(workflow->decoder)
        pthread_join(*(workflow->decoder), NULL);
    if(workflow->encoder)
        pthread_join(*(workflow->encoder), NULL);
    if(workflow->num_of_filters){
        for(int i = 0; i < workflow->num_of_filters; ++i){
            pthread_join(*(workflow->filters[i]), NULL);
        }
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
    if(workflow->decoder != NULL)
        free(workflow->decoder);
    if(workflow->encoder != NULL)
        free(workflow->encoder);
    if(workflow->filters != NULL){
        for(int i = 0; i < workflow->num_of_filters; ++i){
            free(workflow->filters[i]);
        }
        free(workflow->filters);
    }
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

void free_all_helper_scheduler_info(){
    // Note that you need to make sure you've cancelled the thread for accepting new helper scheduler before calling this function
    for(int i = 0; i < helper_scheduler_pool.size(); ++i){
        free_helper_scheduler_info(helper_scheduler_pool[i]);
    }
    helper_scheduler_pool.clear();
}

int send_buffer_to_decoder(void* buffer, long buffer_lenth){
    // Return 0 on success, return 1 on failure

	// Send size of buffer
	// printf("Sending buffer size: %d\n", buffer_lenth);
	tcp_server_for_decoder.send_to_last_connected_client(&buffer_lenth, sizeof(long));
    // printf("Going to wait for receive...\n");
	string rec = tcp_server_for_decoder.receive_name();
    // printf("Going to wait for receive(finished)...\n");
	if( rec != "" )
	{
		// cout << rec << endl;
	}

    long remaining_size_of_buffer = buffer_lenth;
    void* temp_buffer = buffer;
    int is_finished = 0;

    // printf("Going to start sending buffer...\n");

	while(1)
	{
        if(remaining_size_of_buffer > SIZEOFPACKAGE){
		    tcp_server_for_decoder.send_to_last_connected_client(temp_buffer, SIZEOFPACKAGE);
            remaining_size_of_buffer -= SIZEOFPACKAGE;
            temp_buffer += SIZEOFPACKAGE;
        } else {
		    tcp_server_for_decoder.send_to_last_connected_client(temp_buffer, remaining_size_of_buffer);
            remaining_size_of_buffer = 0;
            is_finished = 1;
        }
        // printf("(inside)Going to wait for receive...just send buffer with size: %d\n", remaining_size_of_buffer);
		string rec = tcp_server_for_decoder.receive_name();
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

void free_incoming_data(incoming_data *in_data_to_be_freed){
    free(in_data_to_be_freed->camera_cert);
    free(in_data_to_be_freed->contentBuffer);
    free(in_data_to_be_freed->md_json);
    free(in_data_to_be_freed->vid_sig_buf);
    pthread_mutex_destroy(&(in_data_to_be_freed->individual_access_lock));
    free(in_data_to_be_freed);
}

void free_pre_workflow(pre_workflow *p_workflow_to_be_freed){
    free_metadata(p_workflow_to_be_freed->md);
    free_incoming_data(p_workflow_to_be_freed->in_data);
    free(p_workflow_to_be_freed);
}

void free_helper_scheduler_info(helper_scheduler_info *hs_info_to_be_freed){
    pthread_mutex_destroy(&(hs_info_to_be_freed->individual_access_lock));
    free(hs_info_to_be_freed);
}

int prepare_decoder_pool(int scheduler_port_for_decoder){
    // Return 0 on success; otherwise return 1
    pthread_mutex_lock(&decoder_pool_access_lock);
    int num_of_decoder_should_be_prepared = NUM_OF_DECODER_IN_POOL - num_of_free_decoder;
    pthread_mutex_unlock(&decoder_pool_access_lock);
    while(num_of_decoder_should_be_prepared){
        decoder_args* d_args = (decoder_args*) malloc(sizeof(decoder_args));
        d_args->incoming_port = scheduler_port_for_decoder;
        pthread_t* pt_decoder = (pthread_t*) malloc(sizeof(pthread_t));
        // printf("Going to get into start_decoder_server...\n");
        if(pthread_create(pt_decoder, NULL, start_decoder_server, d_args) != 0){
            printf("pthread for start_decoder_server created failed...quiting...\n");
            return 1;
        }
        decoder_in_pool *new_pool_decoder = (decoder_in_pool*) malloc(sizeof(new_pool_decoder));
        new_pool_decoder->decoder = pt_decoder;
        new_pool_decoder->decoder_id = tcp_server_for_decoder.accepted();
        new_pool_decoder->incoming_port = scheduler_port_for_decoder;
        
        pthread_mutex_lock(&decoder_pool_access_lock);
        ++num_of_free_decoder;
        decoder_pool.push_back(new_pool_decoder);
        pthread_mutex_unlock(&decoder_pool_access_lock);

        free(d_args);
        --num_of_decoder_should_be_prepared;
    }

    return 0;
}

void* do_pre_workflow(void* pre_wf){
    // TO-DO...
    // Responsible for receiving all data, starting enclaves and call the normal workflow at the end
    pre_workflow* p_workflow = (pre_workflow*)pre_wf;

}

int report_to_decoder_as_main_scheduler(TCPServer *tcp_server_for_decoder, int decoder_id){
    // Return 0 on success, otherwise return 1
    char *message_to_decoder = (char*)malloc(SIZEOFPACKAGEFORNAME);
    memset(message_to_decoder, 0, SIZEOFPACKAGEFORNAME);
    memcpy(message_to_decoder, "main", 4);
    // printf("In report_to_decoder_as_main_scheduler, going to send...\n");
    // tcp_server_for_decoder->Send(message_to_decoder, SIZEOFPACKAGEFORNAME, decoder_id);
    tcp_server_for_decoder->Send(message_to_decoder, SIZEOFPACKAGEFORNAME, decoder_id);
    // printf("In report_to_decoder_as_main_scheduler, going to receive...\n");
    string reply_from_decoder = tcp_server_for_decoder->receive_name_with_id(decoder_id);
    // printf("In report_to_decoder_as_main_scheduler, received {%s}\n", reply_from_decoder.c_str());
    if(reply_from_decoder != "ready"){
        printf("report_to_decoder_as_main_scheduler: failed with reply from decoder: {%s}\n", reply_from_decoder.c_str());
        return 1;
    }
    free(message_to_decoder);
    return 0;
}

int report_to_decoder_as_helper_scheduler(TCPServer *tcp_server_for_decoder, int decoder_id, char** argv, string main_scheduler_port_str){
    // Return 0 on success, otherwise return 1
    char *message_to_decoder = (char*)malloc(SIZEOFPACKAGEFORNAME);
    memset(message_to_decoder, 0, SIZEOFPACKAGEFORNAME);
    memcpy(message_to_decoder, "helper", 6);
    tcp_server_for_decoder->Send(message_to_decoder, SIZEOFPACKAGEFORNAME, decoder_id);
    string reply_from_decoder = tcp_server_for_decoder->receive_name_with_id(decoder_id);
    if(reply_from_decoder != "ready"){
        printf("report_to_decoder_as_helper_scheduler: failed with reply from decoder: {%s}\n", reply_from_decoder.c_str());
        return 1;
    }
    
    memset(message_to_decoder, 0, SIZEOFPACKAGEFORNAME);
    memcpy(message_to_decoder, argv[3], size_of_typical_ip_addr);
    tcp_server_for_decoder->Send(message_to_decoder, SIZEOFPACKAGEFORNAME, decoder_id);
    reply_from_decoder = tcp_server_for_decoder->receive_name_with_id(decoder_id);
    if(reply_from_decoder != "ready"){
        printf("report_to_decoder_as_helper_scheduler: failed with reply from decoder: {%s}\n", reply_from_decoder.c_str());
        return 1;
    }
    
    memset(message_to_decoder, 0, SIZEOFPACKAGEFORNAME);
    memcpy(message_to_decoder, main_scheduler_port_str.c_str(), sizeof(main_scheduler_port_str.c_str()));
    tcp_server_for_decoder->Send(message_to_decoder, SIZEOFPACKAGEFORNAME, decoder_id);
    reply_from_decoder = tcp_server_for_decoder->receive_name_with_id(decoder_id);
    if(reply_from_decoder != "ready"){
        printf("report_to_decoder_as_helper_scheduler: failed with reply from decoder: {%s}\n", reply_from_decoder.c_str());
        return 1;
    }
    
    free(message_to_decoder);
    return 0;
}

int send_next_filters_info_to_decoder(TCPServer *tcp_server_for_decoder, int decoder_id, decoder_args* d_args, int is_bundle){
    // Return 0 on success, otherwise return 1
    
    char *message_to_decoder = (char*)malloc(SIZEOFPACKAGEFORNAME);

    long num_of_next_filters = 1;
    if(d_args->is_filter_bundle_detected){
        num_of_next_filters = num_of_filter_in_bundle;
    }
    tcp_server_for_decoder->Send(&num_of_next_filters, sizeof(long), decoder_id);
    string reply_from_decoder = tcp_server_for_decoder->receive_name_with_id(decoder_id);
    if(reply_from_decoder != "ready"){
        printf("send_next_filters_info_to_decoder: failed with reply from decoder: {%s}\n", reply_from_decoder.c_str());
        return 1;
    }

    memset(message_to_decoder, 0, SIZEOFPACKAGEFORNAME);
    // memcpy(message_to_decoder, d_args->outgoing_ip_addr.c_str(), sizeof(d_args->outgoing_ip_addr.c_str()));
    memcpy(message_to_decoder, d_args->outgoing_ip_addr, size_of_typical_ip_addr);
    // printf("In send_next_filters_info_to_decoder, we have d_args->outgoing_ip_addr: {%s}, message_to_decoder: {%s}, sizeof(d_args->outgoing_ip_addr): [%d]\n", d_args->outgoing_ip_addr, message_to_decoder, size_of_typical_ip_addr);
    tcp_server_for_decoder->Send(message_to_decoder, SIZEOFPACKAGEFORNAME, decoder_id);
    reply_from_decoder = tcp_server_for_decoder->receive_name_with_id(decoder_id);
    if(reply_from_decoder != "ready"){
        printf("send_next_filters_info_to_decoder: failed with reply from decoder: {%s}\n", reply_from_decoder.c_str());
        return 1;
    }

    memset(message_to_decoder, 0, SIZEOFPACKAGEFORNAME);
    memcpy(message_to_decoder, to_string(d_args->outgoing_port).c_str(), sizeof(to_string(d_args->outgoing_port).c_str()));
    tcp_server_for_decoder->Send(message_to_decoder, SIZEOFPACKAGEFORNAME, decoder_id);
    reply_from_decoder = tcp_server_for_decoder->receive_name_with_id(decoder_id);
    if(reply_from_decoder != "ready"){
        printf("send_next_filters_info_to_decoder: failed with reply from decoder: {%s}\n", reply_from_decoder.c_str());
        return 1;
    }

    if(is_bundle){
        int filter_bundle_port_marker = self_server_port_marker_extra;
        for(int i = 1; i < num_of_filter_in_bundle; ++i){
            // printf("Setting up extra filter[%d] with outgoing_ip: {%s} and port: {%d}\n", i, d_args->outgoing_ip_addr, filter_bundle_port_marker);
            memset(message_to_decoder, 0, SIZEOFPACKAGEFORNAME);
            // memcpy(message_to_decoder, d_args->outgoing_ip_addr.c_str(), sizeof(d_args->outgoing_ip_addr.c_str()));
            memcpy(message_to_decoder, d_args->outgoing_ip_addr, size_of_typical_ip_addr);
            tcp_server_for_decoder->Send(message_to_decoder, SIZEOFPACKAGEFORNAME, decoder_id);
            reply_from_decoder = tcp_server_for_decoder->receive_name_with_id(decoder_id);
            if(reply_from_decoder != "ready"){
                printf("send_next_filters_info_to_decoder: failed with reply from decoder: {%s}\n", reply_from_decoder.c_str());
                return 1;
            }

            memset(message_to_decoder, 0, SIZEOFPACKAGEFORNAME);
            memcpy(message_to_decoder, to_string(filter_bundle_port_marker).c_str(), sizeof(to_string(filter_bundle_port_marker).c_str()));
            tcp_server_for_decoder->Send(message_to_decoder, SIZEOFPACKAGEFORNAME, decoder_id);
            reply_from_decoder = tcp_server_for_decoder->receive_name_with_id(decoder_id);
            if(reply_from_decoder != "ready"){
                printf("send_next_filters_info_to_decoder: failed with reply from decoder: {%s}\n", reply_from_decoder.c_str());
                return 1;
            }
            
            ++filter_bundle_port_marker;
        }
    }
    
    free(message_to_decoder);
    return 0;
}

int main(int argc, char *argv[], char **env)
{

    if(argc < 2){
        printf("argc: %d\n", argc);
        // printf("%s, %s, %s, %s...\n", argv[0], argv[1], argv[2], argv[3]);
        printf("Usage: ./scheduler [incoming_port(or main_scheduler_port)] [scheduler_mode]* [main_scheduler_ip]*\n");
        return 1;
    }

    // Declare some variables for helper scheduler
    string main_scheduler_ip_address;
    int main_scheduler_port;

    if(argc >= 3){
        current_scheduler_mode = atoi(argv[2]);
        main_scheduler_ip_address = argv[3];
        main_scheduler_port = atoi(argv[1]);
    }

    // Print current mode of scheduler
    if(current_scheduler_mode == 0){
        printf("This scheduler is running at main mode...\n");
    } else if (current_scheduler_mode == 1){
        printf("This scheduler is running at helper mode...\n");
    }

    // Init some mutexes
    pthread_mutex_init(&port_access_lock, NULL);
    pthread_mutex_init(&workflow_access_lock, NULL);
    pthread_mutex_init(&helper_scheduler_pool_access_lock, NULL);
    pthread_mutex_init(&decoder_pool_access_lock, NULL);

    // Register signal handlers
    std::signal(SIGINT, close_app);
    std::signal(SIGPIPE, sigpipe_handler_scheduler);
    std::signal(SIGSEGV, close_app);

    // Start TCPServer for managing decoder
    // Create server and wait for decoder to connect
    vector<int> opts = { SO_REUSEPORT, SO_REUSEADDR };
    pthread_mutex_lock(&port_access_lock);
    int scheduler_port_for_decoder = self_server_port_marker++;
    string scheduler_port_for_decoder_str = to_string(scheduler_port_for_decoder);
    pthread_mutex_unlock(&port_access_lock);
    if( tcp_server_for_decoder.setup(scheduler_port_for_decoder, opts) != 0) {
        cerr << "Errore apertura socket" << endl;
    }
    
    prepare_decoder_pool(scheduler_port_for_decoder);

    // Send alive info to main scheduler if in helper mode
    // and start listening commands from main scheduler
    if(current_scheduler_mode == 1){

        bool result_of_client_connection = tcp_client.setup(main_scheduler_ip_address.c_str(), main_scheduler_port);

        if(!result_of_client_connection){
            printf("Connection to main scheduler failed...\n");
            return 1;
        }

        // TO-DO: Start listener for hearing cmds from main scheduler
        string type_of_cmd;
        
        while(true){
            type_of_cmd = tcp_client.receive_name();
            if(type_of_cmd == "decoder"){

                char* reply_msg = (char*) malloc(SIZEOFPACKAGEFORNAME);
                memset(reply_msg, 0, SIZEOFPACKAGEFORNAME);
                memcpy(reply_msg, "ready", 5);
                tcp_client.Send(reply_msg, SIZEOFPACKAGEFORNAME);
                string main_scheduler_port_for_decoder = tcp_client.receive_name();

                // Init some parameters for decoder thread
                pthread_t* pt_decoder;
                int decoder_id;
                int is_using_decoder_in_pool = 0;

                // Check if we need to start new decoder enclave or we can use one in pool
                pthread_mutex_lock(&decoder_pool_access_lock);
                if(num_of_free_decoder > 0){
                    --num_of_free_decoder;
                    pt_decoder = decoder_pool[num_of_free_decoder]->decoder;
                    decoder_id = decoder_pool[num_of_free_decoder]->decoder_id;
                    is_using_decoder_in_pool = 1;
                    decoder_pool.pop_back();
                }
                pthread_mutex_unlock(&decoder_pool_access_lock);

                if(!is_using_decoder_in_pool){
                    decoder_args* d_args = (decoder_args*) malloc(sizeof(decoder_args));
                    d_args->incoming_port = scheduler_port_for_decoder;
                    pt_decoder = (pthread_t*) malloc(sizeof(pthread_t));
                    printf("There is no decoder left in the pool, going to create one...\n");
                    if(pthread_create(pt_decoder, NULL, start_decoder_server, d_args) != 0){
                        printf("pthread for start_decoder_server created failed...quiting...\n");
                        return 1;
                    }
                    decoder_id = tcp_server_for_decoder.accepted();
                    free(d_args);
                }

                report_to_decoder_as_helper_scheduler(&tcp_server_for_decoder, decoder_id, argv, main_scheduler_port_for_decoder);

                pthread_mutex_lock(&workflow_access_lock);
                workflows = (workflow**) realloc(workflows, ++current_num_of_workflows * sizeof(workflow*));
                workflows[current_num_of_workflows - 1] = (workflow*) malloc(sizeof(workflow));
                workflows[current_num_of_workflows - 1]->decoder = pt_decoder;
                workflows[current_num_of_workflows - 1]->encoder = NULL;
                workflows[current_num_of_workflows - 1]->filters = NULL;
                pthread_mutex_unlock(&workflow_access_lock);
            } else {
                printf("Invalid command received from main shceduler: {%s}\n", type_of_cmd.c_str());
                close_app(1);
            }
        }
    }

    // Do main scheduler things
    if(current_scheduler_mode == 0){
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

        // Start receiving helper scheduler to check in
        pthread_create(&helper_scheduler_accepter, NULL, start_receiving_helper_scheduler_report, (void *)0);

        // Start TCPServer for receving incoming data
        pthread_t msg;
        if( tcp_server.setup(atoi(argv[1]),opts) != 0) {
            cerr << "Errore apertura socket" << endl;
        }

        // Prepare decoder pool if necessary
        prepare_decoder_pool(scheduler_port_for_decoder);

        int num_of_times_scheduler_run = 1;
        
        while (num_of_times_scheduler_run)
        {
            --num_of_times_scheduler_run;

            // Accept connection and receive metadata
            // int *current_communicating_uploader_source = (int*)malloc(sizeof(int));
            // *current_communicating_uploader_source = tcp_server.accepted();

            pre_workflow* new_p_workflow = (pre_workflow*)malloc(sizeof(pre_workflow));
            new_p_workflow->in_data = (incoming_data*)malloc(sizeof(incoming_data));
            pthread_mutex_init(&(new_p_workflow->in_data->individual_access_lock), NULL);

            // int current_communicating_uploader_source = tcp_server.accepted();
            new_p_workflow->incoming_source = tcp_server.accepted();
            
            // declaring argument of time() 
            time_t my_time = time(NULL); 

            // ctime() used to give the present time 
            printf("Receiving started at: %s", ctime(&my_time));
            
            start = high_resolution_clock::now();

            if(pthread_create(&msg, NULL, received, (void *)(new_p_workflow)) != 0){
                printf("pthread for receiving created failed...quiting...\n");
                return 1;
            }
            pthread_join(msg, NULL);
            ++num_of_times_received;
            
            end = high_resolution_clock::now();
            duration = duration_cast<microseconds>(end - start);
            eval_file << duration.count() << ", ";

            // Start Remaining receiving mission
            if(pthread_create(&msg, NULL, do_remaining_receving_jobs, (void *)(new_p_workflow)) != 0){
                printf("pthread for remaining receiving created failed...quiting...\n");
                return 1;
            }
            
            start = high_resolution_clock::now();

            // Parse Metadata
            // printf("md_json(%ld): %s\n", md_json_len, md_json);
            pthread_mutex_lock(&(new_p_workflow->in_data->individual_access_lock));
            if ((new_p_workflow->in_data->md_json)[new_p_workflow->in_data->md_json_len - 1] == '\0') (new_p_workflow->in_data->md_json_len)--;
            if ((new_p_workflow->in_data->md_json)[new_p_workflow->in_data->md_json_len - 1] == '\0') (new_p_workflow->in_data->md_json_len)--;
            new_p_workflow->md = json_2_metadata(new_p_workflow->in_data->md_json, new_p_workflow->in_data->md_json_len);
            pthread_mutex_unlock(&(new_p_workflow->in_data->individual_access_lock));
            if (!new_p_workflow->md) {
                printf("Failed to parse metadata\n");
                return 1;
            }
            string first_filter_name = new_p_workflow->md->filters[0];
            if(first_filter_name == "test_bundle_sharpen_and_blur"){
                printf("[scheduler]: test_bundle_sharpen_and_blur detected...\n");
                new_p_workflow->is_filter_bundle_detected = 1;
            }
            
            end = high_resolution_clock::now();
            duration = duration_cast<microseconds>(end - start);
            eval_file << duration.count() << ", ";
            
            start = high_resolution_clock::now();

            // Assigning port(s)
            pthread_mutex_lock(&port_access_lock);
            int decoder_outgoing_port = self_server_port_marker;
            pthread_mutex_unlock(&port_access_lock);

            // printf("Going to start filter server...\n");
            int size_of_outgoing_ip_addr = size_of_typical_ip_addr;
            // printf("size_of_outgoing_ip_addr: [%d]\n", size_of_outgoing_ip_addr);

            // Start Filter Servers
            pthread_t** pt_filters = (pthread_t**) malloc(new_p_workflow->md->total_filters * sizeof(pthread_t*));
            for(int i = 0; i < new_p_workflow->md->total_filters; ++i){
                filter_args* f_args = (filter_args*) malloc(sizeof(filter_args));    // Using heap to prevent running out of stack memory when scaling up(To-Do: Consider also moving following char array to heap)
                f_args->filter_name = (new_p_workflow->md->filters)[i];
                pthread_mutex_lock(&port_access_lock);
                f_args->incoming_port = self_server_port_marker++;
                pthread_mutex_unlock(&port_access_lock);
                // f_args->outgoing_ip_addr = local_ip_addr; // To-Do: Make this flexible to scale up
                f_args->outgoing_ip_addr = (char*)malloc(size_of_typical_ip_addr + 1);
                memset(f_args->outgoing_ip_addr, 0, size_of_typical_ip_addr + 1);
                memcpy(f_args->outgoing_ip_addr, local_ip_addr, size_of_typical_ip_addr);
                // printf("After setting up f_args, we have local_ip_addr: {%s} and f_args->outgoing_ip_addr: {%s} with size_of_outgoing_ip_add: [%d]\n", local_ip_addr, f_args->outgoing_ip_addr, size_of_typical_ip_addr);
                pthread_mutex_lock(&port_access_lock);
                f_args->outgoing_port = self_server_port_marker;
                pthread_mutex_unlock(&port_access_lock);
                f_args->is_filter_bundle_detected = new_p_workflow->is_filter_bundle_detected;
                pt_filters[i] = (pthread_t*) malloc(sizeof(pthread_t));
                if(pthread_create(pt_filters[i], NULL, start_filter_server, f_args) != 0){
                    printf("pthread for start_filter_server created failed...quiting...\n");
                    return 1;
                }
            }

            // printf("Going to start encoder server...\n");

            // Start Encoder Servers
            encoder_args* e_args = (encoder_args*) malloc(sizeof(encoder_args));    // Using heap to prevent running out of stack memory when scaling up(To-Do: Consider also moving following char array to heap)
            pthread_mutex_lock(&port_access_lock);
            e_args->incoming_port = self_server_port_marker++;
            pthread_mutex_unlock(&port_access_lock);
            e_args->outgoing_port = encoder_outgoing_port_marker++;
            e_args->is_filter_bundle_detected = new_p_workflow->is_filter_bundle_detected;
            pthread_t* pt_encoder = (pthread_t*) malloc(sizeof(pthread_t));
            if(pthread_create(pt_encoder, NULL, start_encoder_server, e_args) != 0){
                printf("pthread for start_encoder_server created failed...quiting...\n");
                return 1;
            }

            // Reason we put starting decoder server at the end is that: in case of filter-bundle, we need to first start all filter-bundle enclaves...
            if(new_p_workflow->is_filter_bundle_detected){
                // printf("[Scheduler]: Trying to join all filter threads...\n");
                for(int i = 0; i < new_p_workflow->md->total_filters; ++i){
                    pthread_join(*(pt_filters[i]), NULL);
                }
            }
            
            // printf("Going to start decoder server...\n");

            // Start Decoder Server
            decoder_args* d_args = (decoder_args*) malloc(sizeof(decoder_args));    // Using heap to prevent running out of stack memory when scaling up(To-Do: Consider also moving following char array to heap)
            // d_args->path_of_cam_vender_pubkey = "../../../keys/camera_vendor_pub";  // To-Do: Make this flexible to different camera vendor
            d_args->incoming_port = scheduler_port_for_decoder;
            d_args->outgoing_ip_addr = "127.0.0.1"; // To-Do: Make this flexible to scale up
            // printf("d_args->outgoing_ip_addr: {%s}\n", d_args->outgoing_ip_addr.c_str());
            d_args->outgoing_ip_addr = (char*)malloc(size_of_outgoing_ip_addr + 1);
            memset(d_args->outgoing_ip_addr, 0, size_of_outgoing_ip_addr + 1);
            memcpy(d_args->outgoing_ip_addr, local_ip_addr, size_of_outgoing_ip_addr);
            // printf("After setting up d_args, we have local_ip_addr: {%s} and d_args->outgoing_ip_addr: {%s} with size_of_outgoing_ip_add: [%d]\n", local_ip_addr, d_args->outgoing_ip_addr, size_of_outgoing_ip_addr);
            d_args->outgoing_port = decoder_outgoing_port;
            d_args->is_filter_bundle_detected = new_p_workflow->is_filter_bundle_detected;

            // Init some parameters for decoder thread
            pthread_t* pt_decoder = NULL;
            int decoder_id;
            int is_using_decoder_in_pool = 0;
            int is_using_decoder_remotely = 0;
            int helper_scheduler_id = -1;

            // Check if we need to start new decoder enclave or we can use one in pool
            pthread_mutex_lock(&decoder_pool_access_lock);
            if(num_of_free_decoder > 0){
                --num_of_free_decoder;
                pt_decoder = decoder_pool[num_of_free_decoder]->decoder;
                decoder_id = decoder_pool[num_of_free_decoder]->decoder_id;
                is_using_decoder_in_pool = 1;
                decoder_pool.pop_back();
            }
            pthread_mutex_unlock(&decoder_pool_access_lock);

            if(is_remote_scheduler_prefered){
                pthread_mutex_lock(&helper_scheduler_pool_access_lock);
                for(int i = 0; i < helper_scheduler_pool.size(); ++i){
                    pthread_mutex_lock(&(helper_scheduler_pool[i]->individual_access_lock));
                    // TO-DO: Make the following depend on capacity of helper scheulder
                    if(helper_scheduler_pool[i]->current_num_of_work < 4){
                        ++(helper_scheduler_pool[i]->current_num_of_work);
                        helper_scheduler_id = helper_scheduler_pool[i]->id_in_current_connection;
                        is_using_decoder_remotely = 1;
                        break;
                    }
                    pthread_mutex_unlock(&(helper_scheduler_pool[i]->individual_access_lock));
                }
                pthread_mutex_unlock(&helper_scheduler_pool_access_lock);

                if(is_using_decoder_remotely){
                    free(d_args->outgoing_ip_addr);
                    d_args->outgoing_ip_addr = (char*)malloc(size_of_typical_ip_addr + 1);
                    memset(d_args->outgoing_ip_addr, 0, size_of_typical_ip_addr + 1);
                    memcpy(d_args->outgoing_ip_addr, local_remote_ip_addr, size_of_typical_ip_addr);

                    char *msg_to_remote_helper_scheduler = (char*)malloc(SIZEOFPACKAGEFORNAME);
                    memset(msg_to_remote_helper_scheduler, 0, SIZEOFPACKAGEFORNAME);
                    memcpy(msg_to_remote_helper_scheduler, "decoder", 7);
                    tcp_server_for_scheduler_helper.Send(msg_to_remote_helper_scheduler, SIZEOFPACKAGEFORNAME, helper_scheduler_id);
                    string reply = tcp_server_for_scheduler_helper.receive_name_with_id(helper_scheduler_id);
                    if(reply != "ready"){
                        printf("Communication with remote server failed with reply: {%s}\n", reply);
                        close_app(1);
                    }
                    memset(msg_to_remote_helper_scheduler, 0, SIZEOFPACKAGEFORNAME);
                    memcpy(msg_to_remote_helper_scheduler, scheduler_port_for_decoder_str.c_str(), sizeof(scheduler_port_for_decoder_str.c_str()));
                    tcp_server_for_scheduler_helper.Send(msg_to_remote_helper_scheduler, SIZEOFPACKAGEFORNAME, helper_scheduler_id);

                    free(msg_to_remote_helper_scheduler);
                }
            }

            if(!is_using_decoder_in_pool && !is_using_decoder_remotely){
                pt_decoder = (pthread_t*) malloc(sizeof(pthread_t));
                // printf("Going to get into start_decoder_server...\n");
                printf("There is no decoder left in the pool and there is no prefered remote helper scheduler, going to create one...\n");
                if(pthread_create(pt_decoder, NULL, start_decoder_server, d_args) != 0){
                    printf("pthread for start_decoder_server created failed...quiting...\n");
                    return 1;
                }
            }
            
            end = high_resolution_clock::now();
            duration = duration_cast<microseconds>(end - start);
            eval_file << (duration.count() - 3000) << ", ";

            // printf("Going to manage worklow...\n");

            // Manage workflows
            pthread_mutex_lock(&workflow_access_lock);
            workflows = (workflow**) realloc(workflows, ++current_num_of_workflows * sizeof(workflow*));
            workflows[current_num_of_workflows - 1] = (workflow*) malloc(sizeof(workflow));
            workflows[current_num_of_workflows - 1]->decoder = pt_decoder;
            workflows[current_num_of_workflows - 1]->encoder = pt_encoder;
            workflows[current_num_of_workflows - 1]->filters = pt_filters;
            workflows[current_num_of_workflows - 1]->num_of_filters = new_p_workflow->md->total_filters;
            pthread_mutex_unlock(&workflow_access_lock);
            
            char* msg_to_send = (char*)malloc(SIZEOFPACKAGEFORNAME);

            start = high_resolution_clock::now();

            // Reset counter for evaluation
            start = high_resolution_clock::now();

            if(!is_using_decoder_in_pool){
                decoder_id = tcp_server_for_decoder.accepted();
            }

            end = high_resolution_clock::now();
            duration = duration_cast<microseconds>(end - start);
            eval_file << duration.count() << ", ";

            start = high_resolution_clock::now();
            
            // Join the receiver thread
            pthread_join(msg, NULL);
            
            end = high_resolution_clock::now();
            duration = duration_cast<microseconds>(end - start);
            eval_file << duration.count() << ", ";

            if(!is_using_decoder_remotely){
                report_to_decoder_as_main_scheduler(&tcp_server_for_decoder, decoder_id);
            }

            // Reset counter for evaluation
            start = high_resolution_clock::now();

            // Send vendor pub name
            // printf("Sending vendor pub name...\n");
            memset(msg_to_send, 0, SIZEOFPACKAGEFORNAME);
            memcpy(msg_to_send, "camera_vendor_pub", 17);  // To-Do: Make this flexible to different camera vendor
            tcp_server_for_decoder.Send(msg_to_send, SIZEOFPACKAGEFORNAME, decoder_id);
            msg_reply_from_decoder = tcp_server_for_decoder.receive_name_with_id(decoder_id);
            // printf("For vendor pub name, got reply: {%s}\n", msg_reply_from_decoder.c_str());
            if(msg_reply_from_decoder != "ready"){
                printf("No ready received from decoder but: %s\n", msg_reply_from_decoder.c_str());
                return 1;
            }

            // printf("Sending metadata...\n");
            // Send MetaData
            memset(msg_to_send, 0, SIZEOFPACKAGEFORNAME);
            memcpy(msg_to_send, "meta", 4);
            // printf("Going to send metadata name...\n");
            tcp_server_for_decoder.Send(msg_to_send, SIZEOFPACKAGEFORNAME, decoder_id);
            // printf("Going to receive metadata name reply...\n");
            msg_reply_from_decoder = tcp_server_for_decoder.receive_name_with_id(decoder_id);
            if(msg_reply_from_decoder != "ready"){
                printf("No ready received from decoder but: %s\n", msg_reply_from_decoder.c_str());
                return 1;
            }
            // printf("Going to send metadata data...\n");
            pthread_mutex_lock(&(new_p_workflow->in_data->individual_access_lock));
            send_buffer_to_decoder(new_p_workflow->in_data->md_json, new_p_workflow->in_data->md_json_len);
            pthread_mutex_unlock(&(new_p_workflow->in_data->individual_access_lock));
            // printf("Metadata is sent...\n");
            
            // Send Video
            memset(msg_to_send, 0, SIZEOFPACKAGEFORNAME);
            memcpy(msg_to_send, "vid", 3);
            tcp_server_for_decoder.Send(msg_to_send, SIZEOFPACKAGEFORNAME, decoder_id);
            msg_reply_from_decoder = tcp_server_for_decoder.receive_name_with_id(decoder_id);
            if(msg_reply_from_decoder != "ready"){
                printf("No ready received from decoder but: %s\n", msg_reply_from_decoder.c_str());
                return 1;
            }
            pthread_mutex_lock(&(new_p_workflow->in_data->individual_access_lock));
            send_buffer_to_decoder(new_p_workflow->in_data->contentBuffer, new_p_workflow->in_data->contentSize);
            pthread_mutex_unlock(&(new_p_workflow->in_data->individual_access_lock));
            
            // Send Signature
            memset(msg_to_send, 0, SIZEOFPACKAGEFORNAME);
            memcpy(msg_to_send, "sig", 3);
            tcp_server_for_decoder.Send(msg_to_send, SIZEOFPACKAGEFORNAME, decoder_id);
            msg_reply_from_decoder = tcp_server_for_decoder.receive_name_with_id(decoder_id);
            if(msg_reply_from_decoder != "ready"){
                printf("No ready received from decoder but: %s\n", msg_reply_from_decoder.c_str());
                return 1;
            }
            pthread_mutex_lock(&(new_p_workflow->in_data->individual_access_lock));
            send_buffer_to_decoder(new_p_workflow->in_data->vid_sig_buf, new_p_workflow->in_data->vid_sig_buf_length);
            pthread_mutex_unlock(&(new_p_workflow->in_data->individual_access_lock));
            
            // Send Certificate
            memset(msg_to_send, 0, SIZEOFPACKAGEFORNAME);
            memcpy(msg_to_send, "cert", 4);
            tcp_server_for_decoder.Send(msg_to_send, SIZEOFPACKAGEFORNAME, decoder_id);
            msg_reply_from_decoder = tcp_server_for_decoder.receive_name_with_id(decoder_id);
            if(msg_reply_from_decoder != "ready"){
                printf("No ready received from decoder but: %s\n", msg_reply_from_decoder.c_str());
                return 1;
            }
            pthread_mutex_lock(&(new_p_workflow->in_data->individual_access_lock));
            send_buffer_to_decoder(new_p_workflow->in_data->camera_cert, new_p_workflow->in_data->camera_cert_len);
            pthread_mutex_unlock(&(new_p_workflow->in_data->individual_access_lock));
            // tcp_server_for_decoder.closed();
            
            end = high_resolution_clock::now();
            duration = duration_cast<microseconds>(end - start);
            eval_file << duration.count() << ", ";
            
            start = high_resolution_clock::now();

            // Free Everything Else
            free(msg_to_send);
            free_pre_workflow(new_p_workflow);

            end = high_resolution_clock::now();
            duration = duration_cast<microseconds>(end - start);
            eval_file << duration.count() << "\n";

            // Setup decoder's next filters
            // printf("Going to call send_next_filters_info_to_decoder...\n");
            send_next_filters_info_to_decoder(&tcp_server_for_decoder, decoder_id, d_args, new_p_workflow->is_filter_bundle_detected);

            // Now we can free d_args
            free(d_args->outgoing_ip_addr);
            free(d_args);
        }

        // Close Server & Client
        tcp_server.closed();
        tcp_server_for_decoder.closed();
    }
    
    if(current_scheduler_mode == 0){
        // Cancel thread for accepting new helper scheduler
        tcp_server_for_scheduler_helper.closed();
        pthread_cancel(helper_scheduler_accepter);
        free_all_helper_scheduler_info();
    }

    // Try join all workflows and free them
    try_join_all_workflows();
    free_all_workflows();

    // Free mutexes
    pthread_mutex_destroy(&port_access_lock);
    pthread_mutex_destroy(&helper_scheduler_pool_access_lock);
    pthread_mutex_destroy(&workflow_access_lock);
    pthread_mutex_destroy(&decoder_pool_access_lock);

    // Close eval file
    eval_file.close();
    alt_eval_file.close();

	return 0;
}
