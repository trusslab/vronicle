#include <iostream>
#include <csignal>
#include <ctime>
#include "TCPServer.h"

TCPServer tcp;
pthread_t msg1[MAX_CLIENT];
int num_message = 0;
int time_send   = 1;

#define SIZEOFPACKAGE 40000

int num_of_files_received = 0;
int current_mode = 0;	// 0 means awaiting reading file's nickname; 1 means awaiting file size; 2 means awaiting file content
FILE* output_file = NULL;
long remaining_file_size = 0;

void close_app(int s) {
	tcp.closed();
	exit(0);
}

void * send_client(void * m) {
        struct descript_socket *desc = (struct descript_socket*) m;

	while(1) {
		if(!tcp.is_online() && tcp.get_last_closed_sockets() == desc->id) {
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
		tcp.Send(date, desc->id);
		// sleep(time_send);
		usleep(500);
	}
	pthread_exit(NULL);
	return 0;
}

void * received(void * m)
{
        pthread_detach(pthread_self());
	vector<descript_socket*> desc;

	while(1)
	{
		desc = tcp.getMessage();
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

				if(current_mode == 0){
					printf("Trying to create new file: %s\n", desc[i]->message);
					char* dirname = "../video_data/src_encoded_video/";
        			mkdir(dirname, 0777);
					int size_of_output_actual_path = (strlen(desc[i]->message) + strlen(dirname) + 1) * sizeof(char);
					char output_actual_path[size_of_output_actual_path];
					memset(output_actual_path, 0, size_of_output_actual_path);
            		memcpy(output_actual_path, dirname, sizeof(char) * strlen(dirname));
            		sprintf(output_actual_path + sizeof(char) * strlen(dirname), "%s", desc[i]->message);
					printf("File is going to be saved at: %s\n", output_actual_path);
					output_file = fopen(output_actual_path, "wb");
					if(output_file == NULL){
						printf("file cannot be created...\n");
						return 0;
					}
					current_mode = 1;
				} else if (current_mode == 1){
					memcpy(&remaining_file_size, desc[i]->message, 8);
					printf("File size got: %d\n", remaining_file_size);
					current_mode = 2;
				} else {
					printf("Remaining message size: %d...\n", remaining_file_size);
					// printf("Message with size: %d, with content: %s to be written...\n", current_message_size, desc[i]->message.c_str());
					if(remaining_file_size > SIZEOFPACKAGE){
						fwrite(desc[i]->message, 1, SIZEOFPACKAGE, output_file);
						remaining_file_size -= SIZEOFPACKAGE;
					} else {
						fwrite(desc[i]->message, 1, remaining_file_size, output_file);
						remaining_file_size = 0;
						current_mode = 0;
						fclose(output_file);
					}

					// if(current_message_size != SIZEOFPACKAGE){
					// 	num_of_files_received++;
					// 	current_mode = 0;
					// 	fclose(output_file);
					// }
				}
				tcp.clean(i);
			}
		}
		usleep(1000);
	}
	return 0;
}

int main(int argc, char **argv)
{
	if(argc < 2) {
		cerr << "Usage: ./server port (opt)time-send" << endl;
		return 0;
	}
	if(argc == 3)
		time_send = atoi(argv[2]);
	std::signal(SIGINT, close_app);

	pthread_t msg;
        vector<int> opts = { SO_REUSEPORT, SO_REUSEADDR };

	if( tcp.setup(atoi(argv[1]),opts) == 0) {
		if( pthread_create(&msg, NULL, received, (void *)0) == 0)
		{
			while(1) {
				tcp.accepted();
				cerr << "Accepted" << endl;
			}
		}
	}
	else
		cerr << "Errore apertura socket" << endl;
	return 0;
}
