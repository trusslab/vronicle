#include "TCPServer.h" 
# define MAXTIMESTRYTORECEIVE 5

char TCPServer::msg[MAXPACKETSIZE];

int TCPServer::num_client;
int TCPServer::last_closed;
bool TCPServer::isonline;
vector<descript_socket*> TCPServer::Message;
vector<descript_socket*> TCPServer::newsockfd;
std::mutex TCPServer::mt;

void sigpipe_handler(int signum){
	printf("There is a SIGPIPE error happened...exiting......(%d)\n", signum);
	// tcp.closed();
	exit(0);
}

void* TCPServer::Task(void *arg)
{
	int n;
	struct descript_socket *desc = (struct descript_socket*) arg;
	pthread_detach(pthread_self());

	// char* msg_container;

	int times_remaining_same = 0;	// Check MAXTIMESTRYTORECEIVE for maximum
	
	// std::signal(SIGPIPE, sigpipe_handler);

        cerr << "open client[ id:"<< desc->id <<" ip:"<< desc->ip <<" socket:"<< desc->socket<<" send:"<< desc->enable_message_runtime <<" ]" << endl;
	// Below is another attempt to reduce the chance of BROKENPIPE (potentially failed??)
	int rounds_left_for_retrying = 3;

	int current_mode = 0;	// 0 is receiving file name; 1 is receiving file size; 2 is receiving file
	int invalid_current_mode_detected = 0;
	long remaining_to_target_file_size = 0;

	while(1)
	{
		// printf("Going to call recv...\n");
		// n = recv(desc->socket, msg, SIZEOFPACKAGE, MSG_WAITALL);
		// n = recv(desc->socket, msg, SIZEOFPACKAGE, 0);
		switch(current_mode){
			case 0:
				n = recv(desc->socket, msg, SIZEOFPACKAGEFORNAME, MSG_WAITALL);
				current_mode = 1;
				break;
			case 1:
				n = recv(desc->socket, msg, SIZEOFPACKAGEFORSIZE, MSG_WAITALL);
				current_mode = 2;
				memcpy(&remaining_to_target_file_size, msg, 8);
				break;
			case 2:
				// printf("Going to receive file...\n");
				n = recv(desc->socket, msg, SIZEOFPACKAGE, 0);
				// printf("Going to receive file(finished..\n)...\n");
				remaining_to_target_file_size -= n;
				if(remaining_to_target_file_size <= 0){
					current_mode = 0;
				}
				break;
			default:
				printf("Invalid current_mode in TCPServer::Task -> %d, exiting...\n", current_mode);
				invalid_current_mode_detected = 1;
				isonline = false;
				cerr << "close client[ id:"<< desc->id <<" ip:"<< desc->ip <<" socket:"<< desc->socket<<" ]" << endl;
				last_closed = desc->id;
				close(desc->socket);

				int id = desc->id;
				auto new_end = std::remove_if(newsockfd.begin(), newsockfd.end(),
													[id](descript_socket *device)
														{ return device->id == id; });
				newsockfd.erase(new_end, newsockfd.end());

				if(num_client>0) num_client--;
				break;
		}
		if(invalid_current_mode_detected){
			break;
		}
		// printf("Potential packet size is: %d\n", n);
		if(n != -1) 
		{
			if(n==0)
			{
				if(--rounds_left_for_retrying <= 0){
					isonline = false;
					cerr << "close client[ id:"<< desc->id <<" ip:"<< desc->ip <<" socket:"<< desc->socket<<" ]" << endl;
					last_closed = desc->id;
					close(desc->socket);

					int id = desc->id;
					auto new_end = std::remove_if(newsockfd.begin(), newsockfd.end(),
														[id](descript_socket *device)
															{ return device->id == id; });
					newsockfd.erase(new_end, newsockfd.end());

					if(num_client>0) num_client--;
					break;
				}
			} else {
				desc->message = msg;
				desc->size_of_packet = n;
				std::lock_guard<std::mutex> guard(mt);
				Message.push_back( desc );
			}
		} else {
			printf("Okay..., now we received a -1...\n");
		}
		// printf("Going to call usleep...\n");
		// usleep(1000);
		// printf("After usleep...\n");
        }
	if(desc != NULL){
		// if(desc->message){
		// 	free(desc->message);
		// 	desc->message = NULL;
		// }
		free(desc);
	}
	cerr << "exit thread: " << this_thread::get_id() << endl;
	pthread_exit(NULL);
	
	return 0;
}

int TCPServer::setup(int port, vector<int> opts)
{
	int opt = 1;
	isonline = false;
	last_closed = -1;
	sockfd = socket(AF_INET,SOCK_STREAM,0);
 	memset(&serverAddress,0,sizeof(serverAddress));

	for(unsigned int i = 0; i < opts.size(); i++) {
		if( (setsockopt(sockfd, SOL_SOCKET, opts.size(), (char *)&opt, sizeof(opt))) < 0 ) {
			cerr << "Errore setsockopt" << endl; 
      			return -1;
	      	}
	}

	serverAddress.sin_family      = AF_INET;
	serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
	serverAddress.sin_port        = htons(port);

	if((::bind(sockfd,(struct sockaddr *)&serverAddress, sizeof(serverAddress))) < 0){
		cerr << "Errore bind" << endl;
		return -1;
	}
	
 	if(listen(sockfd,5) < 0){
		cerr << "Errore listen" << endl;
		return -1;
	}
	num_client = 0;
	isonline = true;
	return 0;
}

void TCPServer::accepted()
{
	socklen_t sosize    = sizeof(clientAddress);
	descript_socket *so = new descript_socket;
	so->socket          = accept(sockfd,(struct sockaddr*)&clientAddress,&sosize);
	so->id              = num_client;
	so->ip              = inet_ntoa(clientAddress.sin_addr);
	newsockfd.push_back( so );
	cerr << "accept client[ id:" << newsockfd[num_client]->id << 
	                      " ip:" << newsockfd[num_client]->ip << 
		              " handle:" << newsockfd[num_client]->socket << " ]" << endl;
	pthread_create(&serverThread[num_client], NULL, &Task, (void *)newsockfd[num_client]);
	isonline=true;
	num_client++;
}

vector<descript_socket*> TCPServer::getMessage()
{
	std::lock_guard<std::mutex> guard(mt);
	return Message;
}

void TCPServer::Send(string msg, int id)
{
	send(newsockfd[id]->socket,msg.c_str(),msg.length(),0);
}

void TCPServer::Send(char* msg, int msg_len, int id)
{
	send(newsockfd[id]->socket,msg,msg_len,0);
}

int TCPServer::get_last_closed_sockets()
{
	return last_closed;
}

void TCPServer::clean(int id)
{
	// if(Message[id]->message){
	// 	free(Message[id]->message);
	// }
	Message[id]->message = NULL;
	memset(msg, 0, MAXPACKETSIZE);
	Message[id]->size_of_packet = 0;
}

string TCPServer::get_ip_addr(int id)
{
	return newsockfd[id]->ip;
}

bool TCPServer::is_online() 
{
	return isonline;
}

void TCPServer::detach(int id)
{
	close(newsockfd[id]->socket);
	newsockfd[id]->ip = "";
	newsockfd[id]->id = -1;
	// if(newsockfd[id]->message){
	// 	free(newsockfd[id]->message);
	// }
	newsockfd[id]->message = NULL;
	Message[id]->size_of_packet = 0;
} 

void TCPServer::closed() 
{
	printf("TCPServer is going to be closed...\n");
	close(sockfd);
}

