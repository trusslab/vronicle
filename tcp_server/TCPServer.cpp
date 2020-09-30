#include "TCPServer.h" 

char TCPServer::msg[MAXPACKETSIZE];

int TCPServer::num_client;
int TCPServer::last_closed;
bool TCPServer::isonline;
int TCPServer::history_num_of_client;
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
	
	// std::signal(SIGPIPE, sigpipe_handler);

        cerr << "open client[ id:"<< desc->id <<" ip:"<< desc->ip <<" socket:"<< desc->socket<<" send:"<< desc->enable_message_runtime <<" ]" << endl;
	// Below is another attempt to reduce the chance of BROKENPIPE (potentially failed??)
	int rounds_left_for_retrying = 3;
	while(1)
	{
		// printf("Going to call recv...\n");
		n = recv(desc->socket, msg, MAXPACKETSIZE, 0);
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
					if(++history_num_of_client == 4){
							printf("All files received successfully, going to start processing video...\n");
							system("cd ../decoder/sgx/decoder_enclave; ./attempt_run_decoder.sh");
							exit(0);
						}
					// printf("Now we have a total of %d clients in history...\n", history_num_of_client);
					break;
				}
			} else {
				// long size_of_file;
				// memcpy(&size_of_file, msg, 8);
				// printf("Received file size of: %d\n", size_of_file);
				// printf("Potential packet size is: %d\n", n);
				
				desc->message = msg;

				// Below is an (potentailly failed) attempt to fix the random abort bug
				// desc->message = (char*) malloc(n * sizeof(char));
				// memcpy(desc->message, msg, n * sizeof(char));

				desc->size_of_packet = n;
				// msg[n]=0;
				// desc->message = string(msg);
						std::lock_guard<std::mutex> guard(mt);
				Message.push_back( desc );
			}
		} else {
			// printf("Okay..., now we received a -1...\n");
		}
		// printf("Going to call usleep...\n");
		usleep(3000);
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

int TCPServer::get_history_num_of_clients()
{
	return history_num_of_client;
}

