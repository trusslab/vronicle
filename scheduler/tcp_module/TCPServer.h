#ifndef TCP_SERVER_H
#define TCP_SERVER_H

#include <pthread.h>
#include <thread>
#include <algorithm>
#include <cctype>
#include <mutex>
#include <csignal>
#include "TCPStandard.h"

using namespace std;

//#define CODA_MSG 4

struct descript_socket{
	int socket     = -1;
	string ip      = "";
	int id         = -1; 
	char* message;
	int size_of_packet = 0;
	bool enable_message_runtime = false;
};

void sigpipe_handler(int signum);

class TCPServer
{
	public:
	int setup(int port, vector<int> opts = vector<int>());
	vector<descript_socket*> getMessage();
	void accepted();
	void Send(string msg, int id);
	void Send(char* msg, int msg_len, int id);
	void send_to_last_connected_client(void* data, int data_size);
	void detach(int id);
	void clean(int id);
        bool is_online();
	string get_ip_addr(int id);
	int get_last_closed_sockets();
	void closed();
    char* receive_exact(int size);
    string receive_name();
    long receive_size_of_data();

	private:
	int sockfd, n, pid;
	struct sockaddr_in serverAddress;
	struct sockaddr_in clientAddress;
	pthread_t serverThread[ MAX_CLIENT ];

	vector<descript_socket*> newsockfd;
	char msg[ MAXPACKETSIZE ];
	vector<descript_socket*> Message;//[CODA_MSG];

	bool isonline;
	int last_closed;
	int last_client_num;
	int num_client;
	std::mutex mt;
	void * Task(void * argv);
};

#endif
