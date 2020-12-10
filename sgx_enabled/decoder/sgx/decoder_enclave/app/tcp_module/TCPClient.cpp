#include "TCPClient.h"

TCPClient::TCPClient()
{
	sock = -1;
	port = 0;
	address = "";
}

bool TCPClient::setup(string address , int port)
{
  	if(sock == -1)
	{
		sock = socket(AF_INET , SOCK_STREAM , 0);
		if (sock == -1)
		{
      			cout << "[decoder:TCPClient]: Could not create socket" << endl;
    		}
        }
  	if((signed)inet_addr(address.c_str()) == -1)
  	{
    		struct hostent *he;
    		struct in_addr **addr_list;
    		if ( (he = gethostbyname( address.c_str() ) ) == NULL)
    		{
		      herror("gethostbyname");
      		      cout<<"[decoder:TCPClient]: Failed to resolve hostname\n";
		      return false;
    		}
	   	addr_list = (struct in_addr **) he->h_addr_list;
    		for(int i = 0; addr_list[i] != NULL; i++)
    		{
      		      server.sin_addr = *addr_list[i];
		      break;
    		}
  	}
  	else
  	{
    		server.sin_addr.s_addr = inet_addr( address.c_str() );
  	}
  	server.sin_family = AF_INET;
  	server.sin_port = htons( port );
  	if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0)
  	{
    		perror("[decoder:TCPClient]: connect failed. Error");
    		return false;
  	}
  	return true;
}

bool TCPClient::Send(string data)
{
	if(sock != -1) 
	{
		if( send(sock , data.c_str() , strlen( data.c_str() ) , 0) != strlen( data.c_str() ))
		{
			cout << "[decoder:TCPClient]: Send failed : " << data << endl;
			return false;
		}
	}
	else
		return false;
	return true;
}


bool TCPClient::Send(void* data, size_t len)
{
	if(sock != -1) 
	{
		if( send(sock , data , len , 0) != len)
		{
			cout << "[decoder:TCPClient]: Send failed with data size: " << len << endl;
			return false;
		}
	}
	else
		return false;
	return true;
}

string TCPClient::receive(int size)
{
  	char buffer[size];
	memset(&buffer[0], 0, sizeof(buffer));

  	string reply;
	if( recv(sock , buffer , size, 0) < 0)
  	{
	    	cout << "[decoder:TCPClient]: receive failed!" << endl;
		return nullptr;
  	}
	buffer[size-1]='\0';
  	reply = buffer;
  	return reply;
}

char* TCPClient::receive_exact(int size)
{
	char* buffer = (char*) malloc(size);
	memset(&buffer[0], 0, sizeof(buffer));

  	string reply;
	if( recv(sock , buffer , size, MSG_WAITALL) < 0)
  	{
	    	cout << "[decoder:TCPClient]: receive failed!" << endl;
		return nullptr;
  	}

  	return buffer;
}

string TCPClient::receive_name()
{
  	char buffer[SIZEOFPACKAGEFORNAME + 1];
	memset(&buffer[0], 0, sizeof(buffer));

  	string reply;
	int n = recv(sock , buffer , SIZEOFPACKAGEFORNAME, MSG_WAITALL);
	// printf("receive_name(%d): %s\n", n, buffer);
	if(n < 0)
  	{
	    cout << "[decoder:TCPClient]: receive failed!" << endl;
		return nullptr;
  	}
	buffer[SIZEOFPACKAGEFORNAME]='\0';
  	reply = buffer;
  	return reply;
}

long TCPClient::receive_size_of_data()
{
  	char buffer[8];
	memset(&buffer[0], 0, sizeof(buffer));
	long size_of_data = 0;

	if( recv(sock , buffer , 8, MSG_WAITALL) < 0)
  	{
	    	cout << "[decoder:TCPClient]: receive failed!" << endl;
		return -1;
  	}
	
	memcpy(&size_of_data, buffer, 8);

  	return size_of_data;
}

string TCPClient::read()
{
  	char buffer[1] = {};
  	string reply;
  	while (buffer[0] != '\n') {
    		if( recv(sock , buffer , sizeof(buffer) , 0) < 0)
    		{
      			cout << "[decoder:TCPClient]: receive failed!" << endl;
			return nullptr;
    		}
		reply += buffer[0];
	}
	return reply;
}

void TCPClient::exit()
{
    close( sock );
	sock = -1;
	port = 0;
	address = "";
}
