#include <iostream>
#include <signal.h>
#include "TCPClient.h"

#define SIZEOFPACKAGE 500000

TCPClient tcp;

void sig_exit(int s)
{
	tcp.exit();
	exit(0);
}

int send_file(const char* file_name){
    // Return 0 on success, return 1 on failure

    FILE* input_file = fopen(file_name, "rb");
	if(input_file == NULL){
		printf("Cannot read %s\n", file_name);
        return 1;
    }
	
    fseek(input_file, 0, SEEK_SET);
	
	unsigned char* buffer = (unsigned char*)malloc(SIZEOFPACKAGE);

	while(1)
	{
   		memset(buffer, 0, SIZEOFPACKAGE);

		size_t num_of_ele_read = fread(buffer, 1, SIZEOFPACKAGE, input_file);

		// printf("Things have been read(%d): %s\n", num_of_ele_read, buffer);

		if(num_of_ele_read == 0){
			break;
		}

		tcp.Send(buffer, num_of_ele_read);
		string rec = tcp.receive();
		if( rec != "" )
		{
			// cout << rec << endl;
		}
		// sleep(1);
		usleep(500);
	}

	fclose(input_file);

    return 0;
}

void send_message(string message){
	tcp.Send(message);
	string rec = tcp.receive();
	if( rec != "" )
	{
		// cout << rec << endl;
	}
	// sleep(1);
	usleep(500);
}

int main(int argc, char *argv[])
{
	if(argc != 4) {
		cerr << "Usage: ./client ip port file_name" << endl;
		return 0;
	}
	signal(SIGINT, sig_exit);

	tcp.setup(argv[1],atoi(argv[2]));

	send_message(argv[3]);
	send_file(argv[3]);

	// while(1)
	// {
	// 	tcp.Send(argv[3]);
	// 	string rec = tcp.receive();
	// 	if( rec != "" )
	// 	{
	// 		cout << rec << endl;
	// 	}
	// 	sleep(1);
	// }
	return 0;
}
