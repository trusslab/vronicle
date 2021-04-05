#include <iostream>
#include <signal.h>
#include <jni.h>
#include "TCPClient.h"
#include <android/log.h>

TCPClient tcp;
const static char* TAG = "client";

#define printf(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__);

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

	// Get size of file and send it
    fseek(input_file, 0, SEEK_END);
	long size_of_file = ftell(input_file);
	printf("Sending file size: %ld\n", size_of_file);
	tcp.Send(&size_of_file, sizeof(long));
	string rec = tcp.receive_exact(SIZEOFPACKAGEFORNAME);
	if( rec != "" )
	{
		// cout << rec << endl;
	}
	// sleep(1);
	// usleep(500);
	
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
		string rec = tcp.receive_exact(REPLYMSGSIZE);
		if( rec != "" )
		{
			// cout << rec << endl;
		}
		// sleep(1);
		// usleep(2000);
	}

	fclose(input_file);

    return 0;
}

void send_message(string message){
	tcp.Send(message);
	string rec = tcp.receive_exact(SIZEOFPACKAGEFORNAME);
	if( rec != "" )
	{
		// cout << rec << endl;
	}
	// sleep(1);
	// usleep(500);
}

void send_message(char* message, int msg_size){
	tcp.Send(message, msg_size);
    // printf("(send_message)Going to wait for receive...\n");
	string rec = tcp.receive_exact(SIZEOFPACKAGEFORNAME);
    // printf("(send_message)Going to wait for receive(finished)...\n");
	if( rec != "" )
	{
		// cout << "send_message received: " << rec << endl;
	}
	// sleep(1);
	// usleep(500);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_example_filtertestwithnativec_MainActivity_establish_1connection(
		JNIEnv* env,
		jobject /* this */,
		jstring ip_address_j, int port) {

	const jsize len_of_ip_address = env->GetStringUTFLength(ip_address_j);
	const char* ip_address = env->GetStringUTFChars(ip_address_j, (jboolean *)0);

    printf("Java_com_example_filtertestwithnativec_MainActivity_establish_connection: going to connect to ip: %s and port: %d\n", ip_address, port);

    int result = tcp.setup(ip_address, port);

//    printf("Java_com_example_filtertestwithnativec_MainActivity_establish_connection: connected...\n");

	return result;
}

//int main(int argc, char *argv[])
//{
//	if(argc != 11) {
//		cerr << "Usage: ./client ip port file_name_1 target_file_name_1 file_name_2 target_file_name_2 file_name_3 target_file_name_3 file_name_4 target_file_name_4" << endl;
//		return 0;
//	}
//	signal(SIGINT, sig_exit);
//
//	tcp.setup(argv[1],atoi(argv[2]));
//
//	char* msg_to_send = (char*)malloc(SIZEOFPACKAGEFORNAME);
//
//	char** current_file_name = &argv[3];
//	char** current_target_file_name = &argv[4];
//
//	for(int i = 0; i < 4; ++i){
//
//		memset(msg_to_send, 0, SIZEOFPACKAGEFORNAME);
//		memcpy(msg_to_send, *current_target_file_name, strlen(*current_target_file_name));
//		send_message(msg_to_send, SIZEOFPACKAGEFORNAME);
//		send_file(*current_file_name);
//
//		current_file_name += 2;
//		current_target_file_name += 2;
//
//	}
//
//
//	// declaring argument of time()
//    time_t my_time = time(NULL);
//
//    // ctime() used to give the present time
//    printf("Files uploading completed at: %s", ctime(&my_time));
//
//	// while(1)
//	// {
//	// 	tcp.Send(argv[3]);
//	// 	string rec = tcp.receive();
//	// 	if( rec != "" )
//	// 	{
//	// 		cout << rec << endl;
//	// 	}
//	// 	sleep(1);
//	// }
//	return 0;
//}
