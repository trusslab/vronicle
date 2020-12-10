Cpp_Files := scheduler.cpp tcp_module/TCPServer.cpp tcp_module/TCPClient.cpp
Cpp_Output_Name := scheduler

all:
	g++ $(Cpp_Files) -o $(Cpp_Output_Name) -pthread

clean:
	rm $(Cpp_Output_Name)