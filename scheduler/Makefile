Cpp_Files := scheduler.cpp tcp_module/TCPServer.cpp tcp_module/TCPClient.cpp
Cpp_Flags := -O2
Cpp_Output_Name := scheduler

all:
	g++ $(Cpp_Files) $(Cpp_Flags) -o $(Cpp_Output_Name) -pthread

clean:
	rm $(Cpp_Output_Name)