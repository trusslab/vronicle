TCP_MODULE_DIR := ../tcp_module

Cpp_Files := $(wildcard *.cpp) $(wildcard $(TCP_MODULE_DIR)/*.cpp)
Cpp_Output_Name := scheduler

all:
	g++ $(Cpp_Files) -o $(Cpp_Output_Name) -pthread -O2

clean:
	rm $(Cpp_Output_Name)