TCP_MODULE_DIR := ../tcp_module

Cpp_Files := $(wildcard *.cpp) $(wildcard $(TCP_MODULE_DIR)/*.cpp)
Cpp_Objects := $(Cpp_Files:.cpp=.o)

Include_Paths := -I. -I$(TCP_MODULE_DIR) -I../common

Cpp_Flags := -O2 $(Include_Paths)

Cpp_Link_Flags := -lpthread

.PHONY: all
all: filter

%.o: %.cpp
	$(CXX) $(Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

filter: $(Cpp_Objects)
	$(CXX) $^ -o $@ $(Cpp_Link_Flags)
	@echo "LINK =>  $@"

.PHONY: clean
clean:
	@rm -f filter $(Cpp_Objects)