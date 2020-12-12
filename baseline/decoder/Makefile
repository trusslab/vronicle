# Added to link with H264 decoder libraries
DECODER_DIR := h264bsd_dec
DECODER_INCLUDE_PATH := $(DECODER_DIR)/include
DECODER_SRC_PATH := $(DECODER_DIR)/src
DECODER_LIB_NAME := h264bsd
DECODER_LIB_PATH := $(DECODER_DIR)/lib

TCP_MODULE_DIR := tcp_module

Cpp_Files := $(wildcard *.cpp) $(wildcard $(TCP_MODULE_DIR)/*.cpp)
Cpp_Objects := $(Cpp_Files:.cpp=.o)

Include_Paths := -I. -I$(TCP_MODULE_DIR) -I$(DECODER_INCLUDE_PATH) -I$(DECODER_SRC_PATH) -I../common

Cpp_Flags := $(Include_Paths)

Cpp_Link_Flags := -lpthread -L$(DECODER_LIB_PATH) -l$(DECODER_LIB_NAME)

.PHONY: all
all: decoder

%.o: %.c
	$(CC) $(Cpp_Flags) -c $< -o $@
	@echo "CC  <=  $<"

decoder: $(Cpp_Objects)
	$(CXX) $^ -o $@ $(Cpp_Link_Flags)
	@echo "LINK =>  $@"

.PHONY: clean
clean:
	@rm -f decoder $(Cpp_Objects)