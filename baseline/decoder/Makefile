# Added to link with H264 decoder libraries
DECODER_DIR := h264bsd_dec
DECODER_INCLUDE_PATH := $(DECODER_DIR)/include
DECODER_SRC_PATH := $(DECODER_DIR)/src
DECODER_LIB_NAME := h264bsd
DECODER_LIB_PATH := $(DECODER_DIR)/lib

# Added to link with FFMPEG H264 decoder libraries
F_DECODER_SRCS := $(shell find ./ffmpeg_decoder -name "*.c" -not -name "*_template.c")
F_DECODER_INCLUDE_PATH := ./ffmpeg_decoder/ffmpeg-src

TCP_MODULE_DIR := ../tcp_module

Cpp_Files := $(wildcard *.cpp) $(wildcard $(TCP_MODULE_DIR)/*.cpp)
Cpp_Objects := $(Cpp_Files:.cpp=.o)

CFLAGS := -I$(F_DECODER_INCLUDE_PATH) -O2 -w -std=c99 -Wno-implicit-function-declaration

# Added for ffmpeg H264 Decoder
F_DECODER_OBJS := $(F_DECODER_SRCS:%.c=%.o)

Include_Paths := -I. -I$(TCP_MODULE_DIR) -I$(DECODER_INCLUDE_PATH) -I$(DECODER_SRC_PATH) -I../common -I$(F_DECODER_INCLUDE_PATH)

Cpp_Flags := -lpthread -lm $(Include_Paths) -O2

Cpp_Link_Flags := -lpthread -lm -L$(DECODER_LIB_PATH) -l$(DECODER_LIB_NAME)

.PHONY: all
all: decoder

%.o: %.cpp
	$(CXX) $(Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

decoder: $(Cpp_Objects) $(F_DECODER_OBJS)
	$(CXX) $^ -o $@ $(Cpp_Link_Flags)
	@echo "LINK =>  $@"

.PHONY: clean
clean:
	@rm -f decoder $(Cpp_Objects)