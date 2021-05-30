# Added to link with FFMPEG H264 decoder libraries
F_DECODER_SRCS := $(shell find ./ffmpeg_decoder -name "*.c" -not -name "*_template.c")
F_DECODER_INCLUDE_PATH := ./ffmpeg_decoder/ffmpeg-src

TCP_MODULE_DIR := ../tcp_module

Cpp_Files := $(wildcard *.cpp) $(wildcard $(TCP_MODULE_DIR)/*.cpp)
Cpp_Objects := $(Cpp_Files:.cpp=.o)

# Added for ffmpeg H264 Decoder
F_DECODER_OBJS := $(F_DECODER_SRCS:%.c=%.o)

Include_Paths := -I. -I$(TCP_MODULE_DIR) -I../common -I$(F_DECODER_INCLUDE_PATH)

Cpp_Flags := -lpthread -lm $(Include_Paths) -DH264E_SVC_API=1 -O2

Cpp_Link_Flags := -lpthread -lm

.PHONY: all
all: all_in_one

%.o: %.cpp
	$(CXX) $(Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

all_in_one: $(Cpp_Objects) $(F_DECODER_OBJS)
	$(CXX) $^ -o $@ $(Cpp_Link_Flags)
	@echo "LINK =>  $@"

.PHONY: clean
clean:
	@rm -f all_in_one $(Cpp_Objects)