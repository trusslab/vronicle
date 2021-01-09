ENABLE_DCAP ?= 0
INCLUDE_PATHS = -I. -I/opt/intel/sgxsdk/include/ -I/home/myles/Downloads/sgxsdk/include/
CXX = g++
COMMON_FLAGS = -g3 -D__STDC_CONSTANT_MACROS \
		       -Wall -Wextra -Wextra -pedantic \
		       -Wdisabled-optimization -Wmissing-declarations \
		       -Wshadow -Wno-unused -Winline \
		       $(INCLUDE_PATHS)
ifeq ($(ENABLE_DCAP), 1)
        COMMON_FLAGS += -DENABLE_DCAP
endif
CXX_FLAGS := $(COMMON_FLAGS) -std=c++14 -Woverloaded-virtual -Wctor-dtor-privacy
CC_FLAGS  := $(COMMON_FLAGS) -std=c11 -Wno-implicit-function-declaration
LDLIBS = -lcrypto -L/opt/intel/sgxsdk/lib64 -lsgx_dcap_quoteverify

Viewer_Cpp_Files = $(wildcard *.cpp)
Viewer_Cpp_Objects = $(Viewer_Cpp_Files:.cpp=.o)
Viewer_C_Files = $(wildcard *.c)
Viewer_C_Objects = $(Viewer_C_Files:.c=.o)
target = sig_verify

all: $(target)

$(target): $(Viewer_C_Objects) $(Viewer_Cpp_Objects)
	$(CXX) -o $@ $^ $(LDLIBS)

%.o: %.cpp
	$(CXX) $(CXX_FLAGS) -c $< -o $@

%.o: %.c
	$(CC) $(CC_FLAGS) -c $< -o $@

test: $(target)
	./$(target) test.mkv

.PHONY: clean
clean:
	$(RM) $(Viewer_Cpp_Objects) $(Viewer_C_Objects) $(target) 
