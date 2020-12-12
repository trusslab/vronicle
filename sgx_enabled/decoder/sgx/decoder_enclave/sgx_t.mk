#
# Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#



######## SGX SDK Settings ########
SGX_MODE ?= HW
SGX_ARCH ?= x64
ENCLAVE_DIR=enclave
ENABLE_DCAP ?= 0

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	$(error x86 build is not supported, only x64!!)
else
	SGX_COMMON_CFLAGS := -m64 -Wall
	ifeq ($(LINUX_SGX_BUILD), 1)
		include ../../../../../buildenv.mk
		SGX_LIBRARY_PATH := $(BUILD_DIR)
		SGX_ENCLAVE_SIGNER := $(BUILD_DIR)/sgx_sign
		SGX_EDGER8R := $(BUILD_DIR)/sgx_edger8r
		SGX_SDK_INC := $(COMMON_DIR)/inc
		LIBCXX_INC := $(LINUX_SDK_DIR)/tlibcxx/include
	else
		SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
		SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
		SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
		SGX_SDK_INC := $(SGX_SDK)/include
		LIBCXX_INC := $(SGX_SDK)/include/libcxx
	endif

endif

ifeq ($(DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

# Added to link with H264 decoder libraries
DECODER_DIR := $(ENCLAVE_DIR)/decoder
DECODER_INCLUDE_PATH := $(DECODER_DIR)/include
DECODER_OBJ_DIR := $(DECODER_DIR)/obj
DECODER_SRC_PATH := $(DECODER_DIR)/src
DECODER_LIB_NAME := h264bsd
DECODER_LIB_PATH := $(DECODER_DIR)/lib

# Added to build with SgxSSL libraries
TSETJMP_LIB := -lsgx_tsetjmp
OPENSSL_LIBRARY_PATH := $(PACKAGE_LIB)/


ifeq "20" "$(word 1, $(sort 20 $(SGXSDK_INT_VERSION)))"
        TSETJMP_LIB:=
endif

ifeq ($(DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
		SGXSSL_Library_Name := sgx_tsgxssld
		OpenSSL_Crypto_Library_Name := sgx_tsgxssl_cryptod
else
        SGX_COMMON_CFLAGS += -O2 -D_FORTIFY_SOURCE=2
		SGXSSL_Library_Name := sgx_tsgxssl
		OpenSSL_Crypto_Library_Name := sgx_tsgxssl_crypto
endif

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

ifeq ($(ENABLE_DCAP), 1)
        SGX_COMMON_CFLAGS += -DENABLE_DCAP
		Trts_Library_Name += -lsgx_dcap_tvl
endif

ifeq ($(SGX_MODE), HW)
ifndef DEBUG
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif

								
TestEnclave_Cpp_Files := $(wildcard $(ENCLAVE_DIR)/*.cpp)
TestEnclave_C_Files := $(wildcard $(ENCLAVE_DIR)/*.c)

TestEnclave_Cpp_Objects := $(TestEnclave_Cpp_Files:.cpp=.o)
TestEnclave_C_Objects := $(TestEnclave_C_Files:.c=.o)

TestEnclave_Include_Paths := -I. -I$(ENCLAVE_DIR) -I$(SGX_SDK_INC) -I$(SGX_SDK_INC)/tlibc -I$(LIBCXX_INC) -I$(PACKAGE_INC) -I$(DECODER_INCLUDE_PATH) -I$(DECODER_SRC_PATH) -Icommon

Common_C_Cpp_Flags := -DOS_ID=$(OS_ID) $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpic -fpie -fstack-protector -fno-builtin-printf -Wformat -Wformat-security $(TestEnclave_Include_Paths) -include "tsgxsslio.h"
TestEnclave_C_Flags := $(Common_C_Cpp_Flags) -Wno-implicit-function-declaration -std=c11
TestEnclave_Cpp_Flags :=  $(Common_C_Cpp_Flags) -std=c++11 -nostdinc++

SgxSSL_Link_Libraries := -L$(OPENSSL_LIBRARY_PATH) -Wl,--whole-archive -l$(SGXSSL_Library_Name) -Wl,--no-whole-archive \
						 -l$(OpenSSL_Crypto_Library_Name)
Security_Link_Flags := -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -pie

# TestEnclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
# 	$(Security_Link_Flags) \
# 	$(SgxSSL_Link_Libraries) -L$(SGX_LIBRARY_PATH) -L$(DECODER_LIB_PATH) \
# 	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
# 	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto $(TSETJMP_LIB) -l$(DECODER_LIB_NAME) -l$(Service_Library_Name) -Wl,--end-group \
# 	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
# 	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
# 	-Wl,--defsym,__ImageBase=0 \
# 	-Wl,--version-script=$(ENCLAVE_DIR)/TestEnclave.lds

TestEnclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
	$(Security_Link_Flags) \
	$(SgxSSL_Link_Libraries) -L$(SGX_LIBRARY_PATH)\
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto $(TSETJMP_LIB) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=$(ENCLAVE_DIR)/TestEnclave.lds	\
	-L$(DECODER_LIB_PATH) -Wl,--whole-archive -l$(DECODER_LIB_NAME) -Wl,--whole-archive


.PHONY: all test

all: TestEnclave.signed.so
# usually release mode don't sign the enclave, but here we want to run the test also in release mode
# this is not realy a release mode as the XML file don't disable debug - we can't load real release enclaves (white list)

test: all


######## TestEnclave Objects ########

# Added for H264 Decoder
libh264bsd.a: 
	@cd $(DECODER_DIR) && mkdir -p include obj lib && cp src/*.h include/ && cd obj && gcc -c ../src/*.c && cd .. && ar rcs lib/libh264bsd.a obj/*
	@echo "GEN => H264 Decoder Shared Library Ready..."

ifeq ($(ENABLE_DCAP), 0)
$(ENCLAVE_DIR)/TestEnclave_t.c: libh264bsd.a $(SGX_EDGER8R) $(ENCLAVE_DIR)/TestEnclave.edl
	@cd $(ENCLAVE_DIR) && $(SGX_EDGER8R) --trusted TestEnclave.edl --search-path $(PACKAGE_INC) --search-path $(SGX_SDK_INC)
else
$(ENCLAVE_DIR)/TestEnclave_dcap_t.c: libh264bsd.a $(SGX_EDGER8R) $(ENCLAVE_DIR)/TestEnclave_dcap.edl
	@cd $(ENCLAVE_DIR) && $(SGX_EDGER8R) --trusted TestEnclave_dcap.edl --search-path $(PACKAGE_INC) --search-path $(SGX_SDK_INC)
endif
	@echo "GEN  =>  $@"

ifeq ($(ENABLE_DCAP), 0)
$(ENCLAVE_DIR)/TestEnclave_t.o: $(ENCLAVE_DIR)/TestEnclave_t.c
else
$(ENCLAVE_DIR)/TestEnclave_t.o: $(ENCLAVE_DIR)/TestEnclave_dcap_t.c
endif
	$(VCC) $(TestEnclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(ENCLAVE_DIR)/ra_tls_options.c: $(ENCLAVE_DIR)/ra_tls_options.c.sh
    ifndef QUOTE_TYPE
    $(error QUOTE_TYPE is not set)
    endif
    ifndef EPID_SUBSCRIPTION_KEY
    $(error EPID_SUBSCRIPTION_KEY is not set)
    endif
    ifndef SPID
    $(error SPID is not set)
    endif
	bash $^ > $@
	@echo "GEN  =>  $@"

$(ENCLAVE_DIR)/ra_tls_options.o: $(ENCLAVE_DIR)/ra_tls_options.c
	$(VCC) $(TestEnclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(ENCLAVE_DIR)/%.o: $(ENCLAVE_DIR)/%.cpp
	$(VCXX) $(TestEnclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(ENCLAVE_DIR)/%.o: $(ENCLAVE_DIR)/%.c
	$(VCC) $(TestEnclave_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

$(ENCLAVE_DIR)/tests/%.o: $(ENCLAVE_DIR)/tests/%.c
	$(VCC) $(TestEnclave_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

TestEnclave.so: $(ENCLAVE_DIR)/TestEnclave_t.o $(ENCLAVE_DIR)/ra_tls_options.o $(TestEnclave_Cpp_Objects) $(TestEnclave_C_Objects)
	@echo "LINK =>  $^"
	@echo "VCXX => $(VCXX)"
	@echo "VCC => $(VCC)"
	$(VCXX) $^ -o $@ $(TestEnclave_Link_Flags)
	@echo "LINK =>  $@"

TestEnclave.signed.so: TestEnclave.so
	@$(SGX_ENCLAVE_SIGNER) sign -key $(ENCLAVE_DIR)/TestEnclave_private.pem -enclave TestEnclave.so -out $@ -config $(ENCLAVE_DIR)/TestEnclave.config.xml
	@echo "SIGN =>  $@"

clean:
ifeq ($(ENABLE_DCAP), 0)
	@rm -f TestEnclave.* $(ENCLAVE_DIR)/TestEnclave_t.* $(TestEnclave_Cpp_Objects) $(TestEnclave_C_Objects)
else
	@rm -f TestEnclave.* $(ENCLAVE_DIR)/TestEnclave_dcap_t.* $(TestEnclave_Cpp_Objects) $(TestEnclave_C_Objects)
endif
	@rm -r $(DECODER_DIR)/include $(DECODER_DIR)/obj $(DECODER_DIR)/lib
