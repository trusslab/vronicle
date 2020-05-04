/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _APP_H_
#define _APP_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */

#include "TestEnclave_u.h"
// #include "RawBase.h"    // For processing raw image

#include <fstream>
#include <iostream>

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif


# define TOKEN_FILENAME   "enclave.token"
# define TESTENCLAVE_FILENAME "TestEnclave.signed.so"

extern sgx_enclave_id_t global_eid;    /* global enclave id */

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(__cplusplus)
}
#endif

typedef struct pixel {
    unsigned char r = 0;
    unsigned char g = 0;
    unsigned char b = 0;
} pixel;

unsigned char truncate(int value)
{
    if(value < 0) return 0;
    if(value > 255) return 255;

    return value;
}

unsigned char truncate(float value)
{
    if(value < 0.0) return 0;
    if(value > 255.0) return 255;

    return value;
}

pixel* unsigned_chars_to_pixels(unsigned char* uchars, int num_of_pixels){
    // This will allocate new memory and return it (pixels)
    // Return NULL on error
    if(uchars == NULL){
        return NULL;
    }
    pixel* results = (pixel*)malloc(sizeof(pixel) * num_of_pixels);
    memcpy(results, uchars, num_of_pixels * 3);
    return results;
}

unsigned char* pixels_to_unsigned_chars(pixel* pixels, int num_of_pixels){
    // This will allocate new memory and return it (pixels)
    // Return NULL on error
    if(pixels == NULL){
        return NULL;
    }
    unsigned char* results = (unsigned char*)malloc(sizeof(unsigned char) * num_of_pixels * 3);
    memcpy(results, pixels, num_of_pixels * 3);
    return results;
}

#endif /* !_APP_H_ */
