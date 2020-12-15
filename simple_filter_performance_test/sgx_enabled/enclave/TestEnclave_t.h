#ifndef TESTENCLAVE_T_H__
#define TESTENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void t_blur(void* img_pixels, size_t size_of_img_pixels, void* out_pixels);

sgx_status_t SGX_CDECL uprint(const char* str);
sgx_status_t SGX_CDECL usgx_exit(int reason);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
