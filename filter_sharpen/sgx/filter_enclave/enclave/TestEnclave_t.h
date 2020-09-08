#ifndef TESTENCLAVE_T_H__
#define TESTENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "ra.h"
#include "ra-attester.h"
#include "sgx_report.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void t_sgxssl_call_apis(void* evp_pkey_v);
void t_sgxver_call_apis(void* image_pixels, size_t size_of_image_pixels, int image_width, int image_height, void* hash_of_original_image, int size_of_hooi, void* signature, size_t size_of_actual_signature, void* original_vendor_pub_str, long int original_vendor_pub_str_len, void* original_cert_str, long int original_cert_str_len, void* processed_pixels, void* runtime_result, int size_of_runtime_result, void* char_array_for_processed_img_sign, int size_of_cafpis, void* hash_of_processed_image, int size_of_hopi, void* processed_img_signautre, size_t size_of_pis, void* size_of_actual_processed_img_signature, size_t sizeof_soapis);
void t_create_key_and_x509(void* cert, size_t size_of_cert, void* actual_size_of_cert, size_t asoc);
void t_free(void);
void dummy(void);

sgx_status_t SGX_CDECL uprint(const char* str);
sgx_status_t SGX_CDECL usgx_exit(int reason);
sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
sgx_status_t SGX_CDECL ocall_sgx_init_quote(sgx_target_info_t* target_info);
sgx_status_t SGX_CDECL ocall_remote_attestation(sgx_report_t* report, const struct ra_tls_options* opts, attestation_verification_report_t* attn_report);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
