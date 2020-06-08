#ifndef TESTENCLAVE_U_H__
#define TESTENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "ra.h"
#include "ra-attester.h"
#include "sgx_report.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef UPRINT_DEFINED__
#define UPRINT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, uprint, (const char* str));
#endif
#ifndef USGX_EXIT_DEFINED__
#define USGX_EXIT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, usgx_exit, (int reason));
#endif
#ifndef U_SGXSSL_FTIME_DEFINED__
#define U_SGXSSL_FTIME_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxssl_ftime, (void* timeptr, uint32_t timeb_len));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif
#ifndef OCALL_SGX_INIT_QUOTE_DEFINED__
#define OCALL_SGX_INIT_QUOTE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_init_quote, (sgx_target_info_t* target_info));
#endif
#ifndef OCALL_REMOTE_ATTESTATION_DEFINED__
#define OCALL_REMOTE_ATTESTATION_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_remote_attestation, (sgx_report_t* report, const struct ra_tls_options* opts, attestation_verification_report_t* attn_report));
#endif

sgx_status_t t_sgxssl_call_apis(sgx_enclave_id_t eid, void* evp_pkey_v);
sgx_status_t t_sgxver_call_apis(sgx_enclave_id_t eid, void* image_pixels, size_t size_of_image_pixels, int image_width, int image_height, void* hash_of_original_image, int size_of_hooi, void* signature, size_t size_of_actual_signature, void* original_pub_key_str, long int original_pub_key_str_len, void* processed_pixels, void* runtime_result, int size_of_runtime_result, void* char_array_for_processed_img_sign, int size_of_cafpis, void* hash_of_processed_image, int size_of_hopi, void* filter_pri_key_str, long int filter_pri_key_str_len, void* processed_img_signautre, size_t size_of_pis, void* size_of_actual_processed_img_signature, size_t sizeof_soapis);
sgx_status_t dummy(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
