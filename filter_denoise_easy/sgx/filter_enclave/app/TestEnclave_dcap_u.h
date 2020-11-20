#ifndef TESTENCLAVE_DCAP_U_H__
#define TESTENCLAVE_DCAP_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "ra.h"
#include "ra-attester.h"
#include "sgx_report.h"
#include "sgx_ql_quote.h"
#include "sgx_qve_header.h"

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
#ifndef OCALL_SGX_INIT_QUOTE_DEFINED__
#define OCALL_SGX_INIT_QUOTE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_init_quote, (sgx_target_info_t* target_info));
#endif
#ifndef OCALL_REMOTE_ATTESTATION_DEFINED__
#define OCALL_REMOTE_ATTESTATION_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_remote_attestation, (sgx_report_t* report, const struct ra_tls_options* opts, attestation_verification_report_t* attn_report));
#endif
#ifndef OCALL_ECDSA_GET_QE_TARGET_INFO_DEFINED__
#define OCALL_ECDSA_GET_QE_TARGET_INFO_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_ecdsa_get_qe_target_info, (sgx_target_info_t* qe_target_info));
#endif
#ifndef OCALL_ECDSA_GET_QUOTE_SIZE_DEFINED__
#define OCALL_ECDSA_GET_QUOTE_SIZE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_ecdsa_get_quote_size, (uint32_t* quote_size));
#endif
#ifndef OCALL_ECDSA_GET_QUOTE_DEFINED__
#define OCALL_ECDSA_GET_QUOTE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_ecdsa_get_quote, (const sgx_report_t* report, uint8_t* quote_buffer, uint32_t quote_size));
#endif
#ifndef OCALL_ECDSA_GET_SUPPLEMENTAL_DATA_SIZE_DEFINED__
#define OCALL_ECDSA_GET_SUPPLEMENTAL_DATA_SIZE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_ecdsa_get_supplemental_data_size, (uint32_t* supplemental_data_size));
#endif
#ifndef OCALL_ECDSA_VERIFY_QUOTE_DEFINED__
#define OCALL_ECDSA_VERIFY_QUOTE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_ecdsa_verify_quote, (const uint8_t* quote_buffer, uint32_t quote_size, sgx_ql_qe_report_info_t* qve_report_info, uint32_t* collateral_expiration_status, sgx_ql_qv_result_t* quote_verification_result, uint8_t* supplemental_data, uint32_t supplemental_data_size));
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

sgx_status_t t_sgxver_call_apis(sgx_enclave_id_t eid, int* retval, void* img_pixels, size_t size_of_img_pixels, void* md_json, size_t size_of_md_json, void* img_sig, size_t size_of_img_sig, void* out_pixels, void* out_md_json, size_t size_of_out_md_json, void* out_img_sig, size_t size_of_out_img_sig);
sgx_status_t t_verify_cert(sgx_enclave_id_t eid, int* retval, void* ias_cert, size_t size_of_ias_cert);
sgx_status_t t_create_key_and_x509(sgx_enclave_id_t eid, void* cert, size_t size_of_cert, void* actual_size_of_cert, size_t asoc);
sgx_status_t t_free(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
