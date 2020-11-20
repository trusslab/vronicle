#ifndef TESTENCLAVE_DCAP_T_H__
#define TESTENCLAVE_DCAP_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

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

int t_sgxver_call_apis(void* img_pixels, size_t size_of_img_pixels, void* md_json, size_t size_of_md_json, void* img_sig, size_t size_of_img_sig, void* out_pixels, void* out_md_json, size_t size_of_out_md_json, void* out_img_sig, size_t size_of_out_img_sig);
int t_verify_cert(void* ias_cert, size_t size_of_ias_cert);
void t_create_key_and_x509(void* cert, size_t size_of_cert, void* actual_size_of_cert, size_t asoc);
void t_free(void);

sgx_status_t SGX_CDECL uprint(const char* str);
sgx_status_t SGX_CDECL usgx_exit(int reason);
sgx_status_t SGX_CDECL ocall_sgx_init_quote(sgx_target_info_t* target_info);
sgx_status_t SGX_CDECL ocall_remote_attestation(sgx_report_t* report, const struct ra_tls_options* opts, attestation_verification_report_t* attn_report);
sgx_status_t SGX_CDECL ocall_ecdsa_get_qe_target_info(sgx_target_info_t* qe_target_info);
sgx_status_t SGX_CDECL ocall_ecdsa_get_quote_size(uint32_t* quote_size);
sgx_status_t SGX_CDECL ocall_ecdsa_get_quote(const sgx_report_t* report, uint8_t* quote_buffer, uint32_t quote_size);
sgx_status_t SGX_CDECL ocall_ecdsa_get_supplemental_data_size(uint32_t* supplemental_data_size);
sgx_status_t SGX_CDECL ocall_ecdsa_verify_quote(const uint8_t* quote_buffer, uint32_t quote_size, sgx_ql_qe_report_info_t* qve_report_info, uint32_t* collateral_expiration_status, sgx_ql_qv_result_t* quote_verification_result, uint8_t* supplemental_data, uint32_t supplemental_data_size);
sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
