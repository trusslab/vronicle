#ifndef ENCODERENCLAVE_T_H__
#define ENCODERENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "common.h"
#include "ra.h"
#include "ra-attester.h"
#include "sgx_report.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int t_encoder_init(cmdline* cl_in, size_t cl_size, int w, int h);
int t_encode_frame(unsigned char* frame_sig, size_t frame_sig_size, uint8_t* frame, size_t frame_size);
int t_verify_cert(char* vendor_pubkey_str, size_t vendor_pubkey_str_size, char* cert_str, size_t cert_str_size);
void t_get_sig_size(size_t* sig_size);
void t_get_sig(unsigned char* sig, size_t sig_size);
void t_get_encoded_video_size(size_t* video_size);
void t_get_encoded_video(unsigned char* video, size_t video_size);
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
