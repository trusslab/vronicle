#ifndef TESTENCLAVE_T_H__
#define TESTENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "../app/basetype.h"
#include "ra.h"
#include "ra-attester.h"
#include "sgx_report.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void t_create_key_and_x509(void* cert, size_t size_of_cert, void* actual_size_of_cert, size_t asoc);
void t_free(void);
int t_sgxver_prepare_decoder(void* input_content_buffer, long int size_of_input_content_buffer, void* md_json, long int md_json_len, void* vendor_pub, long int vendor_pub_len, void* camera_cert, long int camera_cert_len, void* vid_sig, size_t vid_sig_len);
int t_sgxver_decode_single_frame(void* decoded_frame, long int size_of_decoded_frame, void* output_md_json, long int size_of_output_json, void* output_sig, long int size_of_output_sig);
int t_sgxver_decode_content(void* input_content_buffer, long int size_of_input_content_buffer, void* md_json, long int md_json_len, void* vendor_pub, long int vendor_pub_len, void* camera_cert, long int camera_cert_len, void* vid_sig, size_t vid_sig_len, u32* frame_width, u32* frame_height, int* num_of_frames, void* output_rgb_buffer, void* output_sig_buffer, void* output_md_buffer);

sgx_status_t SGX_CDECL uprint(const char* str);
sgx_status_t SGX_CDECL usgx_exit(int reason);
sgx_status_t SGX_CDECL ocall_sgx_init_quote(sgx_target_info_t* target_info);
sgx_status_t SGX_CDECL ocall_remote_attestation(sgx_report_t* report, const struct ra_tls_options* opts, attestation_verification_report_t* attn_report);
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
