#include "EncoderEnclave_u.h"
#include <errno.h>

typedef struct ms_t_encoder_init_t {
	int ms_retval;
	cmdline* ms_cl_in;
	size_t ms_cl_size;
	int ms_w;
	int ms_h;
} ms_t_encoder_init_t;

typedef struct ms_t_encode_frame_t {
	int ms_retval;
	unsigned char* ms_frame_sig;
	size_t ms_frame_sig_size;
	uint8_t* ms_frame;
	size_t ms_frame_size;
} ms_t_encode_frame_t;

typedef struct ms_t_verify_cert_t {
	int ms_retval;
	char* ms_vendor_pubkey_str;
	size_t ms_vendor_pubkey_str_size;
	char* ms_cert_str;
	size_t ms_cert_str_size;
} ms_t_verify_cert_t;

typedef struct ms_t_get_sig_size_t {
	size_t* ms_sig_size;
} ms_t_get_sig_size_t;

typedef struct ms_t_get_sig_t {
	unsigned char* ms_sig;
	size_t ms_sig_size;
} ms_t_get_sig_t;

typedef struct ms_t_get_encoded_video_size_t {
	size_t* ms_video_size;
} ms_t_get_encoded_video_size_t;

typedef struct ms_t_get_encoded_video_t {
	unsigned char* ms_video;
	size_t ms_video_size;
} ms_t_get_encoded_video_t;

typedef struct ms_t_create_key_and_x509_t {
	void* ms_cert;
	size_t ms_size_of_cert;
	void* ms_actual_size_of_cert;
	size_t ms_asoc;
} ms_t_create_key_and_x509_t;

typedef struct ms_uprint_t {
	const char* ms_str;
} ms_uprint_t;

typedef struct ms_usgx_exit_t {
	int ms_reason;
} ms_usgx_exit_t;

typedef struct ms_u_sgxssl_ftime_t {
	void* ms_timeptr;
	uint32_t ms_timeb_len;
} ms_u_sgxssl_ftime_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_ocall_sgx_init_quote_t {
	sgx_target_info_t* ms_target_info;
} ms_ocall_sgx_init_quote_t;

typedef struct ms_ocall_remote_attestation_t {
	sgx_report_t* ms_report;
	const struct ra_tls_options* ms_opts;
	attestation_verification_report_t* ms_attn_report;
} ms_ocall_remote_attestation_t;

static sgx_status_t SGX_CDECL EncoderEnclave_uprint(void* pms)
{
	ms_uprint_t* ms = SGX_CAST(ms_uprint_t*, pms);
	uprint(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EncoderEnclave_usgx_exit(void* pms)
{
	ms_usgx_exit_t* ms = SGX_CAST(ms_usgx_exit_t*, pms);
	usgx_exit(ms->ms_reason);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EncoderEnclave_u_sgxssl_ftime(void* pms)
{
	ms_u_sgxssl_ftime_t* ms = SGX_CAST(ms_u_sgxssl_ftime_t*, pms);
	u_sgxssl_ftime(ms->ms_timeptr, ms->ms_timeb_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EncoderEnclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EncoderEnclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EncoderEnclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EncoderEnclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EncoderEnclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EncoderEnclave_ocall_sgx_init_quote(void* pms)
{
	ms_ocall_sgx_init_quote_t* ms = SGX_CAST(ms_ocall_sgx_init_quote_t*, pms);
	ocall_sgx_init_quote(ms->ms_target_info);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EncoderEnclave_ocall_remote_attestation(void* pms)
{
	ms_ocall_remote_attestation_t* ms = SGX_CAST(ms_ocall_remote_attestation_t*, pms);
	ocall_remote_attestation(ms->ms_report, ms->ms_opts, ms->ms_attn_report);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[10];
} ocall_table_EncoderEnclave = {
	10,
	{
		(void*)EncoderEnclave_uprint,
		(void*)EncoderEnclave_usgx_exit,
		(void*)EncoderEnclave_u_sgxssl_ftime,
		(void*)EncoderEnclave_sgx_oc_cpuidex,
		(void*)EncoderEnclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)EncoderEnclave_sgx_thread_set_untrusted_event_ocall,
		(void*)EncoderEnclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)EncoderEnclave_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)EncoderEnclave_ocall_sgx_init_quote,
		(void*)EncoderEnclave_ocall_remote_attestation,
	}
};
sgx_status_t t_encoder_init(sgx_enclave_id_t eid, int* retval, cmdline* cl_in, size_t cl_size, int w, int h)
{
	sgx_status_t status;
	ms_t_encoder_init_t ms;
	ms.ms_cl_in = cl_in;
	ms.ms_cl_size = cl_size;
	ms.ms_w = w;
	ms.ms_h = h;
	status = sgx_ecall(eid, 0, &ocall_table_EncoderEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t t_encode_frame(sgx_enclave_id_t eid, int* retval, unsigned char* frame_sig, size_t frame_sig_size, uint8_t* frame, size_t frame_size)
{
	sgx_status_t status;
	ms_t_encode_frame_t ms;
	ms.ms_frame_sig = frame_sig;
	ms.ms_frame_sig_size = frame_sig_size;
	ms.ms_frame = frame;
	ms.ms_frame_size = frame_size;
	status = sgx_ecall(eid, 1, &ocall_table_EncoderEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t t_verify_cert(sgx_enclave_id_t eid, int* retval, char* vendor_pubkey_str, size_t vendor_pubkey_str_size, char* cert_str, size_t cert_str_size)
{
	sgx_status_t status;
	ms_t_verify_cert_t ms;
	ms.ms_vendor_pubkey_str = vendor_pubkey_str;
	ms.ms_vendor_pubkey_str_size = vendor_pubkey_str_size;
	ms.ms_cert_str = cert_str;
	ms.ms_cert_str_size = cert_str_size;
	status = sgx_ecall(eid, 2, &ocall_table_EncoderEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t t_get_sig_size(sgx_enclave_id_t eid, size_t* sig_size)
{
	sgx_status_t status;
	ms_t_get_sig_size_t ms;
	ms.ms_sig_size = sig_size;
	status = sgx_ecall(eid, 3, &ocall_table_EncoderEnclave, &ms);
	return status;
}

sgx_status_t t_get_sig(sgx_enclave_id_t eid, unsigned char* sig, size_t sig_size)
{
	sgx_status_t status;
	ms_t_get_sig_t ms;
	ms.ms_sig = sig;
	ms.ms_sig_size = sig_size;
	status = sgx_ecall(eid, 4, &ocall_table_EncoderEnclave, &ms);
	return status;
}

sgx_status_t t_get_encoded_video_size(sgx_enclave_id_t eid, size_t* video_size)
{
	sgx_status_t status;
	ms_t_get_encoded_video_size_t ms;
	ms.ms_video_size = video_size;
	status = sgx_ecall(eid, 5, &ocall_table_EncoderEnclave, &ms);
	return status;
}

sgx_status_t t_get_encoded_video(sgx_enclave_id_t eid, unsigned char* video, size_t video_size)
{
	sgx_status_t status;
	ms_t_get_encoded_video_t ms;
	ms.ms_video = video;
	ms.ms_video_size = video_size;
	status = sgx_ecall(eid, 6, &ocall_table_EncoderEnclave, &ms);
	return status;
}

sgx_status_t t_create_key_and_x509(sgx_enclave_id_t eid, void* cert, size_t size_of_cert, void* actual_size_of_cert, size_t asoc)
{
	sgx_status_t status;
	ms_t_create_key_and_x509_t ms;
	ms.ms_cert = cert;
	ms.ms_size_of_cert = size_of_cert;
	ms.ms_actual_size_of_cert = actual_size_of_cert;
	ms.ms_asoc = asoc;
	status = sgx_ecall(eid, 7, &ocall_table_EncoderEnclave, &ms);
	return status;
}

sgx_status_t t_free(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 8, &ocall_table_EncoderEnclave, NULL);
	return status;
}

sgx_status_t dummy(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 9, &ocall_table_EncoderEnclave, NULL);
	return status;
}

