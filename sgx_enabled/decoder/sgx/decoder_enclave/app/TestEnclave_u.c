#include "TestEnclave_u.h"
#include <errno.h>

typedef struct ms_t_create_key_and_x509_t {
	void* ms_cert;
	size_t ms_size_of_cert;
	void* ms_actual_size_of_cert;
	size_t ms_asoc;
} ms_t_create_key_and_x509_t;

typedef struct ms_t_sgxver_prepare_decoder_t {
	int ms_retval;
	void* ms_input_content_buffer;
	long int ms_size_of_input_content_buffer;
	void* ms_md_json;
	long int ms_md_json_len;
	void* ms_vendor_pub;
	long int ms_vendor_pub_len;
	void* ms_camera_cert;
	long int ms_camera_cert_len;
	void* ms_vid_sig;
	size_t ms_vid_sig_len;
} ms_t_sgxver_prepare_decoder_t;

typedef struct ms_t_sgxver_decode_single_frame_t {
	int ms_retval;
	void* ms_decoded_frame;
	long int ms_size_of_decoded_frame;
	void* ms_output_md_json;
	long int ms_size_of_output_json;
	void* ms_output_sig;
	long int ms_size_of_output_sig;
} ms_t_sgxver_decode_single_frame_t;

typedef struct ms_t_sgxver_decode_content_t {
	int ms_retval;
	void* ms_input_content_buffer;
	long int ms_size_of_input_content_buffer;
	void* ms_md_json;
	long int ms_md_json_len;
	void* ms_vendor_pub;
	long int ms_vendor_pub_len;
	void* ms_camera_cert;
	long int ms_camera_cert_len;
	void* ms_vid_sig;
	size_t ms_vid_sig_len;
	u32* ms_frame_width;
	u32* ms_frame_height;
	int* ms_num_of_frames;
	void* ms_output_rgb_buffer;
	void* ms_output_sig_buffer;
	void* ms_output_md_buffer;
} ms_t_sgxver_decode_content_t;

typedef struct ms_uprint_t {
	const char* ms_str;
} ms_uprint_t;

typedef struct ms_usgx_exit_t {
	int ms_reason;
} ms_usgx_exit_t;

typedef struct ms_ocall_sgx_init_quote_t {
	sgx_target_info_t* ms_target_info;
} ms_ocall_sgx_init_quote_t;

typedef struct ms_ocall_remote_attestation_t {
	sgx_report_t* ms_report;
	const struct ra_tls_options* ms_opts;
	attestation_verification_report_t* ms_attn_report;
} ms_ocall_remote_attestation_t;

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

static sgx_status_t SGX_CDECL TestEnclave_uprint(void* pms)
{
	ms_uprint_t* ms = SGX_CAST(ms_uprint_t*, pms);
	uprint(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_usgx_exit(void* pms)
{
	ms_usgx_exit_t* ms = SGX_CAST(ms_usgx_exit_t*, pms);
	usgx_exit(ms->ms_reason);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_ocall_sgx_init_quote(void* pms)
{
	ms_ocall_sgx_init_quote_t* ms = SGX_CAST(ms_ocall_sgx_init_quote_t*, pms);
	ocall_sgx_init_quote(ms->ms_target_info);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_ocall_remote_attestation(void* pms)
{
	ms_ocall_remote_attestation_t* ms = SGX_CAST(ms_ocall_remote_attestation_t*, pms);
	ocall_remote_attestation(ms->ms_report, ms->ms_opts, ms->ms_attn_report);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_u_sgxssl_ftime(void* pms)
{
	ms_u_sgxssl_ftime_t* ms = SGX_CAST(ms_u_sgxssl_ftime_t*, pms);
	u_sgxssl_ftime(ms->ms_timeptr, ms->ms_timeb_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[10];
} ocall_table_TestEnclave = {
	10,
	{
		(void*)TestEnclave_uprint,
		(void*)TestEnclave_usgx_exit,
		(void*)TestEnclave_ocall_sgx_init_quote,
		(void*)TestEnclave_ocall_remote_attestation,
		(void*)TestEnclave_u_sgxssl_ftime,
		(void*)TestEnclave_sgx_oc_cpuidex,
		(void*)TestEnclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)TestEnclave_sgx_thread_set_untrusted_event_ocall,
		(void*)TestEnclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)TestEnclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t t_create_key_and_x509(sgx_enclave_id_t eid, void* cert, size_t size_of_cert, void* actual_size_of_cert, size_t asoc)
{
	sgx_status_t status;
	ms_t_create_key_and_x509_t ms;
	ms.ms_cert = cert;
	ms.ms_size_of_cert = size_of_cert;
	ms.ms_actual_size_of_cert = actual_size_of_cert;
	ms.ms_asoc = asoc;
	status = sgx_ecall(eid, 0, &ocall_table_TestEnclave, &ms);
	return status;
}

sgx_status_t t_free(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_TestEnclave, NULL);
	return status;
}

sgx_status_t t_sgxver_prepare_decoder(sgx_enclave_id_t eid, int* retval, void* input_content_buffer, long int size_of_input_content_buffer, void* md_json, long int md_json_len, void* vendor_pub, long int vendor_pub_len, void* camera_cert, long int camera_cert_len, void* vid_sig, size_t vid_sig_len)
{
	sgx_status_t status;
	ms_t_sgxver_prepare_decoder_t ms;
	ms.ms_input_content_buffer = input_content_buffer;
	ms.ms_size_of_input_content_buffer = size_of_input_content_buffer;
	ms.ms_md_json = md_json;
	ms.ms_md_json_len = md_json_len;
	ms.ms_vendor_pub = vendor_pub;
	ms.ms_vendor_pub_len = vendor_pub_len;
	ms.ms_camera_cert = camera_cert;
	ms.ms_camera_cert_len = camera_cert_len;
	ms.ms_vid_sig = vid_sig;
	ms.ms_vid_sig_len = vid_sig_len;
	status = sgx_ecall(eid, 2, &ocall_table_TestEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t t_sgxver_decode_single_frame(sgx_enclave_id_t eid, int* retval, void* decoded_frame, long int size_of_decoded_frame, void* output_md_json, long int size_of_output_json, void* output_sig, long int size_of_output_sig)
{
	sgx_status_t status;
	ms_t_sgxver_decode_single_frame_t ms;
	ms.ms_decoded_frame = decoded_frame;
	ms.ms_size_of_decoded_frame = size_of_decoded_frame;
	ms.ms_output_md_json = output_md_json;
	ms.ms_size_of_output_json = size_of_output_json;
	ms.ms_output_sig = output_sig;
	ms.ms_size_of_output_sig = size_of_output_sig;
	status = sgx_ecall(eid, 3, &ocall_table_TestEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t t_sgxver_decode_content(sgx_enclave_id_t eid, int* retval, void* input_content_buffer, long int size_of_input_content_buffer, void* md_json, long int md_json_len, void* vendor_pub, long int vendor_pub_len, void* camera_cert, long int camera_cert_len, void* vid_sig, size_t vid_sig_len, u32* frame_width, u32* frame_height, int* num_of_frames, void* output_rgb_buffer, void* output_sig_buffer, void* output_md_buffer)
{
	sgx_status_t status;
	ms_t_sgxver_decode_content_t ms;
	ms.ms_input_content_buffer = input_content_buffer;
	ms.ms_size_of_input_content_buffer = size_of_input_content_buffer;
	ms.ms_md_json = md_json;
	ms.ms_md_json_len = md_json_len;
	ms.ms_vendor_pub = vendor_pub;
	ms.ms_vendor_pub_len = vendor_pub_len;
	ms.ms_camera_cert = camera_cert;
	ms.ms_camera_cert_len = camera_cert_len;
	ms.ms_vid_sig = vid_sig;
	ms.ms_vid_sig_len = vid_sig_len;
	ms.ms_frame_width = frame_width;
	ms.ms_frame_height = frame_height;
	ms.ms_num_of_frames = num_of_frames;
	ms.ms_output_rgb_buffer = output_rgb_buffer;
	ms.ms_output_sig_buffer = output_sig_buffer;
	ms.ms_output_md_buffer = output_md_buffer;
	status = sgx_ecall(eid, 4, &ocall_table_TestEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

