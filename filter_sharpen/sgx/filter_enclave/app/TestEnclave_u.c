#include "TestEnclave_u.h"
#include <errno.h>

typedef struct ms_t_sgxssl_call_apis_t {
	void* ms_evp_pkey_v;
} ms_t_sgxssl_call_apis_t;

typedef struct ms_t_sgxver_call_apis_t {
	void* ms_image_pixels;
	size_t ms_size_of_image_pixels;
	int ms_image_width;
	int ms_image_height;
	void* ms_hash_of_original_image;
	int ms_size_of_hooi;
	void* ms_signature;
	size_t ms_size_of_actual_signature;
	void* ms_original_vendor_pub_str;
	long int ms_original_vendor_pub_str_len;
	void* ms_original_cert_str;
	long int ms_original_cert_str_len;
	void* ms_processed_pixels;
	void* ms_runtime_result;
	int ms_size_of_runtime_result;
	void* ms_char_array_for_processed_img_sign;
	int ms_size_of_cafpis;
	void* ms_hash_of_processed_image;
	int ms_size_of_hopi;
	void* ms_processed_img_signautre;
	size_t ms_size_of_pis;
	void* ms_size_of_actual_processed_img_signature;
	size_t ms_sizeof_soapis;
} ms_t_sgxver_call_apis_t;

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

static const struct {
	size_t nr_ocall;
	void * table[10];
} ocall_table_TestEnclave = {
	10,
	{
		(void*)TestEnclave_uprint,
		(void*)TestEnclave_usgx_exit,
		(void*)TestEnclave_u_sgxssl_ftime,
		(void*)TestEnclave_sgx_oc_cpuidex,
		(void*)TestEnclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)TestEnclave_sgx_thread_set_untrusted_event_ocall,
		(void*)TestEnclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)TestEnclave_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)TestEnclave_ocall_sgx_init_quote,
		(void*)TestEnclave_ocall_remote_attestation,
	}
};
sgx_status_t t_sgxssl_call_apis(sgx_enclave_id_t eid, void* evp_pkey_v)
{
	sgx_status_t status;
	ms_t_sgxssl_call_apis_t ms;
	ms.ms_evp_pkey_v = evp_pkey_v;
	status = sgx_ecall(eid, 0, &ocall_table_TestEnclave, &ms);
	return status;
}

sgx_status_t t_sgxver_call_apis(sgx_enclave_id_t eid, void* image_pixels, size_t size_of_image_pixels, int image_width, int image_height, void* hash_of_original_image, int size_of_hooi, void* signature, size_t size_of_actual_signature, void* original_vendor_pub_str, long int original_vendor_pub_str_len, void* original_cert_str, long int original_cert_str_len, void* processed_pixels, void* runtime_result, int size_of_runtime_result, void* char_array_for_processed_img_sign, int size_of_cafpis, void* hash_of_processed_image, int size_of_hopi, void* processed_img_signautre, size_t size_of_pis, void* size_of_actual_processed_img_signature, size_t sizeof_soapis)
{
	sgx_status_t status;
	ms_t_sgxver_call_apis_t ms;
	ms.ms_image_pixels = image_pixels;
	ms.ms_size_of_image_pixels = size_of_image_pixels;
	ms.ms_image_width = image_width;
	ms.ms_image_height = image_height;
	ms.ms_hash_of_original_image = hash_of_original_image;
	ms.ms_size_of_hooi = size_of_hooi;
	ms.ms_signature = signature;
	ms.ms_size_of_actual_signature = size_of_actual_signature;
	ms.ms_original_vendor_pub_str = original_vendor_pub_str;
	ms.ms_original_vendor_pub_str_len = original_vendor_pub_str_len;
	ms.ms_original_cert_str = original_cert_str;
	ms.ms_original_cert_str_len = original_cert_str_len;
	ms.ms_processed_pixels = processed_pixels;
	ms.ms_runtime_result = runtime_result;
	ms.ms_size_of_runtime_result = size_of_runtime_result;
	ms.ms_char_array_for_processed_img_sign = char_array_for_processed_img_sign;
	ms.ms_size_of_cafpis = size_of_cafpis;
	ms.ms_hash_of_processed_image = hash_of_processed_image;
	ms.ms_size_of_hopi = size_of_hopi;
	ms.ms_processed_img_signautre = processed_img_signautre;
	ms.ms_size_of_pis = size_of_pis;
	ms.ms_size_of_actual_processed_img_signature = size_of_actual_processed_img_signature;
	ms.ms_sizeof_soapis = sizeof_soapis;
	status = sgx_ecall(eid, 1, &ocall_table_TestEnclave, &ms);
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
	status = sgx_ecall(eid, 2, &ocall_table_TestEnclave, &ms);
	return status;
}

sgx_status_t t_free(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 3, &ocall_table_TestEnclave, NULL);
	return status;
}

sgx_status_t dummy(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 4, &ocall_table_TestEnclave, NULL);
	return status;
}

