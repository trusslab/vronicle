#include "TestEnclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_t_sgxssl_call_apis(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_t_sgxssl_call_apis_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_t_sgxssl_call_apis_t* ms = SGX_CAST(ms_t_sgxssl_call_apis_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_evp_pkey_v = ms->ms_evp_pkey_v;



	t_sgxssl_call_apis(_tmp_evp_pkey_v);


	return status;
}

static sgx_status_t SGX_CDECL sgx_t_sgxver_call_apis(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_t_sgxver_call_apis_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_t_sgxver_call_apis_t* ms = SGX_CAST(ms_t_sgxver_call_apis_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_image_pixels = ms->ms_image_pixels;
	size_t _tmp_size_of_image_pixels = ms->ms_size_of_image_pixels;
	size_t _len_image_pixels = _tmp_size_of_image_pixels;
	void* _in_image_pixels = NULL;
	void* _tmp_hash_of_original_image = ms->ms_hash_of_original_image;
	int _tmp_size_of_hooi = ms->ms_size_of_hooi;
	size_t _len_hash_of_original_image = _tmp_size_of_hooi;
	void* _in_hash_of_original_image = NULL;
	void* _tmp_signature = ms->ms_signature;
	size_t _tmp_size_of_actual_signature = ms->ms_size_of_actual_signature;
	size_t _len_signature = _tmp_size_of_actual_signature;
	void* _in_signature = NULL;
	void* _tmp_original_vendor_pub_str = ms->ms_original_vendor_pub_str;
	long int _tmp_original_vendor_pub_str_len = ms->ms_original_vendor_pub_str_len;
	size_t _len_original_vendor_pub_str = _tmp_original_vendor_pub_str_len;
	void* _in_original_vendor_pub_str = NULL;
	void* _tmp_original_cert_str = ms->ms_original_cert_str;
	long int _tmp_original_cert_str_len = ms->ms_original_cert_str_len;
	size_t _len_original_cert_str = _tmp_original_cert_str_len;
	void* _in_original_cert_str = NULL;
	void* _tmp_processed_pixels = ms->ms_processed_pixels;
	size_t _len_processed_pixels = _tmp_size_of_image_pixels;
	void* _in_processed_pixels = NULL;
	void* _tmp_runtime_result = ms->ms_runtime_result;
	int _tmp_size_of_runtime_result = ms->ms_size_of_runtime_result;
	size_t _len_runtime_result = _tmp_size_of_runtime_result;
	void* _in_runtime_result = NULL;
	void* _tmp_char_array_for_processed_img_sign = ms->ms_char_array_for_processed_img_sign;
	int _tmp_size_of_cafpis = ms->ms_size_of_cafpis;
	size_t _len_char_array_for_processed_img_sign = _tmp_size_of_cafpis;
	void* _in_char_array_for_processed_img_sign = NULL;
	void* _tmp_hash_of_processed_image = ms->ms_hash_of_processed_image;
	int _tmp_size_of_hopi = ms->ms_size_of_hopi;
	size_t _len_hash_of_processed_image = _tmp_size_of_hopi;
	void* _in_hash_of_processed_image = NULL;
	void* _tmp_processed_img_signautre = ms->ms_processed_img_signautre;
	size_t _tmp_size_of_pis = ms->ms_size_of_pis;
	size_t _len_processed_img_signautre = _tmp_size_of_pis;
	void* _in_processed_img_signautre = NULL;
	void* _tmp_size_of_actual_processed_img_signature = ms->ms_size_of_actual_processed_img_signature;
	size_t _tmp_sizeof_soapis = ms->ms_sizeof_soapis;
	size_t _len_size_of_actual_processed_img_signature = _tmp_sizeof_soapis;
	void* _in_size_of_actual_processed_img_signature = NULL;

	CHECK_UNIQUE_POINTER(_tmp_image_pixels, _len_image_pixels);
	CHECK_UNIQUE_POINTER(_tmp_hash_of_original_image, _len_hash_of_original_image);
	CHECK_UNIQUE_POINTER(_tmp_signature, _len_signature);
	CHECK_UNIQUE_POINTER(_tmp_original_vendor_pub_str, _len_original_vendor_pub_str);
	CHECK_UNIQUE_POINTER(_tmp_original_cert_str, _len_original_cert_str);
	CHECK_UNIQUE_POINTER(_tmp_processed_pixels, _len_processed_pixels);
	CHECK_UNIQUE_POINTER(_tmp_runtime_result, _len_runtime_result);
	CHECK_UNIQUE_POINTER(_tmp_char_array_for_processed_img_sign, _len_char_array_for_processed_img_sign);
	CHECK_UNIQUE_POINTER(_tmp_hash_of_processed_image, _len_hash_of_processed_image);
	CHECK_UNIQUE_POINTER(_tmp_processed_img_signautre, _len_processed_img_signautre);
	CHECK_UNIQUE_POINTER(_tmp_size_of_actual_processed_img_signature, _len_size_of_actual_processed_img_signature);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_image_pixels != NULL && _len_image_pixels != 0) {
		_in_image_pixels = (void*)malloc(_len_image_pixels);
		if (_in_image_pixels == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_image_pixels, _len_image_pixels, _tmp_image_pixels, _len_image_pixels)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_hash_of_original_image != NULL && _len_hash_of_original_image != 0) {
		_in_hash_of_original_image = (void*)malloc(_len_hash_of_original_image);
		if (_in_hash_of_original_image == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_hash_of_original_image, _len_hash_of_original_image, _tmp_hash_of_original_image, _len_hash_of_original_image)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_signature != NULL && _len_signature != 0) {
		_in_signature = (void*)malloc(_len_signature);
		if (_in_signature == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_signature, _len_signature, _tmp_signature, _len_signature)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_original_vendor_pub_str != NULL && _len_original_vendor_pub_str != 0) {
		_in_original_vendor_pub_str = (void*)malloc(_len_original_vendor_pub_str);
		if (_in_original_vendor_pub_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_original_vendor_pub_str, _len_original_vendor_pub_str, _tmp_original_vendor_pub_str, _len_original_vendor_pub_str)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_original_cert_str != NULL && _len_original_cert_str != 0) {
		_in_original_cert_str = (void*)malloc(_len_original_cert_str);
		if (_in_original_cert_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_original_cert_str, _len_original_cert_str, _tmp_original_cert_str, _len_original_cert_str)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_processed_pixels != NULL && _len_processed_pixels != 0) {
		if ((_in_processed_pixels = (void*)malloc(_len_processed_pixels)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_processed_pixels, 0, _len_processed_pixels);
	}
	if (_tmp_runtime_result != NULL && _len_runtime_result != 0) {
		if ((_in_runtime_result = (void*)malloc(_len_runtime_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_runtime_result, 0, _len_runtime_result);
	}
	if (_tmp_char_array_for_processed_img_sign != NULL && _len_char_array_for_processed_img_sign != 0) {
		if ((_in_char_array_for_processed_img_sign = (void*)malloc(_len_char_array_for_processed_img_sign)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_char_array_for_processed_img_sign, 0, _len_char_array_for_processed_img_sign);
	}
	if (_tmp_hash_of_processed_image != NULL && _len_hash_of_processed_image != 0) {
		if ((_in_hash_of_processed_image = (void*)malloc(_len_hash_of_processed_image)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_hash_of_processed_image, 0, _len_hash_of_processed_image);
	}
	if (_tmp_processed_img_signautre != NULL && _len_processed_img_signautre != 0) {
		if ((_in_processed_img_signautre = (void*)malloc(_len_processed_img_signautre)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_processed_img_signautre, 0, _len_processed_img_signautre);
	}
	if (_tmp_size_of_actual_processed_img_signature != NULL && _len_size_of_actual_processed_img_signature != 0) {
		if ((_in_size_of_actual_processed_img_signature = (void*)malloc(_len_size_of_actual_processed_img_signature)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_size_of_actual_processed_img_signature, 0, _len_size_of_actual_processed_img_signature);
	}

	t_sgxver_call_apis(_in_image_pixels, _tmp_size_of_image_pixels, ms->ms_image_width, ms->ms_image_height, _in_hash_of_original_image, _tmp_size_of_hooi, _in_signature, _tmp_size_of_actual_signature, _in_original_vendor_pub_str, _tmp_original_vendor_pub_str_len, _in_original_cert_str, _tmp_original_cert_str_len, _in_processed_pixels, _in_runtime_result, _tmp_size_of_runtime_result, _in_char_array_for_processed_img_sign, _tmp_size_of_cafpis, _in_hash_of_processed_image, _tmp_size_of_hopi, _in_processed_img_signautre, _tmp_size_of_pis, _in_size_of_actual_processed_img_signature, _tmp_sizeof_soapis);
	if (_in_processed_pixels) {
		if (memcpy_s(_tmp_processed_pixels, _len_processed_pixels, _in_processed_pixels, _len_processed_pixels)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_runtime_result) {
		if (memcpy_s(_tmp_runtime_result, _len_runtime_result, _in_runtime_result, _len_runtime_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_char_array_for_processed_img_sign) {
		if (memcpy_s(_tmp_char_array_for_processed_img_sign, _len_char_array_for_processed_img_sign, _in_char_array_for_processed_img_sign, _len_char_array_for_processed_img_sign)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_hash_of_processed_image) {
		if (memcpy_s(_tmp_hash_of_processed_image, _len_hash_of_processed_image, _in_hash_of_processed_image, _len_hash_of_processed_image)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_processed_img_signautre) {
		if (memcpy_s(_tmp_processed_img_signautre, _len_processed_img_signautre, _in_processed_img_signautre, _len_processed_img_signautre)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_size_of_actual_processed_img_signature) {
		if (memcpy_s(_tmp_size_of_actual_processed_img_signature, _len_size_of_actual_processed_img_signature, _in_size_of_actual_processed_img_signature, _len_size_of_actual_processed_img_signature)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_image_pixels) free(_in_image_pixels);
	if (_in_hash_of_original_image) free(_in_hash_of_original_image);
	if (_in_signature) free(_in_signature);
	if (_in_original_vendor_pub_str) free(_in_original_vendor_pub_str);
	if (_in_original_cert_str) free(_in_original_cert_str);
	if (_in_processed_pixels) free(_in_processed_pixels);
	if (_in_runtime_result) free(_in_runtime_result);
	if (_in_char_array_for_processed_img_sign) free(_in_char_array_for_processed_img_sign);
	if (_in_hash_of_processed_image) free(_in_hash_of_processed_image);
	if (_in_processed_img_signautre) free(_in_processed_img_signautre);
	if (_in_size_of_actual_processed_img_signature) free(_in_size_of_actual_processed_img_signature);
	return status;
}

static sgx_status_t SGX_CDECL sgx_t_create_key_and_x509(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_t_create_key_and_x509_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_t_create_key_and_x509_t* ms = SGX_CAST(ms_t_create_key_and_x509_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_cert = ms->ms_cert;
	size_t _tmp_size_of_cert = ms->ms_size_of_cert;
	size_t _len_cert = _tmp_size_of_cert;
	void* _in_cert = NULL;
	void* _tmp_actual_size_of_cert = ms->ms_actual_size_of_cert;
	size_t _tmp_asoc = ms->ms_asoc;
	size_t _len_actual_size_of_cert = _tmp_asoc;
	void* _in_actual_size_of_cert = NULL;

	CHECK_UNIQUE_POINTER(_tmp_cert, _len_cert);
	CHECK_UNIQUE_POINTER(_tmp_actual_size_of_cert, _len_actual_size_of_cert);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_cert != NULL && _len_cert != 0) {
		if ((_in_cert = (void*)malloc(_len_cert)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_cert, 0, _len_cert);
	}
	if (_tmp_actual_size_of_cert != NULL && _len_actual_size_of_cert != 0) {
		if ((_in_actual_size_of_cert = (void*)malloc(_len_actual_size_of_cert)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_actual_size_of_cert, 0, _len_actual_size_of_cert);
	}

	t_create_key_and_x509(_in_cert, _tmp_size_of_cert, _in_actual_size_of_cert, _tmp_asoc);
	if (_in_cert) {
		if (memcpy_s(_tmp_cert, _len_cert, _in_cert, _len_cert)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_actual_size_of_cert) {
		if (memcpy_s(_tmp_actual_size_of_cert, _len_actual_size_of_cert, _in_actual_size_of_cert, _len_actual_size_of_cert)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_cert) free(_in_cert);
	if (_in_actual_size_of_cert) free(_in_actual_size_of_cert);
	return status;
}

static sgx_status_t SGX_CDECL sgx_t_free(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	t_free();
	return status;
}

static sgx_status_t SGX_CDECL sgx_dummy(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	dummy();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[5];
} g_ecall_table = {
	5,
	{
		{(void*)(uintptr_t)sgx_t_sgxssl_call_apis, 0, 0},
		{(void*)(uintptr_t)sgx_t_sgxver_call_apis, 0, 0},
		{(void*)(uintptr_t)sgx_t_create_key_and_x509, 0, 0},
		{(void*)(uintptr_t)sgx_t_free, 0, 0},
		{(void*)(uintptr_t)sgx_dummy, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[10][5];
} g_dyn_entry_table = {
	10,
	{
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL uprint(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_uprint_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_uprint_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_uprint_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_uprint_t));
	ocalloc_size -= sizeof(ms_uprint_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL usgx_exit(int reason)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_usgx_exit_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_usgx_exit_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_usgx_exit_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_usgx_exit_t));
	ocalloc_size -= sizeof(ms_usgx_exit_t);

	ms->ms_reason = reason;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_timeptr = timeb_len;

	ms_u_sgxssl_ftime_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_ftime_t);
	void *__tmp = NULL;

	void *__tmp_timeptr = NULL;

	CHECK_ENCLAVE_POINTER(timeptr, _len_timeptr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (timeptr != NULL) ? _len_timeptr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_ftime_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_ftime_t));
	ocalloc_size -= sizeof(ms_u_sgxssl_ftime_t);

	if (timeptr != NULL) {
		ms->ms_timeptr = (void*)__tmp;
		__tmp_timeptr = __tmp;
		memset(__tmp_timeptr, 0, _len_timeptr);
		__tmp = (void *)((size_t)__tmp + _len_timeptr);
		ocalloc_size -= _len_timeptr;
	} else {
		ms->ms_timeptr = NULL;
	}
	
	ms->ms_timeb_len = timeb_len;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (timeptr) {
			if (memcpy_s((void*)timeptr, _len_timeptr, __tmp_timeptr, _len_timeptr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_init_quote(sgx_target_info_t* target_info)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_target_info = sizeof(sgx_target_info_t);

	ms_ocall_sgx_init_quote_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_init_quote_t);
	void *__tmp = NULL;

	void *__tmp_target_info = NULL;

	CHECK_ENCLAVE_POINTER(target_info, _len_target_info);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (target_info != NULL) ? _len_target_info : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_init_quote_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_init_quote_t));
	ocalloc_size -= sizeof(ms_ocall_sgx_init_quote_t);

	if (target_info != NULL) {
		ms->ms_target_info = (sgx_target_info_t*)__tmp;
		__tmp_target_info = __tmp;
		memset(__tmp_target_info, 0, _len_target_info);
		__tmp = (void *)((size_t)__tmp + _len_target_info);
		ocalloc_size -= _len_target_info;
	} else {
		ms->ms_target_info = NULL;
	}
	
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (target_info) {
			if (memcpy_s((void*)target_info, _len_target_info, __tmp_target_info, _len_target_info)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_remote_attestation(sgx_report_t* report, const struct ra_tls_options* opts, attestation_verification_report_t* attn_report)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_report = sizeof(sgx_report_t);
	size_t _len_opts = sizeof(struct ra_tls_options);
	size_t _len_attn_report = sizeof(attestation_verification_report_t);

	ms_ocall_remote_attestation_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_remote_attestation_t);
	void *__tmp = NULL;

	void *__tmp_attn_report = NULL;

	CHECK_ENCLAVE_POINTER(report, _len_report);
	CHECK_ENCLAVE_POINTER(opts, _len_opts);
	CHECK_ENCLAVE_POINTER(attn_report, _len_attn_report);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (report != NULL) ? _len_report : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (opts != NULL) ? _len_opts : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (attn_report != NULL) ? _len_attn_report : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_remote_attestation_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_remote_attestation_t));
	ocalloc_size -= sizeof(ms_ocall_remote_attestation_t);

	if (report != NULL) {
		ms->ms_report = (sgx_report_t*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, report, _len_report)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_report);
		ocalloc_size -= _len_report;
	} else {
		ms->ms_report = NULL;
	}
	
	if (opts != NULL) {
		ms->ms_opts = (const struct ra_tls_options*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, opts, _len_opts)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_opts);
		ocalloc_size -= _len_opts;
	} else {
		ms->ms_opts = NULL;
	}
	
	if (attn_report != NULL) {
		ms->ms_attn_report = (attestation_verification_report_t*)__tmp;
		__tmp_attn_report = __tmp;
		memset(__tmp_attn_report, 0, _len_attn_report);
		__tmp = (void *)((size_t)__tmp + _len_attn_report);
		ocalloc_size -= _len_attn_report;
	} else {
		ms->ms_attn_report = NULL;
	}
	
	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (attn_report) {
			if (memcpy_s((void*)attn_report, _len_attn_report, __tmp_attn_report, _len_attn_report)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

