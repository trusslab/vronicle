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


typedef struct ms_t_sgxver_call_apis_t {
	int ms_retval;
	void* ms_img_pixels;
	size_t ms_size_of_img_pixels;
	void* ms_md_json;
	size_t ms_size_of_md_json;
	void* ms_img_sig;
	size_t ms_size_of_img_sig;
	void* ms_out_pixels;
	void* ms_out_md_json;
	size_t ms_size_of_out_md_json;
	void* ms_out_img_sig;
	size_t ms_size_of_out_img_sig;
} ms_t_sgxver_call_apis_t;

typedef struct ms_t_verify_cert_t {
	int ms_retval;
	void* ms_ias_cert;
	size_t ms_size_of_ias_cert;
} ms_t_verify_cert_t;

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

static sgx_status_t SGX_CDECL sgx_t_sgxver_call_apis(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_t_sgxver_call_apis_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_t_sgxver_call_apis_t* ms = SGX_CAST(ms_t_sgxver_call_apis_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_img_pixels = ms->ms_img_pixels;
	size_t _tmp_size_of_img_pixels = ms->ms_size_of_img_pixels;
	size_t _len_img_pixels = _tmp_size_of_img_pixels;
	void* _in_img_pixels = NULL;
	void* _tmp_md_json = ms->ms_md_json;
	size_t _tmp_size_of_md_json = ms->ms_size_of_md_json;
	size_t _len_md_json = _tmp_size_of_md_json;
	void* _in_md_json = NULL;
	void* _tmp_img_sig = ms->ms_img_sig;
	size_t _tmp_size_of_img_sig = ms->ms_size_of_img_sig;
	size_t _len_img_sig = _tmp_size_of_img_sig;
	void* _in_img_sig = NULL;
	void* _tmp_out_pixels = ms->ms_out_pixels;
	size_t _len_out_pixels = _tmp_size_of_img_pixels;
	void* _in_out_pixels = NULL;
	void* _tmp_out_md_json = ms->ms_out_md_json;
	size_t _tmp_size_of_out_md_json = ms->ms_size_of_out_md_json;
	size_t _len_out_md_json = _tmp_size_of_out_md_json;
	void* _in_out_md_json = NULL;
	void* _tmp_out_img_sig = ms->ms_out_img_sig;
	size_t _tmp_size_of_out_img_sig = ms->ms_size_of_out_img_sig;
	size_t _len_out_img_sig = _tmp_size_of_out_img_sig;
	void* _in_out_img_sig = NULL;

	CHECK_UNIQUE_POINTER(_tmp_img_pixels, _len_img_pixels);
	CHECK_UNIQUE_POINTER(_tmp_md_json, _len_md_json);
	CHECK_UNIQUE_POINTER(_tmp_img_sig, _len_img_sig);
	CHECK_UNIQUE_POINTER(_tmp_out_pixels, _len_out_pixels);
	CHECK_UNIQUE_POINTER(_tmp_out_md_json, _len_out_md_json);
	CHECK_UNIQUE_POINTER(_tmp_out_img_sig, _len_out_img_sig);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_img_pixels != NULL && _len_img_pixels != 0) {
		_in_img_pixels = (void*)malloc(_len_img_pixels);
		if (_in_img_pixels == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_img_pixels, _len_img_pixels, _tmp_img_pixels, _len_img_pixels)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_md_json != NULL && _len_md_json != 0) {
		_in_md_json = (void*)malloc(_len_md_json);
		if (_in_md_json == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_md_json, _len_md_json, _tmp_md_json, _len_md_json)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_img_sig != NULL && _len_img_sig != 0) {
		_in_img_sig = (void*)malloc(_len_img_sig);
		if (_in_img_sig == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_img_sig, _len_img_sig, _tmp_img_sig, _len_img_sig)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_out_pixels != NULL && _len_out_pixels != 0) {
		if ((_in_out_pixels = (void*)malloc(_len_out_pixels)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out_pixels, 0, _len_out_pixels);
	}
	if (_tmp_out_md_json != NULL && _len_out_md_json != 0) {
		if ((_in_out_md_json = (void*)malloc(_len_out_md_json)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out_md_json, 0, _len_out_md_json);
	}
	if (_tmp_out_img_sig != NULL && _len_out_img_sig != 0) {
		if ((_in_out_img_sig = (void*)malloc(_len_out_img_sig)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out_img_sig, 0, _len_out_img_sig);
	}

	ms->ms_retval = t_sgxver_call_apis(_in_img_pixels, _tmp_size_of_img_pixels, _in_md_json, _tmp_size_of_md_json, _in_img_sig, _tmp_size_of_img_sig, _in_out_pixels, _in_out_md_json, _tmp_size_of_out_md_json, _in_out_img_sig, _tmp_size_of_out_img_sig);
err:
	if (_in_img_pixels) free(_in_img_pixels);
	if (_in_md_json) free(_in_md_json);
	if (_in_img_sig) free(_in_img_sig);
	if (_in_out_pixels) {
		if (memcpy_s(_tmp_out_pixels, _len_out_pixels, _in_out_pixels, _len_out_pixels)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_out_pixels);
	}
	if (_in_out_md_json) {
		if (memcpy_s(_tmp_out_md_json, _len_out_md_json, _in_out_md_json, _len_out_md_json)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_out_md_json);
	}
	if (_in_out_img_sig) {
		if (memcpy_s(_tmp_out_img_sig, _len_out_img_sig, _in_out_img_sig, _len_out_img_sig)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_out_img_sig);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_t_verify_cert(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_t_verify_cert_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_t_verify_cert_t* ms = SGX_CAST(ms_t_verify_cert_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_ias_cert = ms->ms_ias_cert;
	size_t _tmp_size_of_ias_cert = ms->ms_size_of_ias_cert;
	size_t _len_ias_cert = _tmp_size_of_ias_cert;
	void* _in_ias_cert = NULL;

	CHECK_UNIQUE_POINTER(_tmp_ias_cert, _len_ias_cert);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ias_cert != NULL && _len_ias_cert != 0) {
		_in_ias_cert = (void*)malloc(_len_ias_cert);
		if (_in_ias_cert == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_ias_cert, _len_ias_cert, _tmp_ias_cert, _len_ias_cert)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = t_verify_cert(_in_ias_cert, _tmp_size_of_ias_cert);
err:
	if (_in_ias_cert) free(_in_ias_cert);

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
err:
	if (_in_cert) {
		if (memcpy_s(_tmp_cert, _len_cert, _in_cert, _len_cert)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_cert);
	}
	if (_in_actual_size_of_cert) {
		if (memcpy_s(_tmp_actual_size_of_cert, _len_actual_size_of_cert, _in_actual_size_of_cert, _len_actual_size_of_cert)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_actual_size_of_cert);
	}

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
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[5];
} g_ecall_table = {
	5,
	{
		{(void*)(uintptr_t)sgx_t_sgxver_call_apis, 0},
		{(void*)(uintptr_t)sgx_t_verify_cert, 0},
		{(void*)(uintptr_t)sgx_t_create_key_and_x509, 0},
		{(void*)(uintptr_t)sgx_t_free, 0},
		{(void*)(uintptr_t)sgx_dummy, 0},
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

	ocalloc_size += (str != NULL) ? _len_str : 0;

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

	ocalloc_size += (timeptr != NULL) ? _len_timeptr : 0;

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

	ocalloc_size += (cpuinfo != NULL) ? _len_cpuinfo : 0;

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

	ocalloc_size += (waiters != NULL) ? _len_waiters : 0;

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

	ocalloc_size += (target_info != NULL) ? _len_target_info : 0;

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

	ocalloc_size += (report != NULL) ? _len_report : 0;
	ocalloc_size += (opts != NULL) ? _len_opts : 0;
	ocalloc_size += (attn_report != NULL) ? _len_attn_report : 0;

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

