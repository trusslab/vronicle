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
	void* ms_hash_of_contract;
	size_t ms_len_of_hash;
	void* ms_signature;
	void* ms_size_of_actual_signature;
	int ms_size_of_soas;
	void* ms_public_key;
	size_t ms_len_of_pukey;
	void* ms_size_of_actual_pukey;
	size_t ms_size_of_soap;
} ms_t_sgxver_call_apis_t;

typedef struct ms_uprint_t {
	const char* ms_str;
} ms_uprint_t;

typedef struct ms_usgx_exit_t {
	int ms_reason;
} ms_usgx_exit_t;

typedef struct ms_ucreate_thread_t {
	int ms_retval;
} ms_ucreate_thread_t;

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

static sgx_status_t SGX_CDECL sgx_new_thread_func(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	new_thread_func();
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
	void* _tmp_hash_of_contract = ms->ms_hash_of_contract;
	size_t _tmp_len_of_hash = ms->ms_len_of_hash;
	size_t _len_hash_of_contract = _tmp_len_of_hash;
	void* _in_hash_of_contract = NULL;
	void* _tmp_signature = ms->ms_signature;
	size_t _len_signature = 512;
	void* _in_signature = NULL;
	void* _tmp_size_of_actual_signature = ms->ms_size_of_actual_signature;
	int _tmp_size_of_soas = ms->ms_size_of_soas;
	size_t _len_size_of_actual_signature = _tmp_size_of_soas;
	void* _in_size_of_actual_signature = NULL;
	void* _tmp_public_key = ms->ms_public_key;
	size_t _tmp_len_of_pukey = ms->ms_len_of_pukey;
	size_t _len_public_key = _tmp_len_of_pukey;
	void* _in_public_key = NULL;
	void* _tmp_size_of_actual_pukey = ms->ms_size_of_actual_pukey;
	size_t _tmp_size_of_soap = ms->ms_size_of_soap;
	size_t _len_size_of_actual_pukey = _tmp_size_of_soap;
	void* _in_size_of_actual_pukey = NULL;

	CHECK_UNIQUE_POINTER(_tmp_hash_of_contract, _len_hash_of_contract);
	CHECK_UNIQUE_POINTER(_tmp_signature, _len_signature);
	CHECK_UNIQUE_POINTER(_tmp_size_of_actual_signature, _len_size_of_actual_signature);
	CHECK_UNIQUE_POINTER(_tmp_public_key, _len_public_key);
	CHECK_UNIQUE_POINTER(_tmp_size_of_actual_pukey, _len_size_of_actual_pukey);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_hash_of_contract != NULL && _len_hash_of_contract != 0) {
		_in_hash_of_contract = (void*)malloc(_len_hash_of_contract);
		if (_in_hash_of_contract == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_hash_of_contract, _len_hash_of_contract, _tmp_hash_of_contract, _len_hash_of_contract)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_signature != NULL && _len_signature != 0) {
		if ((_in_signature = (void*)malloc(_len_signature)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_signature, 0, _len_signature);
	}
	if (_tmp_size_of_actual_signature != NULL && _len_size_of_actual_signature != 0) {
		if ((_in_size_of_actual_signature = (void*)malloc(_len_size_of_actual_signature)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_size_of_actual_signature, 0, _len_size_of_actual_signature);
	}
	if (_tmp_public_key != NULL && _len_public_key != 0) {
		if ((_in_public_key = (void*)malloc(_len_public_key)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_public_key, 0, _len_public_key);
	}
	if (_tmp_size_of_actual_pukey != NULL && _len_size_of_actual_pukey != 0) {
		if ((_in_size_of_actual_pukey = (void*)malloc(_len_size_of_actual_pukey)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_size_of_actual_pukey, 0, _len_size_of_actual_pukey);
	}

	t_sgxver_call_apis(_in_hash_of_contract, _tmp_len_of_hash, _in_signature, _in_size_of_actual_signature, _tmp_size_of_soas, _in_public_key, _tmp_len_of_pukey, _in_size_of_actual_pukey, _tmp_size_of_soap);
	if (_in_signature) {
		if (memcpy_s(_tmp_signature, _len_signature, _in_signature, _len_signature)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_size_of_actual_signature) {
		if (memcpy_s(_tmp_size_of_actual_signature, _len_size_of_actual_signature, _in_size_of_actual_signature, _len_size_of_actual_signature)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_public_key) {
		if (memcpy_s(_tmp_public_key, _len_public_key, _in_public_key, _len_public_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_size_of_actual_pukey) {
		if (memcpy_s(_tmp_size_of_actual_pukey, _len_size_of_actual_pukey, _in_size_of_actual_pukey, _len_size_of_actual_pukey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_hash_of_contract) free(_in_hash_of_contract);
	if (_in_signature) free(_in_signature);
	if (_in_size_of_actual_signature) free(_in_size_of_actual_signature);
	if (_in_public_key) free(_in_public_key);
	if (_in_size_of_actual_pukey) free(_in_size_of_actual_pukey);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[3];
} g_ecall_table = {
	3,
	{
		{(void*)(uintptr_t)sgx_t_sgxssl_call_apis, 0, 0},
		{(void*)(uintptr_t)sgx_new_thread_func, 0, 0},
		{(void*)(uintptr_t)sgx_t_sgxver_call_apis, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[9][3];
} g_dyn_entry_table = {
	9,
	{
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
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

sgx_status_t SGX_CDECL ucreate_thread(int* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ucreate_thread_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ucreate_thread_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ucreate_thread_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ucreate_thread_t));
	ocalloc_size -= sizeof(ms_ucreate_thread_t);

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
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
	status = sgx_ocall(3, ms);

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
	status = sgx_ocall(4, ms);

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
	status = sgx_ocall(5, ms);

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
	status = sgx_ocall(6, ms);

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
	status = sgx_ocall(7, ms);

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
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

