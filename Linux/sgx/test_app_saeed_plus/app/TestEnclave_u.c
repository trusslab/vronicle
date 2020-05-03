#include "TestEnclave_u.h"
#include <errno.h>

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

static sgx_status_t SGX_CDECL TestEnclave_ucreate_thread(void* pms)
{
	ms_ucreate_thread_t* ms = SGX_CAST(ms_ucreate_thread_t*, pms);
	ms->ms_retval = ucreate_thread();

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
	void * table[9];
} ocall_table_TestEnclave = {
	9,
	{
		(void*)TestEnclave_uprint,
		(void*)TestEnclave_usgx_exit,
		(void*)TestEnclave_ucreate_thread,
		(void*)TestEnclave_u_sgxssl_ftime,
		(void*)TestEnclave_sgx_oc_cpuidex,
		(void*)TestEnclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)TestEnclave_sgx_thread_set_untrusted_event_ocall,
		(void*)TestEnclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)TestEnclave_sgx_thread_set_multiple_untrusted_events_ocall,
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

sgx_status_t new_thread_func(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_TestEnclave, NULL);
	return status;
}

sgx_status_t t_sgxver_call_apis(sgx_enclave_id_t eid, void* hash_of_contract, size_t len_of_hash, void* signature, void* size_of_actual_signature, int size_of_soas, void* public_key, size_t len_of_pukey, void* size_of_actual_pukey, size_t size_of_soap)
{
	sgx_status_t status;
	ms_t_sgxver_call_apis_t ms;
	ms.ms_hash_of_contract = hash_of_contract;
	ms.ms_len_of_hash = len_of_hash;
	ms.ms_signature = signature;
	ms.ms_size_of_actual_signature = size_of_actual_signature;
	ms.ms_size_of_soas = size_of_soas;
	ms.ms_public_key = public_key;
	ms.ms_len_of_pukey = len_of_pukey;
	ms.ms_size_of_actual_pukey = size_of_actual_pukey;
	ms.ms_size_of_soap = size_of_soap;
	status = sgx_ecall(eid, 2, &ocall_table_TestEnclave, &ms);
	return status;
}

