#include "EncoderEnclave_t.h"

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

static sgx_status_t SGX_CDECL sgx_t_encoder_init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_t_encoder_init_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_t_encoder_init_t* ms = SGX_CAST(ms_t_encoder_init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	cmdline* _tmp_cl_in = ms->ms_cl_in;
	size_t _tmp_cl_size = ms->ms_cl_size;
	size_t _len_cl_in = _tmp_cl_size;
	cmdline* _in_cl_in = NULL;

	CHECK_UNIQUE_POINTER(_tmp_cl_in, _len_cl_in);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_cl_in != NULL && _len_cl_in != 0) {
		_in_cl_in = (cmdline*)malloc(_len_cl_in);
		if (_in_cl_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_cl_in, _len_cl_in, _tmp_cl_in, _len_cl_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = t_encoder_init(_in_cl_in, _tmp_cl_size, ms->ms_w, ms->ms_h);
err:
	if (_in_cl_in) free(_in_cl_in);

	return status;
}

static sgx_status_t SGX_CDECL sgx_t_encode_frame(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_t_encode_frame_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_t_encode_frame_t* ms = SGX_CAST(ms_t_encode_frame_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_frame_sig = ms->ms_frame_sig;
	size_t _tmp_frame_sig_size = ms->ms_frame_sig_size;
	size_t _len_frame_sig = _tmp_frame_sig_size;
	unsigned char* _in_frame_sig = NULL;
	uint8_t* _tmp_frame = ms->ms_frame;
	size_t _tmp_frame_size = ms->ms_frame_size;
	size_t _len_frame = _tmp_frame_size;
	uint8_t* _in_frame = NULL;

	CHECK_UNIQUE_POINTER(_tmp_frame_sig, _len_frame_sig);
	CHECK_UNIQUE_POINTER(_tmp_frame, _len_frame);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_frame_sig != NULL && _len_frame_sig != 0) {
		_in_frame_sig = (unsigned char*)malloc(_len_frame_sig);
		if (_in_frame_sig == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_frame_sig, _len_frame_sig, _tmp_frame_sig, _len_frame_sig)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_frame != NULL && _len_frame != 0) {
		_in_frame = (uint8_t*)malloc(_len_frame);
		if (_in_frame == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_frame, _len_frame, _tmp_frame, _len_frame)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = t_encode_frame(_in_frame_sig, _tmp_frame_sig_size, _in_frame, _tmp_frame_size);
err:
	if (_in_frame_sig) free(_in_frame_sig);
	if (_in_frame) free(_in_frame);

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
	char* _tmp_vendor_pubkey_str = ms->ms_vendor_pubkey_str;
	size_t _tmp_vendor_pubkey_str_size = ms->ms_vendor_pubkey_str_size;
	size_t _len_vendor_pubkey_str = _tmp_vendor_pubkey_str_size;
	char* _in_vendor_pubkey_str = NULL;
	char* _tmp_cert_str = ms->ms_cert_str;
	size_t _tmp_cert_str_size = ms->ms_cert_str_size;
	size_t _len_cert_str = _tmp_cert_str_size;
	char* _in_cert_str = NULL;

	CHECK_UNIQUE_POINTER(_tmp_vendor_pubkey_str, _len_vendor_pubkey_str);
	CHECK_UNIQUE_POINTER(_tmp_cert_str, _len_cert_str);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_vendor_pubkey_str != NULL && _len_vendor_pubkey_str != 0) {
		_in_vendor_pubkey_str = (char*)malloc(_len_vendor_pubkey_str);
		if (_in_vendor_pubkey_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_vendor_pubkey_str, _len_vendor_pubkey_str, _tmp_vendor_pubkey_str, _len_vendor_pubkey_str)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_cert_str != NULL && _len_cert_str != 0) {
		_in_cert_str = (char*)malloc(_len_cert_str);
		if (_in_cert_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_cert_str, _len_cert_str, _tmp_cert_str, _len_cert_str)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = t_verify_cert(_in_vendor_pubkey_str, _tmp_vendor_pubkey_str_size, _in_cert_str, _tmp_cert_str_size);
err:
	if (_in_vendor_pubkey_str) free(_in_vendor_pubkey_str);
	if (_in_cert_str) free(_in_cert_str);

	return status;
}

static sgx_status_t SGX_CDECL sgx_t_get_sig_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_t_get_sig_size_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_t_get_sig_size_t* ms = SGX_CAST(ms_t_get_sig_size_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	size_t* _tmp_sig_size = ms->ms_sig_size;
	size_t _len_sig_size = sizeof(size_t);
	size_t* _in_sig_size = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sig_size, _len_sig_size);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sig_size != NULL && _len_sig_size != 0) {
		if ((_in_sig_size = (size_t*)malloc(_len_sig_size)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sig_size, 0, _len_sig_size);
	}

	t_get_sig_size(_in_sig_size);
err:
	if (_in_sig_size) {
		if (memcpy_s(_tmp_sig_size, _len_sig_size, _in_sig_size, _len_sig_size)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_sig_size);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_t_get_sig(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_t_get_sig_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_t_get_sig_t* ms = SGX_CAST(ms_t_get_sig_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_sig = ms->ms_sig;
	size_t _tmp_sig_size = ms->ms_sig_size;
	size_t _len_sig = _tmp_sig_size;
	unsigned char* _in_sig = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sig, _len_sig);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sig != NULL && _len_sig != 0) {
		if ((_in_sig = (unsigned char*)malloc(_len_sig)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sig, 0, _len_sig);
	}

	t_get_sig(_in_sig, _tmp_sig_size);
err:
	if (_in_sig) {
		if (memcpy_s(_tmp_sig, _len_sig, _in_sig, _len_sig)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_sig);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_t_get_encoded_video_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_t_get_encoded_video_size_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_t_get_encoded_video_size_t* ms = SGX_CAST(ms_t_get_encoded_video_size_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	size_t* _tmp_video_size = ms->ms_video_size;
	size_t _len_video_size = sizeof(size_t);
	size_t* _in_video_size = NULL;

	CHECK_UNIQUE_POINTER(_tmp_video_size, _len_video_size);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_video_size != NULL && _len_video_size != 0) {
		if ((_in_video_size = (size_t*)malloc(_len_video_size)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_video_size, 0, _len_video_size);
	}

	t_get_encoded_video_size(_in_video_size);
err:
	if (_in_video_size) {
		if (memcpy_s(_tmp_video_size, _len_video_size, _in_video_size, _len_video_size)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_video_size);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_t_get_encoded_video(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_t_get_encoded_video_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_t_get_encoded_video_t* ms = SGX_CAST(ms_t_get_encoded_video_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_video = ms->ms_video;
	size_t _tmp_video_size = ms->ms_video_size;
	size_t _len_video = _tmp_video_size;
	unsigned char* _in_video = NULL;

	CHECK_UNIQUE_POINTER(_tmp_video, _len_video);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_video != NULL && _len_video != 0) {
		if ((_in_video = (unsigned char*)malloc(_len_video)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_video, 0, _len_video);
	}

	t_get_encoded_video(_in_video, _tmp_video_size);
err:
	if (_in_video) {
		if (memcpy_s(_tmp_video, _len_video, _in_video, _len_video)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_video);
	}

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
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[10];
} g_ecall_table = {
	10,
	{
		{(void*)(uintptr_t)sgx_t_encoder_init, 0},
		{(void*)(uintptr_t)sgx_t_encode_frame, 0},
		{(void*)(uintptr_t)sgx_t_verify_cert, 0},
		{(void*)(uintptr_t)sgx_t_get_sig_size, 0},
		{(void*)(uintptr_t)sgx_t_get_sig, 0},
		{(void*)(uintptr_t)sgx_t_get_encoded_video_size, 0},
		{(void*)(uintptr_t)sgx_t_get_encoded_video, 0},
		{(void*)(uintptr_t)sgx_t_create_key_and_x509, 0},
		{(void*)(uintptr_t)sgx_t_free, 0},
		{(void*)(uintptr_t)sgx_dummy, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[10][10];
} g_dyn_entry_table = {
	10,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
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

