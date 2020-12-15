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


typedef struct ms_t_blur_t {
	void* ms_img_pixels;
	size_t ms_size_of_img_pixels;
	void* ms_out_pixels;
} ms_t_blur_t;

typedef struct ms_uprint_t {
	const char* ms_str;
} ms_uprint_t;

typedef struct ms_usgx_exit_t {
	int ms_reason;
} ms_usgx_exit_t;

static sgx_status_t SGX_CDECL sgx_t_blur(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_t_blur_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_t_blur_t* ms = SGX_CAST(ms_t_blur_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_img_pixels = ms->ms_img_pixels;
	size_t _tmp_size_of_img_pixels = ms->ms_size_of_img_pixels;
	size_t _len_img_pixels = _tmp_size_of_img_pixels;
	void* _in_img_pixels = NULL;
	void* _tmp_out_pixels = ms->ms_out_pixels;
	size_t _len_out_pixels = _tmp_size_of_img_pixels;
	void* _in_out_pixels = NULL;

	CHECK_UNIQUE_POINTER(_tmp_img_pixels, _len_img_pixels);
	CHECK_UNIQUE_POINTER(_tmp_out_pixels, _len_out_pixels);

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
	if (_tmp_out_pixels != NULL && _len_out_pixels != 0) {
		if ((_in_out_pixels = (void*)malloc(_len_out_pixels)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out_pixels, 0, _len_out_pixels);
	}

	t_blur(_in_img_pixels, _tmp_size_of_img_pixels, _in_out_pixels);
	if (_in_out_pixels) {
		if (memcpy_s(_tmp_out_pixels, _len_out_pixels, _in_out_pixels, _len_out_pixels)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_img_pixels) free(_in_img_pixels);
	if (_in_out_pixels) free(_in_out_pixels);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[1];
} g_ecall_table = {
	1,
	{
		{(void*)(uintptr_t)sgx_t_blur, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[2][1];
} g_dyn_entry_table = {
	2,
	{
		{0, },
		{0, },
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

