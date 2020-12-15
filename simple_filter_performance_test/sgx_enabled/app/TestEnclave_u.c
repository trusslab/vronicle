#include "TestEnclave_u.h"
#include <errno.h>

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

static const struct {
	size_t nr_ocall;
	void * table[2];
} ocall_table_TestEnclave = {
	2,
	{
		(void*)TestEnclave_uprint,
		(void*)TestEnclave_usgx_exit,
	}
};
sgx_status_t t_blur(sgx_enclave_id_t eid, void* img_pixels, size_t size_of_img_pixels, void* out_pixels)
{
	sgx_status_t status;
	ms_t_blur_t ms;
	ms.ms_img_pixels = img_pixels;
	ms.ms_size_of_img_pixels = size_of_img_pixels;
	ms.ms_out_pixels = out_pixels;
	status = sgx_ecall(eid, 0, &ocall_table_TestEnclave, &ms);
	return status;
}

