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

static sgx_status_t SGX_CDECL sgx_t_sgxver_prepare_decoder(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_t_sgxver_prepare_decoder_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_t_sgxver_prepare_decoder_t* ms = SGX_CAST(ms_t_sgxver_prepare_decoder_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_input_content_buffer = ms->ms_input_content_buffer;
	long int _tmp_size_of_input_content_buffer = ms->ms_size_of_input_content_buffer;
	size_t _len_input_content_buffer = _tmp_size_of_input_content_buffer;
	void* _in_input_content_buffer = NULL;
	void* _tmp_md_json = ms->ms_md_json;
	long int _tmp_md_json_len = ms->ms_md_json_len;
	size_t _len_md_json = _tmp_md_json_len;
	void* _in_md_json = NULL;
	void* _tmp_vendor_pub = ms->ms_vendor_pub;
	long int _tmp_vendor_pub_len = ms->ms_vendor_pub_len;
	size_t _len_vendor_pub = _tmp_vendor_pub_len;
	void* _in_vendor_pub = NULL;
	void* _tmp_camera_cert = ms->ms_camera_cert;
	long int _tmp_camera_cert_len = ms->ms_camera_cert_len;
	size_t _len_camera_cert = _tmp_camera_cert_len;
	void* _in_camera_cert = NULL;
	void* _tmp_vid_sig = ms->ms_vid_sig;
	size_t _tmp_vid_sig_len = ms->ms_vid_sig_len;
	size_t _len_vid_sig = _tmp_vid_sig_len;
	void* _in_vid_sig = NULL;

	CHECK_UNIQUE_POINTER(_tmp_input_content_buffer, _len_input_content_buffer);
	CHECK_UNIQUE_POINTER(_tmp_md_json, _len_md_json);
	CHECK_UNIQUE_POINTER(_tmp_vendor_pub, _len_vendor_pub);
	CHECK_UNIQUE_POINTER(_tmp_camera_cert, _len_camera_cert);
	CHECK_UNIQUE_POINTER(_tmp_vid_sig, _len_vid_sig);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_input_content_buffer != NULL && _len_input_content_buffer != 0) {
		_in_input_content_buffer = (void*)malloc(_len_input_content_buffer);
		if (_in_input_content_buffer == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_input_content_buffer, _len_input_content_buffer, _tmp_input_content_buffer, _len_input_content_buffer)) {
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
	if (_tmp_vendor_pub != NULL && _len_vendor_pub != 0) {
		_in_vendor_pub = (void*)malloc(_len_vendor_pub);
		if (_in_vendor_pub == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_vendor_pub, _len_vendor_pub, _tmp_vendor_pub, _len_vendor_pub)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_camera_cert != NULL && _len_camera_cert != 0) {
		_in_camera_cert = (void*)malloc(_len_camera_cert);
		if (_in_camera_cert == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_camera_cert, _len_camera_cert, _tmp_camera_cert, _len_camera_cert)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_vid_sig != NULL && _len_vid_sig != 0) {
		_in_vid_sig = (void*)malloc(_len_vid_sig);
		if (_in_vid_sig == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_vid_sig, _len_vid_sig, _tmp_vid_sig, _len_vid_sig)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = t_sgxver_prepare_decoder(_in_input_content_buffer, _tmp_size_of_input_content_buffer, _in_md_json, _tmp_md_json_len, _in_vendor_pub, _tmp_vendor_pub_len, _in_camera_cert, _tmp_camera_cert_len, _in_vid_sig, _tmp_vid_sig_len);

err:
	if (_in_input_content_buffer) free(_in_input_content_buffer);
	if (_in_md_json) free(_in_md_json);
	if (_in_vendor_pub) free(_in_vendor_pub);
	if (_in_camera_cert) free(_in_camera_cert);
	if (_in_vid_sig) free(_in_vid_sig);
	return status;
}

static sgx_status_t SGX_CDECL sgx_t_sgxver_decode_single_frame(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_t_sgxver_decode_single_frame_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_t_sgxver_decode_single_frame_t* ms = SGX_CAST(ms_t_sgxver_decode_single_frame_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_decoded_frame = ms->ms_decoded_frame;
	long int _tmp_size_of_decoded_frame = ms->ms_size_of_decoded_frame;
	size_t _len_decoded_frame = _tmp_size_of_decoded_frame;
	void* _in_decoded_frame = NULL;
	void* _tmp_output_md_json = ms->ms_output_md_json;
	long int _tmp_size_of_output_json = ms->ms_size_of_output_json;
	size_t _len_output_md_json = _tmp_size_of_output_json;
	void* _in_output_md_json = NULL;
	void* _tmp_output_sig = ms->ms_output_sig;
	long int _tmp_size_of_output_sig = ms->ms_size_of_output_sig;
	size_t _len_output_sig = _tmp_size_of_output_sig;
	void* _in_output_sig = NULL;

	CHECK_UNIQUE_POINTER(_tmp_decoded_frame, _len_decoded_frame);
	CHECK_UNIQUE_POINTER(_tmp_output_md_json, _len_output_md_json);
	CHECK_UNIQUE_POINTER(_tmp_output_sig, _len_output_sig);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_decoded_frame != NULL && _len_decoded_frame != 0) {
		if ((_in_decoded_frame = (void*)malloc(_len_decoded_frame)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_decoded_frame, 0, _len_decoded_frame);
	}
	if (_tmp_output_md_json != NULL && _len_output_md_json != 0) {
		if ((_in_output_md_json = (void*)malloc(_len_output_md_json)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_output_md_json, 0, _len_output_md_json);
	}
	if (_tmp_output_sig != NULL && _len_output_sig != 0) {
		if ((_in_output_sig = (void*)malloc(_len_output_sig)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_output_sig, 0, _len_output_sig);
	}

	ms->ms_retval = t_sgxver_decode_single_frame(_in_decoded_frame, _tmp_size_of_decoded_frame, _in_output_md_json, _tmp_size_of_output_json, _in_output_sig, _tmp_size_of_output_sig);
	if (_in_decoded_frame) {
		if (memcpy_s(_tmp_decoded_frame, _len_decoded_frame, _in_decoded_frame, _len_decoded_frame)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_output_md_json) {
		if (memcpy_s(_tmp_output_md_json, _len_output_md_json, _in_output_md_json, _len_output_md_json)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_output_sig) {
		if (memcpy_s(_tmp_output_sig, _len_output_sig, _in_output_sig, _len_output_sig)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_decoded_frame) free(_in_decoded_frame);
	if (_in_output_md_json) free(_in_output_md_json);
	if (_in_output_sig) free(_in_output_sig);
	return status;
}

static sgx_status_t SGX_CDECL sgx_t_sgxver_decode_content(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_t_sgxver_decode_content_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_t_sgxver_decode_content_t* ms = SGX_CAST(ms_t_sgxver_decode_content_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_input_content_buffer = ms->ms_input_content_buffer;
	long int _tmp_size_of_input_content_buffer = ms->ms_size_of_input_content_buffer;
	size_t _len_input_content_buffer = _tmp_size_of_input_content_buffer;
	void* _in_input_content_buffer = NULL;
	void* _tmp_md_json = ms->ms_md_json;
	long int _tmp_md_json_len = ms->ms_md_json_len;
	size_t _len_md_json = _tmp_md_json_len;
	void* _in_md_json = NULL;
	void* _tmp_vendor_pub = ms->ms_vendor_pub;
	long int _tmp_vendor_pub_len = ms->ms_vendor_pub_len;
	size_t _len_vendor_pub = _tmp_vendor_pub_len;
	void* _in_vendor_pub = NULL;
	void* _tmp_camera_cert = ms->ms_camera_cert;
	long int _tmp_camera_cert_len = ms->ms_camera_cert_len;
	size_t _len_camera_cert = _tmp_camera_cert_len;
	void* _in_camera_cert = NULL;
	void* _tmp_vid_sig = ms->ms_vid_sig;
	size_t _tmp_vid_sig_len = ms->ms_vid_sig_len;
	size_t _len_vid_sig = _tmp_vid_sig_len;
	void* _in_vid_sig = NULL;
	u32* _tmp_frame_width = ms->ms_frame_width;
	size_t _len_frame_width = sizeof(u32);
	u32* _in_frame_width = NULL;
	u32* _tmp_frame_height = ms->ms_frame_height;
	size_t _len_frame_height = sizeof(u32);
	u32* _in_frame_height = NULL;
	int* _tmp_num_of_frames = ms->ms_num_of_frames;
	size_t _len_num_of_frames = sizeof(int);
	int* _in_num_of_frames = NULL;
	void* _tmp_output_rgb_buffer = ms->ms_output_rgb_buffer;
	void* _tmp_output_sig_buffer = ms->ms_output_sig_buffer;
	void* _tmp_output_md_buffer = ms->ms_output_md_buffer;

	CHECK_UNIQUE_POINTER(_tmp_input_content_buffer, _len_input_content_buffer);
	CHECK_UNIQUE_POINTER(_tmp_md_json, _len_md_json);
	CHECK_UNIQUE_POINTER(_tmp_vendor_pub, _len_vendor_pub);
	CHECK_UNIQUE_POINTER(_tmp_camera_cert, _len_camera_cert);
	CHECK_UNIQUE_POINTER(_tmp_vid_sig, _len_vid_sig);
	CHECK_UNIQUE_POINTER(_tmp_frame_width, _len_frame_width);
	CHECK_UNIQUE_POINTER(_tmp_frame_height, _len_frame_height);
	CHECK_UNIQUE_POINTER(_tmp_num_of_frames, _len_num_of_frames);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_input_content_buffer != NULL && _len_input_content_buffer != 0) {
		_in_input_content_buffer = (void*)malloc(_len_input_content_buffer);
		if (_in_input_content_buffer == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_input_content_buffer, _len_input_content_buffer, _tmp_input_content_buffer, _len_input_content_buffer)) {
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
	if (_tmp_vendor_pub != NULL && _len_vendor_pub != 0) {
		_in_vendor_pub = (void*)malloc(_len_vendor_pub);
		if (_in_vendor_pub == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_vendor_pub, _len_vendor_pub, _tmp_vendor_pub, _len_vendor_pub)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_camera_cert != NULL && _len_camera_cert != 0) {
		_in_camera_cert = (void*)malloc(_len_camera_cert);
		if (_in_camera_cert == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_camera_cert, _len_camera_cert, _tmp_camera_cert, _len_camera_cert)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_vid_sig != NULL && _len_vid_sig != 0) {
		_in_vid_sig = (void*)malloc(_len_vid_sig);
		if (_in_vid_sig == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_vid_sig, _len_vid_sig, _tmp_vid_sig, _len_vid_sig)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_frame_width != NULL && _len_frame_width != 0) {
		if ((_in_frame_width = (u32*)malloc(_len_frame_width)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_frame_width, 0, _len_frame_width);
	}
	if (_tmp_frame_height != NULL && _len_frame_height != 0) {
		if ((_in_frame_height = (u32*)malloc(_len_frame_height)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_frame_height, 0, _len_frame_height);
	}
	if (_tmp_num_of_frames != NULL && _len_num_of_frames != 0) {
		if ( _len_num_of_frames % sizeof(*_tmp_num_of_frames) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_num_of_frames = (int*)malloc(_len_num_of_frames)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_num_of_frames, 0, _len_num_of_frames);
	}

	ms->ms_retval = t_sgxver_decode_content(_in_input_content_buffer, _tmp_size_of_input_content_buffer, _in_md_json, _tmp_md_json_len, _in_vendor_pub, _tmp_vendor_pub_len, _in_camera_cert, _tmp_camera_cert_len, _in_vid_sig, _tmp_vid_sig_len, _in_frame_width, _in_frame_height, _in_num_of_frames, _tmp_output_rgb_buffer, _tmp_output_sig_buffer, _tmp_output_md_buffer);
	if (_in_frame_width) {
		if (memcpy_s(_tmp_frame_width, _len_frame_width, _in_frame_width, _len_frame_width)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_frame_height) {
		if (memcpy_s(_tmp_frame_height, _len_frame_height, _in_frame_height, _len_frame_height)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_num_of_frames) {
		if (memcpy_s(_tmp_num_of_frames, _len_num_of_frames, _in_num_of_frames, _len_num_of_frames)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_input_content_buffer) free(_in_input_content_buffer);
	if (_in_md_json) free(_in_md_json);
	if (_in_vendor_pub) free(_in_vendor_pub);
	if (_in_camera_cert) free(_in_camera_cert);
	if (_in_vid_sig) free(_in_vid_sig);
	if (_in_frame_width) free(_in_frame_width);
	if (_in_frame_height) free(_in_frame_height);
	if (_in_num_of_frames) free(_in_num_of_frames);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[5];
} g_ecall_table = {
	5,
	{
		{(void*)(uintptr_t)sgx_t_create_key_and_x509, 0, 0},
		{(void*)(uintptr_t)sgx_t_free, 0, 0},
		{(void*)(uintptr_t)sgx_t_sgxver_prepare_decoder, 0, 0},
		{(void*)(uintptr_t)sgx_t_sgxver_decode_single_frame, 0, 0},
		{(void*)(uintptr_t)sgx_t_sgxver_decode_content, 0, 0},
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
	
	status = sgx_ocall(2, ms);

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
	
	status = sgx_ocall(3, ms);

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
	status = sgx_ocall(4, ms);

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
	status = sgx_ocall(5, ms);

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
	status = sgx_ocall(6, ms);

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
	status = sgx_ocall(7, ms);

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
	status = sgx_ocall(8, ms);

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
	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

