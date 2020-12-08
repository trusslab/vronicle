#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include <sgx_uae_service.h>

#include <ra.h>
#include <ra-attester.h>
#include <ias-ra.h>

#ifdef ENABLE_DCAP
#include <string.h>
#include "sgx_quote_3.h"
#include "sgx_dcap_ql_wrapper.h"
#endif

/* Untrusted code to do remote attestation with the SGX SDK. */

void ocall_remote_attestation
(
    sgx_report_t* report,
    const struct ra_tls_options* opts,
    attestation_verification_report_t* attn_report
)
{
    // produce quote
    uint32_t quote_size;
    sgx_calc_quote_size(NULL, 0, &quote_size);
    
    sgx_quote_t* quote = (sgx_quote_t*) calloc(1, quote_size);
    
    sgx_status_t status;
    status = sgx_get_quote(report,
                           opts->quote_type,
                           &opts->spid,
                           NULL,
                           NULL,
                           0,
                           NULL,
                           quote,
                           quote_size);
    assert(SGX_SUCCESS == status);

    // verify against IAS
    obtain_attestation_verification_report(quote, quote_size, opts, attn_report);
}

void ocall_sgx_init_quote
(
    sgx_target_info_t* target_info
)
{
    sgx_epid_group_id_t gid;
    sgx_status_t status = sgx_init_quote(target_info, &gid);
    // printf("sgx_status_t: %d\n", status);
    assert(status == SGX_SUCCESS);
}

#ifdef ENABLE_DCAP
// Get DCAP quoting enclave target info
void ocall_ecdsa_get_qe_target_info
(
    sgx_target_info_t* qe_target_info
)
{
    quote3_error_t status = sgx_qe_get_target_info(qe_target_info);
    assert(status == SGX_QL_SUCCESS);
}

// Get DCAP quote size
void ocall_ecdsa_get_quote_size
(
    uint32_t* quote_size
)
{
    quote3_error_t status = SGX_QL_SUCCESS;
    
    // Get quote size
    status = sgx_qe_get_quote_size(quote_size);
    assert(status == SGX_QL_SUCCESS);
}

// Generate DCAP quote
void ocall_ecdsa_get_quote
(
    const sgx_report_t* report,
    uint8_t* quote_buffer,
    uint32_t quote_size
)
{
    quote3_error_t status = SGX_QL_SUCCESS;

    // Get quote
    uint8_t tmp_quote_buffer[quote_size];
    memset(tmp_quote_buffer, 0, quote_size);
    status = sgx_qe_get_quote(report, quote_size, tmp_quote_buffer);
    assert(status == SGX_QL_SUCCESS);
    memcpy(quote_buffer, tmp_quote_buffer, quote_size);
}
#endif
