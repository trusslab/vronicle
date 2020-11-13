#define ENABLE_DCAP 1
#ifdef ENABLE_DCAP
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include "sgx_quote_3.h"
#include "sgx_dcap_quoteverify.h"

// Get supplemental data size
void ocall_ecdsa_get_supplemental_data_size
(
    uint32_t* supplemental_data_size
)
{
    // Init variables
    quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;

    /* Set QvE loading policy. */
    dcap_ret = sgx_qv_set_enclave_load_policy(SGX_QL_DEFAULT);
    assert(dcap_ret == SGX_QL_SUCCESS);

    /* Get supplemental data size. */
    dcap_ret = sgx_qv_get_quote_supplemental_data_size(supplemental_data_size);
    assert(dcap_ret == SGX_QL_SUCCESS);
}

// Prepare for DCAP quote verification
void ocall_ecdsa_verify_quote
(
    const uint8_t* quote_buffer,
    const uint32_t quote_size,
    sgx_ql_qe_report_info_t* qve_report_info,
    uint32_t* collateral_expiration_status,
    sgx_ql_qv_result_t *quote_verification_result,
    uint8_t* supplemental_data,
    uint32_t supplemental_data_size
)
{
    // Init variables
    time_t current_time = 1605146732; // TODO: Make this a non-hardcoded time.
    quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;

    /* Set QvE loading policy. */
    dcap_ret = sgx_qv_set_enclave_load_policy(SGX_QL_DEFAULT);
    assert(dcap_ret == SGX_QL_SUCCESS);

    uint8_t tmp_supplemental_data[supplemental_data_size];
    memset(tmp_supplemental_data, 0, supplemental_data_size);

    /* Verify quote. */
    dcap_ret = sgx_qv_verify_quote(
        quote_buffer, quote_size,
        NULL,
        current_time,
        collateral_expiration_status,
        quote_verification_result,
        qve_report_info,
        supplemental_data_size,
        tmp_supplemental_data
    );
    assert(dcap_ret == SGX_QL_SUCCESS);
    memcpy(supplemental_data, tmp_supplemental_data, supplemental_data_size);
}
#endif