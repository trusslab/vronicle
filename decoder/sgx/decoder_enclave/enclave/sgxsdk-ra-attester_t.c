#include <assert.h>
#include <string.h>
#include <stdio.h>

#include <sgx_uae_service.h>

#include "ra.h"
#include "ra-attester.h"
#include "ra_private.h"
// #include "ra_tls_t.h" // OCALLs
#include "TestEnclave_t.h"

#ifdef ENABLE_DCAP
#include "sgx_quote_3.h"
#endif

/* Trusted portion (called from within the enclave) to do remote
   attestation with the SGX SDK.  */
void do_remote_attestation
(
    sgx_report_data_t* report_data,
    const struct ra_tls_options* opts,
    attestation_verification_report_t* attn_report
)
{
    sgx_target_info_t target_info = {0, };
    ocall_sgx_init_quote(&target_info);

    sgx_report_t report = {0, };
    sgx_status_t status = sgx_create_report(&target_info, report_data, &report);
    assert(status == SGX_SUCCESS);

    ocall_remote_attestation(&report, opts, attn_report);
}

void ra_tls_create_report(
    sgx_report_t* report
)
{
    sgx_target_info_t target_info = {0, };
    sgx_report_data_t report_data = {0, };
    memset(report, 0, sizeof(*report));

    sgx_create_report(&target_info, &report_data, report);
}

#ifdef ENABLE_DCAP
void do_ecdsa_remote_attestation
(
    const sgx_report_data_t* report_data,
    uint8_t* quote,
    uint32_t* quote_size
)
{
    sgx_target_info_t qe_target_info = {0, };
    ocall_ecdsa_get_qe_target_info(&qe_target_info);

    sgx_report_t report = {0, };
    sgx_status_t status = sgx_create_report(&qe_target_info, report_data, &report);
    assert(status == SGX_SUCCESS);

    ocall_ecdsa_get_quote_size(quote_size);

    uint8_t tmp_quote[*quote_size];
    memset(tmp_quote, 0, *quote_size);
    ocall_ecdsa_get_quote(&report, tmp_quote, *quote_size);

    memcpy(quote, tmp_quote, *quote_size);
}
#endif
