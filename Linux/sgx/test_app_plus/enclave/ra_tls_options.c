#include "ra-attester.h"

struct ra_tls_options my_ra_tls_options = {
    // SPID format is 32 hex-character string, e.g., 0123456789abcdef0123456789abcdef
    .spid = {{0x98,0x99,0x2B,0x8D,0x5C,0x52,0x67,0xB7,0x2A,0x2C,0x92,0x67,0x8A,0x74,0x39,0xF5,}},
    .quote_type = SGX_LINKABLE_SIGNATURE,
    .ias_server = "api.trustedservices.intel.com/sgx/dev",
    // EPID_SUBSCRIPTION_KEY format is "012345679abcdef012345679abcdef"
    .subscription_key = "ecb6baf92cbb4f57a338e8f29739cf00"
};

struct ecdsa_ra_tls_options my_ecdsa_ra_tls_options = {
    // ECDSA_SUBSCRIPTION_KEY format is "012345679abcdef012345679abcdef"
    .subscription_key = ""
};
