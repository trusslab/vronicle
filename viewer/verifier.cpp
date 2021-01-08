#include "verifier.h"
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <assert.h>
#include "ra-challenger.h"
#include "metadata.h"
#ifdef ENABLE_DCAP
#include "sgx_ql_quote.h"
#include "sgx_dcap_quoteverify.h"
#endif

Verifier::Verifier(const std::string &_video_file_name,
                   const std::string &_sig_file_name,
                   const std::string &_cert_file_name,
                   const std::string &_md_file_name) {
    video_file_name =  _video_file_name;
    sig_file_name =    _sig_file_name;
    cert_file_name = _cert_file_name;
    md_file_name = _md_file_name;
}

size_t Verifier::calcDecodeLength(const char* b64input) {
  size_t len = strlen(b64input), padding = 0;
  // printf("The len in calc is: %d\n", (int)len);

  if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
    padding = 2;
  else if (b64input[len-1] == '=') //last char is =
    padding = 1;

  // printf("The padding in calc is: %d\n", (int)padding);
  return (len*3)/4 - padding;
}

void Verifier::Base64Decode(const char* b64message, unsigned char** buffer, size_t* length) {
  BIO *bio, *b64;

  int decodeLen = calcDecodeLength(b64message);
  // printf("decodeLen is: %d\n", decodeLen);
  *buffer = (unsigned char*)malloc(decodeLen + 1);
  (*buffer)[decodeLen] = '\0';

  bio = BIO_new_mem_buf(b64message, -1);
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_push(b64, bio);

  *length = BIO_read(bio, *buffer, strlen(b64message));
  // printf("The length is: %d\n", (int)*length);
  // printf("The buffer is: %s\n", buffer);
  BIO_free_all(bio);
}

void Verifier::verify() {
    FILE* video_file = fopen(video_file_name.c_str(), "rb");
    FILE* sig_file = fopen(sig_file_name.c_str(), "rb");
    FILE* cert_file = fopen(cert_file_name.c_str(), "r");
    FILE* md_json_file = fopen(md_file_name.c_str(), "r");

	if (video_file && sig_file && cert_file && md_json_file) {
		// Read video file
        fseek(video_file, 0, SEEK_END);
		size_t video_size = ftell(video_file);
        fseek(video_file, 0, SEEK_SET);
		char *video = new char [video_size];
        fread(video, 1, video_size, video_file);
		fclose(video_file);

		// Read metadata
        fseek(md_json_file, 0, SEEK_END);
		size_t md_json_size = ftell(md_json_file);
        fseek(md_json_file, 0, SEEK_SET);
		char *md_json = new char [md_json_size];
        fread(md_json, 1, md_json_size, md_json_file);
		fclose(md_json_file);

		// Read signature
        fseek(sig_file, 0, SEEK_END);
        size_t b64_sig_size = ftell(sig_file);
        fseek(sig_file, 0, SEEK_SET);
        char *b64_sig = new char [b64_sig_size + 1];
        fread(b64_sig, 1, b64_sig_size, sig_file);
        b64_sig[b64_sig_size + 1] = '\0';
		fclose(sig_file);
		unsigned char* sig;
		size_t sig_size = 0;
		Base64Decode(b64_sig, &sig, &sig_size);

		// Read Encoder certificate
        fseek(cert_file, 0, SEEK_END);
        size_t cert_size = ftell(cert_file);
        fseek(cert_file, 0, SEEK_SET);
        char *cert = new char [cert_size];
        fread(cert, 1, cert_size, cert_file);
		fclose(cert_file);
    	const unsigned char* p = (const unsigned char*)cert;

#ifndef ENABLE_DCAP
		// Verify IAS certificate
		int ret = verify_sgx_cert_extensions((uint8_t*)cert, (uint32_t)cert_size);
		if (ret) {
			printf("IAS cert verification failed\n");
			return;
		}

		// Extract public key from IAS certificate
		EVP_PKEY* evp_pubkey = EVP_PKEY_new();
		X509 *crt = X509_new();
 	    crt = d2i_X509(NULL, &p, cert_size);
 	    assert(crt != NULL);
 	    evp_pubkey = X509_get_pubkey(crt);
		if(!evp_pubkey){
			printf("Failed to retreive public key\n");
			return;
		}
#else
    	int ret = 0;
    	time_t current_time = 0;
    	uint32_t supplemental_data_size = 0;
    	uint8_t *p_supplemental_data = NULL;
    	quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
    	sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    	uint32_t collateral_expiration_status = 1;

    	// Extract DCAP evidence from X509 cert
    	X509* crt = d2i_X509(NULL, &p, cert_size);
    	assert(crt != NULL);
    	ecdsa_attestation_evidence_t evidence = {0, };
    	openssl_ecdsa_extract_x509_extensions(crt, &evidence);

		//call DCAP quote verify library to get supplemental data size
        //
        dcap_ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
        if (dcap_ret == SGX_QL_SUCCESS && supplemental_data_size == sizeof(sgx_ql_qv_supplemental_t)) {
            printf("\tInfo: sgx_qv_get_quote_supplemental_data_size successfully returned.\n");
            p_supplemental_data = (uint8_t*)malloc(supplemental_data_size);
        }
        else {
            printf("\tError: sgx_qv_get_quote_supplemental_data_size failed: 0x%04x\n", dcap_ret);
            supplemental_data_size = 0;
        }

        //set current time. This is only for sample purposes, in production mode a trusted time should be used.
        //
        current_time = time(NULL);


        //call DCAP quote verify library for quote verification
        //here you can choose 'trusted' or 'untrusted' quote verification by specifying parameter '&qve_report_info'
        //if '&qve_report_info' is NOT NULL, this API will call Intel QvE to verify quote
        //if '&qve_report_info' is NULL, this API will call 'untrusted quote verify lib' to verify quote, this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
        dcap_ret = sgx_qv_verify_quote(
            evidence.quote.data(), (uint32_t)evidence.quote.size(),
            NULL,
            current_time,
            &collateral_expiration_status,
            &quote_verification_result,
            NULL,
            supplemental_data_size,
            p_supplemental_data);
        if (dcap_ret == SGX_QL_SUCCESS) {
            printf("\tInfo: App: sgx_qv_verify_quote successfully returned.\n");
        }
        else {
            printf("\tError: App: sgx_qv_verify_quote failed: 0x%04x\n", dcap_ret);
        }

        //check verification result
        //
        switch (quote_verification_result)
        {
        case SGX_QL_QV_RESULT_OK:
        case SGX_QL_QV_RESULT_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_OUT_OF_DATE:
        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
        case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
			evp_pubkey = X509_get_pubkey(crt);
			if(!evp_pubkey){
				printf("Failed to retreive public key\n");
				return;
			}
            break;
        case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
        case SGX_QL_QV_RESULT_REVOKED:
        case SGX_QL_QV_RESULT_UNSPECIFIED:
        default:
            printf("\tError: App: Verification completed with Terminal result: %x\n", quote_verification_result);
            break;
        }
#endif

		// Verify signature
		EVP_MD_CTX *mdctx = NULL;
		const EVP_MD *md = NULL;
		OpenSSL_add_all_digests();
		do {
			md = EVP_get_digestbyname("SHA256");
			if (md == NULL) {
				std::cout << "EVP_get_digestbyname error: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
				break;
			}
			if(!(mdctx = EVP_MD_CTX_new())){
				std::cout << "EVP_MD_CTX_new error: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
				break;
			}
			if(1 != EVP_DigestInit_ex(mdctx, md, NULL)){
				std::cout << "EVP_DigestInit_ex error: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
				break;
			}
			if(1 != EVP_VerifyInit_ex(mdctx, EVP_sha256(), NULL)){
				std::cout << "EVP_VerifyInit_ex error: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
				break;
			}
			if(1 != EVP_VerifyUpdate(mdctx, video, video_size)){
				std::cout << "EVP_VerifyUpdate error: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
				break;
			}
			// printf("Going to update VerifySig with md_json(%d): [%s]\n", md_json_size, md_json);
			if(1 != EVP_VerifyUpdate(mdctx, md_json, md_json_size)){
				std::cout << "EVP_VerifyUpdate error: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
				break;
			}
			if(1 != EVP_VerifyFinal(mdctx, (const unsigned char*)sig, (unsigned int)sig_size, evp_pubkey)){
				std::cout << "EVP_VerifyFinal error: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
				break;
			}
		} while(0);
		delete[] video;
		delete[] md_json;
		delete[] b64_sig;
		free(sig);
		EVP_MD_CTX_free(mdctx);
		EVP_PKEY_free(evp_pubkey);
	}
    return;
}