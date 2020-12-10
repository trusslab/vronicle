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

Verifier::Verifier(const std::string &_video_file_name,
                   const std::string &_sig_file_name,
                   const std::string &_ias_cert_file_name,
                   const std::string &_md_file_name) {
    video_file_name =  _video_file_name;
    sig_file_name =    _sig_file_name;
    ias_cert_file_name = _ias_cert_file_name;
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
    FILE* ias_cert_file = fopen(ias_cert_file_name.c_str(), "r");
    FILE* md_json_file = fopen(md_file_name.c_str(), "r");

	if (video_file && sig_file && ias_cert_file && md_json_file) {
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
        fseek(ias_cert_file, 0, SEEK_END);
        size_t ias_cert_size = ftell(ias_cert_file);
        fseek(ias_cert_file, 0, SEEK_SET);
        char *ias_cert = new char [ias_cert_size];
        fread(ias_cert, 1, ias_cert_size, ias_cert_file);
		fclose(ias_cert_file);

		// Verify IAS certificate
		int ret = verify_sgx_cert_extensions((uint8_t*)ias_cert, (uint32_t)ias_cert_size);
		if (ret) {
			printf("IAS cert verification failed\n");
			return;
		}

		// Extract public key from IAS certificate
		EVP_PKEY* evp_pubkey = EVP_PKEY_new();
		X509 *crt = X509_new();
 	    const unsigned char* p = (unsigned char*)ias_cert;
 	    crt = d2i_X509(NULL, &p, ias_cert_size);
 	    assert(crt != NULL);
 	    evp_pubkey = X509_get_pubkey(crt);
		if(!evp_pubkey){
			printf("Failed to retreive public key\n");
			return;
		}

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