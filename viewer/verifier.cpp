#include "verifier.h"
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

Verifier::Verifier(const std::string &_video_file_name,
                   const std::string &_sig_file_name,
                   const std::string &_pubkey_file_name) {
    video_file_name =  _video_file_name;
    sig_file_name =    _sig_file_name;
    pubkey_file_name = _pubkey_file_name;
}

void Verifier::verify() {
    FILE* video_file = fopen(video_file_name.c_str(), "rb");
    FILE* sig_file = fopen(sig_file_name.c_str(), "rb");
    FILE* pubkey_file = fopen(pubkey_file_name.c_str(), "r");
	if (video_file && sig_file && pubkey_file) {
		// Read video file
        fseek(video_file, 0, SEEK_END);
		size_t video_size = ftell(video_file);
        fseek(video_file, 0, SEEK_SET);
		char *video = new char [video_size + 1];
        fread(video, 1, video_size, video_file);
        video[video_size + 1] = '\0';
		fclose(video_file);

		// Read signature
        fseek(sig_file, 0, SEEK_END);
        size_t sig_size = ftell(sig_file);
        fseek(sig_file, 0, SEEK_SET);
        char *sig = new char [sig_size + 1];
        fread(sig, 1, sig_size, sig_file);
        sig[sig_size + 1] = '\0';
		fclose(sig_file);

		// Read public key
		EVP_PKEY* evp_pubkey = EVP_PKEY_new();
		evp_pubkey = PEM_read_PUBKEY(pubkey_file, &evp_pubkey, NULL, NULL);

		// Sign video file using client_privkey (for now)
		EVP_MD_CTX *mdctx = NULL;
		const EVP_MD *md = NULL;
		OpenSSL_add_all_digests();
		md = EVP_get_digestbyname("SHA256");
		if (md == NULL) {
			std::cout << "EVP_get_digestbyname error: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
			exit(1);
		}
		if(!(mdctx = EVP_MD_CTX_new())){
			std::cout << "EVP_MD_CTX_new error: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
			exit(1);
		}
		if(1 != EVP_DigestInit_ex(mdctx, md, NULL)){
			std::cout << "EVP_DigestInit_ex error: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
			exit(1);
		}
		if(1 != EVP_VerifyInit_ex(mdctx, EVP_sha256(), NULL)){
			std::cout << "EVP_VerifyInit_ex error: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
			exit(1);
		}
		if(1 != EVP_VerifyUpdate(mdctx, video, video_size)){
			std::cout << "EVP_VerifyUpdate error: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
			exit(1);
		}
		if(1 != EVP_VerifyFinal(mdctx, (const unsigned char*)sig, (unsigned int)sig_size, evp_pubkey)){
			std::cout << "EVP_VerifyFinal error: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
			exit(1);
		}
		delete[] video;
		delete[] sig;
		EVP_MD_CTX_free(mdctx);
		EVP_PKEY_free(evp_pubkey);
	}
    return;
}