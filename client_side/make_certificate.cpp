#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

int mkcert(X509 **x509p, EVP_PKEY *prikey, EVP_PKEY *pubkey, int serial, int days)
// adopted from https://opensource.apple.com/source/OpenSSL/OpenSSL-22/openssl/demos/x509/mkcert.c
	{
        // Return 0 on normal; otherwise if some error happens
        X509 *x;
        X509_NAME *name=NULL;

        if ((x509p == NULL) || (*x509p == NULL)){
            if ((x=X509_new()) == NULL){
                printf("X509 certificate cannot be created\n");
                return 1;
            }
		} else {
            x= *x509p;
        }

        printf("Certificate create complete\n");

        X509_set_version(x, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(x), serial);
        X509_gmtime_adj(X509_get_notBefore(x), 0);
	    X509_gmtime_adj(X509_get_notAfter(x), (long)60*60*24*days);
        X509_set_pubkey(x, pubkey);

        name = X509_get_subject_name(x);

        printf("Got certificate subject name\n");

        X509_NAME_add_entry_by_txt(name,"C",
				MBSTRING_ASC, (const unsigned char*)"US", -1, -1, 0);
	    X509_NAME_add_entry_by_txt(name,"CN",
				MBSTRING_ASC, (const unsigned char*)"IcySakura", -1, -1, 0);

        X509_set_issuer_name(x,name);

        if (!X509_sign(x, prikey, EVP_md5())){
            printf("X509 certificate cannot be signed\n");
            return 1;
        }

        *x509p=x;
        return 0;
    }

int main(int argc, char **argv){
    if(argc != 4){
        printf("Usage: [private_key_for_signing] [public_key_being_signed] [certificate_name]");
        return 1;
    }

    FILE* privatekey_file = fopen(argv[1], "r");
    EVP_PKEY *evp_private_key_for_signing = NULL;
    if(privatekey_file == NULL){
        printf("Private key is failed to read: %s\n", argv[1]);
        return 1;
    }
    PEM_read_PrivateKey(privatekey_file, &evp_private_key_for_signing, 0, 0);

    printf("Private key read complete\n");

    FILE* publickey_file = fopen(argv[2], "r");
    EVP_PKEY *evp_public_key_being_signed = NULL;
    if(publickey_file == NULL){
        printf("Public key is failed to read: %s\n", argv[2]);
        return 1;
    }
    PEM_read_PUBKEY(publickey_file, &evp_public_key_being_signed, 0, 0);

    printf("Public key read complete\n");

    X509 *cert = NULL;
    int result_of_mkcert = mkcert(&cert, evp_private_key_for_signing, evp_public_key_being_signed, 0, 365);

    if(result_of_mkcert == 0){
        if(cert == NULL){
            printf("Somehow the certificate is still NULL!!!!\n");
        }
        FILE* outfd = fopen(argv[3], "w");
        int result_of_save_cert = PEM_write_X509(outfd, cert);
        if(result_of_save_cert != 1){
            printf("Certificate cannot be saved: %s\n", argv[3]);
        }
    }

    return 0;
}
