#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

#include <stdio.h>
#include <fstream>
#include <iostream>
#include <string.h>

using namespace std;

typedef void CRYPTO_RWLOCK;

struct evp_pkey_st {
    int type;
    int save_type;
    int references;
    const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *engine;
    union {
        char *ptr;
# ifndef OPENSSL_NO_RSA
        struct rsa_st *rsa;     /* RSA */
# endif
# ifndef OPENSSL_NO_DSA
        struct dsa_st *dsa;     /* DSA */
# endif
# ifndef OPENSSL_NO_DH
        struct dh_st *dh;       /* DH */
# endif
# ifndef OPENSSL_NO_EC
        struct ec_key_st *ec;   /* ECC */
# endif
    } pkey;
    int save_parameters;
    STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
    CRYPTO_RWLOCK *lock;
} /* EVP_PKEY */ ;

EVP_PKEY *evp_pkey;
RSA *keypair;

void rsa_key_gen()
{
	BIGNUM *bn = BN_new();
	if (bn == NULL) {
		printf("BN_new failure: %ld\n", ERR_get_error());
	    return;
	}
	int ret = BN_set_word(bn, RSA_F4);
    if (!ret) {
       	printf("BN_set_word failure\n");
	    return;
	}
	
	keypair = RSA_new();
	if (keypair == NULL) {
		printf("RSA_new failure: %ld\n", ERR_get_error());
	    return;
	}
	ret = RSA_generate_key_ex(keypair, 4096, bn, NULL);
	if (!ret) {
        printf("RSA_generate_key_ex failure: %ld\n", ERR_get_error());
	    return;
	}

	evp_pkey = EVP_PKEY_new();
	if (evp_pkey == NULL) {
		printf("EVP_PKEY_new failure: %ld\n", ERR_get_error());
		return;
	}
	EVP_PKEY_assign_RSA(evp_pkey, keypair);

	// public key - string
	int len = i2d_PublicKey(evp_pkey, NULL);
	unsigned char *buf = (unsigned char *) malloc (len + 1);
	unsigned char *tbuf = buf;
	i2d_PublicKey(evp_pkey, &tbuf);

	// print public key
	printf ("{\"public\":\"");
	int i;
	for (i = 0; i < len; i++) {
	    printf("%02x", (unsigned char) buf[i]);
	}
	printf("\"}\n");

	free(buf);

	// private key - string
	len = i2d_PrivateKey(evp_pkey, NULL);
	buf = (unsigned char *) malloc (len + 1);
	tbuf = buf;
	i2d_PrivateKey(evp_pkey, &tbuf);

	// print private key
	printf ("{\"private\":\"");
	for (i = 0; i < len; i++) {
	    printf("%02x", (unsigned char) buf[i]);
	}
	printf("\"}\n");

	free(buf);

	BN_free(bn);

    /*
	EVP_PKEY_free(evp_pkey);

	if (evp_pkey->pkey.ptr != NULL) {
	  RSA_free(keypair);
	}
    */
}

int freeEverthing(){
	EVP_PKEY_free(evp_pkey);

	if (evp_pkey->pkey.ptr != NULL) {
	  RSA_free(keypair);
	}
    return 0;
}

int main(int argc, char *argv[]){
	/*
    EVP_PKEY *pkey;
    FILE *f = fopen(argv[1], "rb");
    if(f == NULL){
        cout << "File is not read successfully..." << endl;
        return -1;
    }
    cout << "Before putting public key into it, the size is: " << sizeof(pkey) << endl;
    pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    cout << "After putting public key into it, the size is: " << sizeof(pkey) << endl;
    if(pkey == NULL){
        cout << "Key is not read successfully..." << endl;
        return -2;
    }

    int len = i2d_PublicKey(pkey, NULL);
	unsigned char *buf = (unsigned char *) malloc (len + 1);
	unsigned char *tbuf = buf;
	i2d_PublicKey(pkey, &tbuf);

    printf ("{\"public\":\"");
	int i;
	for (i = 0; i < len; i++) {
	    printf("%02x", (unsigned char) buf[i]);
	}
	printf("\"}\n");

	free(buf);
	*/

	rsa_key_gen();

	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	char mess1[] = "Test Hash\n";
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len, i;

	OpenSSL_add_all_digests();

	md = EVP_get_digestbyname("SHA256");

	if (md == NULL) {
         printf("Unknown message digest %s\n", "SHA256");
         exit(1);
    }

	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, md, NULL);
	/*
	EVP_DigestUpdate(mdctx, mess1, strlen(mess1));
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);

	printf("Digest is: ");
	for (i = 0; i < md_len; i++)
		printf("%02x", md_value[i]);
    printf("\n");
	*/

	int ret;
	ret = EVP_SignInit_ex(mdctx, EVP_sha256(), NULL);
	if(ret != 1){
		printf("EVP_SignInit_ex error. \n");
        exit(1);
	}

	ret = EVP_SignUpdate(mdctx, (void*)mess1, sizeof(mess1));
	if(ret != 1){
		printf("EVP_SignUpdate error. \n");
        exit(1);
	}

	//printf("The size of pkey is: %d\n", EVP_PKEY_size(evp_pkey));
	//printf("The len of pkey is: %d\n", i2d_PrivateKey(evp_pkey, NULL));

	unsigned char* signature;
	signature = (unsigned char*)malloc(1024);

	unsigned int sizeOfSignature = -1;

	ret = EVP_SignFinal(mdctx, signature, &sizeOfSignature, evp_pkey);
	if(ret != 1){
		printf("EVP_SignFinal error. \n");
        exit(1);
	}

	//printf("The signature is: %s\n", signature);
	printf("The size of signature is: %d\n", sizeOfSignature);

	// Below part is for verifying signature
	
	EVP_DigestInit_ex(mdctx, md, NULL);	// Temp re_initialize

	ret = EVP_VerifyInit_ex(mdctx, EVP_sha256(), NULL);
	if(ret != 1){
		printf("EVP_VerifyInit_ex error. \n");
        exit(1);
	}

	ret = EVP_VerifyUpdate(mdctx, (void*)mess1, sizeof(mess1));
	if(ret != 1){
		printf("EVP_VerifyUpdate error. \n");
        exit(1);
	}

	ret = EVP_VerifyFinal(mdctx, signature, (unsigned int)512, evp_pkey);
	printf("EVP_VerifyFinal result: %d\n", ret);

	// Below part is for freeing data
	// For freeing evp_md_ctx
	EVP_MD_CTX_free(mdctx);

	// For freeing the signature
	free(signature);

    return 0;
}



