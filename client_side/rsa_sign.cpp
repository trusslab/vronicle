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

EVP_PKEY *evp_pkey = NULL;
RSA* keypair;
char hash_of_file[65];

int read_rsa_pri_key(const char* private_key_name){
    // Return 0 on success, otherwise, return 1
    FILE* privatekey_file = fopen(private_key_name, "r");
    if(privatekey_file == NULL){
        printf("What the hell?!\n");
        return 1;
    }
    PEM_read_PrivateKey(privatekey_file, &evp_pkey, 0, 0);

    // private key - string
	int len = i2d_PrivateKey(evp_pkey, NULL);
	unsigned char *buf = (unsigned char *) malloc (len + 1);
	unsigned char *tbuf = buf;
	i2d_PrivateKey(evp_pkey, &tbuf);
    /*

	// print private key
	printf ("{\"private\":\"");
	int i;
	for (i = 0; i < len; i++) {
	    printf("%02x", (unsigned char) buf[i]);
	}
	printf("\"}\n");

	free(buf);
    */
    fclose(privatekey_file);



    return 0;
}

void sha256_hash_string (unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65])
{
    int i = 0;

    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }

    outputBuffer[64] = 0;
}

int read_file_as_hash(char* file_path){
    // Return 0 on success, otherwise, return 1
    FILE *file = fopen(file_path, "rb");
    if(file == NULL){
        return 1;
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    const int bufSize = 32768;
    unsigned char* buffer = (unsigned char*)malloc(bufSize);
    int bytesRead = 0;
    if(!buffer) return ENOMEM;
    while((bytesRead = fread(buffer, 1, bufSize, file)))
    {
        SHA256_Update(&sha256, buffer, bytesRead);
    }
    SHA256_Final(hash, &sha256);

    sha256_hash_string(hash, hash_of_file);
    fclose(file);
    free(buffer);
    return 0;
}

void Base64Encode( const unsigned char* buffer,
                   size_t length,
                   char** base64Text) {
  BIO *bio, *b64;
  BUF_MEM *bufferPtr;

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);

  BIO_write(bio, buffer, length);
  BIO_flush(bio);
  BIO_get_mem_ptr(bio, &bufferPtr);
  BIO_set_close(bio, BIO_NOCLOSE);
  BIO_free_all(bio);

  *base64Text=(*bufferPtr).data;
}

int sign_and_save_signature(const char* sign_file_name){
    // Return 0 on success, otherwise, return 1
    EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	// char mess1[] = "Test Hash\n";
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

    printf("hash_of_file to be signed: %s\n", hash_of_file);

	ret = EVP_SignUpdate(mdctx, (void*)hash_of_file, sizeof(hash_of_file));
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

	printf("The size of signature is: %d\n", sizeOfSignature);

    char* base64_signature;

    Base64Encode(signature, sizeOfSignature, &base64_signature);

    // printf("base64signature is: %s\n", base64_signature);

    // ofstream publickey_file;
    ofstream signature_file;
    signature_file.open(sign_file_name);
    if (!signature_file.is_open()){
        return 1;
    }
    signature_file.write(base64_signature, strlen(base64_signature));
    signature_file.close();
	EVP_MD_CTX_free(mdctx);

    free(signature);
    
    return 0;
}

int main(int argc, char *argv[]){
    if(argc != 3){
        printf("Usage: [private_key_name] [num_of_frames]");
        return 1;
    }

    int num_of_frames = atoi(argv[2]);

    if(read_rsa_pri_key(argv[1]) != 0){
        printf("Private key: %s cannot be read.\n", argv[1]);
        return 1;
    }

    char buf[25];
    char outbuf[30];

    for(int i = 0; i < 30; ++i){
        snprintf(buf, 25, "./out_raw/out_raw_%d", i);
        snprintf(outbuf, 30, "./out_raw_sign/camera_sign_%d", i);

        if(read_file_as_hash(buf) != 0){
            // https://stackoverflow.com/questions/2262386/generate-sha256-with-openssl-and-c
            printf("File(as hash): %s cannot be read.\n", buf);
            return 1;
        }

        // printf("The hash we have now is: %s\n", (char*)hash_to_be_signed);

        if(sign_and_save_signature(outbuf) != 0){
            // https://stackoverflow.com/questions/2262386/generate-sha256-with-openssl-and-c
            printf("Signature: %s cannot be signed or failed in saving.\n", outbuf);
            return 1;
        }
    }

    return 0;
}