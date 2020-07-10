#include <stdio.h>
#include "jpeglib.h"
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

#include <fstream>
#include <iostream>

#include "raw_def.h"
#include "single_pixel_color_filters.h"
#include "multi_pixel_color_filters.h"

using namespace std;

JSAMPLE * image_buffer = NULL;	/* Points to large array of R,G,B-order data */
int image_height = 0;	/* Number of rows in image */
int image_width = 0;		/* Number of columns in image */

int read_raw_file(const char* file_name){
    // Return 0 on success, return 1 on failure
    FILE* input_raw_file = fopen(file_name, "r");
    char buff[257]; // Plus one for eof
    int counter_for_image_info = 0; // First two are width and height
    int counter_for_checking_if_all_rgb_values_read_properly = 0;
    char* info;
    while(fgets(buff, 257, input_raw_file) != NULL){
        // printf("buff: %s\n", buff);
        info = strtok(buff, ",");
        while(info != NULL){
            // printf("Info: %d\n", atoi(info));
            if(counter_for_image_info == 0){
                image_width = atoi(info);
                ++counter_for_image_info;
            } else if (counter_for_image_info == 1){
                image_height = atoi(info);
                ++counter_for_image_info;
                printf("The image has width: %d, and height: %d.\n", image_width, image_height);
                image_buffer = (JSAMPLE*)malloc(sizeof(JSAMPLE) * image_width * image_height * 3);
            } else {
                if(counter_for_checking_if_all_rgb_values_read_properly + 10 >= image_width * image_height * 3){
                    // printf("Current counter: %d, current limit: %d.\n", counter_for_checking_if_all_rgb_values_read_properly, image_width * image_height * 3);
                    // printf("Current info: %d\n", atoi(info));
                }
                image_buffer[counter_for_checking_if_all_rgb_values_read_properly++] = atoi(info);
            }
            info = strtok(NULL, ",");
        }
        // printf("Current buff: %s\n", buff);
    }
    if(image_buffer == NULL || image_height == 0 || image_width == 0 || 
        counter_for_checking_if_all_rgb_values_read_properly != image_width * image_height * 3){
            return 1;
        }
    printf("The very first pixel has RGB value: (%d, %d, %d).\n", image_buffer[0], image_buffer[1], image_buffer[2]);
    return 0;
}

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
RSA *keypair = NULL;
char hash_of_file[65];
char* base64signature;

int read_rsa_pub_key(const char* publickey_file_name){
    // Return 0 on success, otherwise, return 1
    FILE* publickey_file = fopen(publickey_file_name, "r");
    if(publickey_file == NULL){
        printf("what? No file?\n");
        return 1;
    }
    /*
    keypair = PEM_read_RSAPublicKey(publickey_file, &keypair, NULL, NULL);
    if(keypair == NULL){
        return 1;
    }
    */
    evp_pkey = PEM_read_PUBKEY(publickey_file, &evp_pkey, NULL, NULL);
    if(evp_pkey == NULL){
        printf("A NULL key\n");
        return 1;
    }


    // public key - string
	int len = i2d_PublicKey(evp_pkey, NULL);
	unsigned char *buf = (unsigned char *) malloc (len + 1);
	unsigned char *tbuf = buf;
	i2d_PublicKey(evp_pkey, &tbuf);

    printf ("{\"public\":\"");
	int i;
	for (i = 0; i < len; i++) {
	    printf("%02x", (unsigned char) buf[i]);
	}
	printf("\"}\n");

	free(buf);

    fclose(publickey_file);

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

int read_signature(const char* sign_file_name){
    // Return 0 on success, otherwise, return 1
    FILE* signature_file = fopen(sign_file_name, "r");
    if(signature_file == NULL){
        return 1;
    }

    /*
    ifstream signature_file;
    signature_file.open(sign_file_name);

    if(!signature_file.is_open()){
        return 1;
    }
    */

    /*
    while(!signature_file.eof()){
        signature_file >> base64signature;
    }
    */
    
    //fgets(base64signature, 2048, signature_file);

    fseek(signature_file, 0, SEEK_END);
    long length = ftell(signature_file);
    fseek(signature_file, 0, SEEK_SET);

    base64signature = (char*)malloc(length);

    fread(base64signature, 1, length, signature_file);

    fclose(signature_file);
    return 0;
}

size_t calcDecodeLength(const char* b64input) {
  size_t len = strlen(b64input), padding = 0;

  if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
    padding = 2;
  else if (b64input[len-1] == '=') //last char is =
    padding = 1;
  return (len*3)/4 - padding;
}

void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length) {
  BIO *bio, *b64;

  int decodeLen = calcDecodeLength(b64message);
  *buffer = (unsigned char*)malloc(decodeLen + 1);
  (*buffer)[decodeLen] = '\0';

  bio = BIO_new_mem_buf(b64message, -1);
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_push(b64, bio);

  *length = BIO_read(bio, *buffer, strlen(b64message));
  BIO_free_all(bio);
}

int verify_signature(){
    // Return 1 on success, otherwise, return 0

    EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len, i;
	int ret;

	OpenSSL_add_all_digests();

    md = EVP_get_digestbyname("SHA256");

	if (md == NULL) {
         printf("Unknown message digest %s\n", "SHA256");
         exit(1);
    }

	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, md, NULL);

	ret = EVP_VerifyInit_ex(mdctx, EVP_sha256(), NULL);
	if(ret != 1){
		printf("EVP_VerifyInit_ex error. \n");
        exit(1);
	}

    printf("hash_of_file to be verified: %s\n", hash_of_file);

	ret = EVP_VerifyUpdate(mdctx, (void*)hash_of_file, sizeof(hash_of_file));
	if(ret != 1){
		printf("EVP_VerifyUpdate error. \n");
        exit(1);
	}

    // printf("base64signature: %s\n", base64signature);
    unsigned char* encMessage;
    size_t encMessageLength;
    Base64Decode(base64signature, &encMessage, &encMessageLength);

	ret = EVP_VerifyFinal(mdctx, encMessage, encMessageLength, evp_pkey);
	printf("EVP_VerifyFinal result: %d\n", ret);

	// Below part is for freeing data
	// For freeing evp_md_ctx
	EVP_MD_CTX_free(mdctx);

    return ret;
}

bool RSAVerifySignature( RSA* rsa,
                         unsigned char* MsgHash,
                         size_t MsgHashLen,
                         const char* Msg,
                         size_t MsgLen,
                         bool* Authentic) {
  *Authentic = false;
  EVP_PKEY* pubKey  = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(pubKey, rsa);
  EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();

  if (EVP_DigestVerifyInit(m_RSAVerifyCtx,NULL, EVP_sha256(),NULL,pubKey)<=0) {
    return false;
  }
  if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0) {
    return false;
  }
  int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
  printf("AuthStatus: %d\n", AuthStatus);
  if (AuthStatus==1) {
    *Authentic = true;
    EVP_MD_CTX_free(m_RSAVerifyCtx);
    return true;
  } else if(AuthStatus==0){
    *Authentic = false;
    EVP_MD_CTX_free(m_RSAVerifyCtx);
    return true;
  } else{
    *Authentic = false;
    EVP_MD_CTX_free(m_RSAVerifyCtx);
    return false;
  }
}

EVP_PKEY *new_evp_pkey = NULL;
RSA *new_keypair = NULL;

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
	
	new_keypair = RSA_new();
	if (new_keypair == NULL) {
		printf("RSA_new failure: %ld\n", ERR_get_error());
	    return;
	}
	ret = RSA_generate_key_ex(new_keypair, 4096, bn, NULL);
	if (!ret) {
        printf("RSA_generate_key_ex failure: %ld\n", ERR_get_error());
	    return;
	}

	new_evp_pkey = EVP_PKEY_new();
	if (new_evp_pkey == NULL) {
		printf("EVP_PKEY_new failure: %ld\n", ERR_get_error());
		return;
	}
	EVP_PKEY_assign_RSA(new_evp_pkey, new_keypair);

    /*
	// public key - string
	int len = i2d_PublicKey(new_evp_pkey, NULL);
	unsigned char *buf = (unsigned char *) malloc (len + 1);
	unsigned char *tbuf = buf;
	i2d_PublicKey(new_evp_pkey, &tbuf);

	// print public key
	printf ("{\"public\":\"");
	int i;
	for (i = 0; i < len; i++) {
	    printf("%02x", (unsigned char) buf[i]);
	}
	printf("\"}\n");

	free(buf);

	// private key - string
	len = i2d_PrivateKey(new_evp_pkey, NULL);
	buf = (unsigned char *) malloc (len + 1);
	tbuf = buf;
	i2d_PrivateKey(new_evp_pkey, &tbuf);

	// print private key
	printf ("{\"private\":\"");
	for (i = 0; i < len; i++) {
	    printf("%02x", (unsigned char) buf[i]);
	}
	printf("\"}\n");

	free(buf);
    */

	BN_free(bn);

    /*
	EVP_PKEY_free(new_evp_pkey);

	if (new_evp_pkey->pkey.ptr != NULL) {
	  RSA_free(new_keypair);
	}
    */
}

int save_key_pair(const char* public_key_file_name, const char* private_key_file_name){
    // Return 0 on success, otherwise, return 1

    // Save public key
    int len = i2d_PublicKey(new_evp_pkey, NULL);
	unsigned char *buf = (unsigned char *) malloc (len + 1);
	unsigned char *tbuf = buf;
	i2d_PublicKey(new_evp_pkey, &tbuf);

    // ofstream publickey_file;
    FILE* publickey_file = fopen(public_key_file_name, "w+");
    PEM_write_PUBKEY(publickey_file, new_evp_pkey);
    fclose(publickey_file);
    /*
    publickey_file.open(base_key_name + "_pub");
    if (!publickey_file.is_open()){
        return 1;
    }
    publickey_file.write((char*) tbuf, sizeof(tbuf));
    publickey_file.close();
    */

    // Save private key
    FILE* privatekey_file = fopen(private_key_file_name, "w+");
    PEM_write_PrivateKey(privatekey_file, new_evp_pkey, NULL, 0, 0, NULL, NULL);
    fclose(privatekey_file);
    /*
	free(buf);
    len = i2d_PrivateKey(new_evp_pkey, NULL);
	buf = (unsigned char *) malloc (len + 1);
	tbuf = buf;
	i2d_PrivateKey(new_evp_pkey, &tbuf);

    ofstream privatekey_file;
    privatekey_file.open(base_key_name + "_pri");
    if (!privatekey_file.is_open()){
        return 1;
    }
    privatekey_file.write((char*) tbuf, sizeof(tbuf));
    privatekey_file.close();

    free(buf);
    */

    return 0;
}

int freeEverthing(){
	EVP_PKEY_free(new_evp_pkey);

	if (new_evp_pkey->pkey.ptr != NULL) {
	  RSA_free(new_keypair);
	}
    return 0;
}

int apply_single_pixel_filter(){
    // Return 0 on success, otherwise, return 1
    // This will use a filter which take and process a single pixel each time
    int total_number_of_rgb_values = image_width * image_height * 3;
    for(int i = 0; i < total_number_of_rgb_values; i += 3){
        change_brightness(&image_buffer[i], &image_buffer[i + 1], &image_buffer[i + 2], 50);
    }
    return 0;
}

int apply_multi_pixel_filter(){
    // Return 0 on success, otherwise, return 1
    // This will use a filter which take and process many pixels each time
    int total_number_of_pixels = image_width * image_height;
    pixel* image_pixels = jsamples_to_pixels(image_buffer, total_number_of_pixels);
    free(image_buffer);
    pixel* result_pixels = blur(image_pixels, image_width, total_number_of_pixels, 9);
    // pixel* result_pixels = sharpen(image_pixels, image_width, total_number_of_pixels, 9);
    // pixel* result_pixels = blur_5(image_pixels, image_width, total_number_of_pixels, 1.0 / 25.0);
    // pixel* result_pixels = sharpen_3(image_pixels, image_width, total_number_of_pixels, 1.0 / 25.0);
    image_buffer = pixels_to_jsamples(image_pixels, total_number_of_pixels);
    free(image_pixels);
    return 0;
}

int save_and_free_output_image_buffer(const char* file_name){
    // First check if the number of pixels (RGB values) is correct
    // Return 0 if success, otherwise, return 1

    int total_number_of_rgb_values = image_width * image_height * 3;

    FILE* output_file = fopen(file_name, "w+");
    if(output_file == NULL){
        return 1;
    }
    fprintf(output_file, "%07d,%07d,", image_width, image_height);
    for(int i = 0; i < total_number_of_rgb_values - 1; ++i){
        fprintf(output_file, "%03d,", image_buffer[i]);
    }
    fprintf(output_file, "%03d", image_buffer[total_number_of_rgb_values - 1]);
    fclose(output_file);
    
    free(image_buffer);
    return 0;
}

int sign_and_save_signature(EVP_PKEY* key_for_sign, const char* sign_file_name){
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

	ret = EVP_SignUpdate(mdctx, (void*)hash_of_file, sizeof(hash_of_file));
	if(ret != 1){
		printf("EVP_SignUpdate error. \n");
        exit(1);
	}

	//printf("The size of pkey is: %d\n", EVP_PKEY_size(key_for_sign));
	//printf("The len of pkey is: %d\n", i2d_PrivateKey(key_for_sign, NULL));

	unsigned char* signature;
	signature = (unsigned char*)malloc(1024);

	unsigned int sizeOfSignature = -1;

	ret = EVP_SignFinal(mdctx, signature, &sizeOfSignature, key_for_sign);
	if(ret != 1){
		printf("EVP_SignFinal error. \n");
        exit(1);
	}

	printf("The size of signature is: %d\n", sizeOfSignature);

    // ofstream publickey_file;
    ofstream signature_file;
    signature_file.open(sign_file_name);
    if (!signature_file.is_open()){
        return 1;
    }
    signature_file.write((char*)signature, sizeOfSignature);
    signature_file.close();
	EVP_MD_CTX_free(mdctx);

    free(signature);
    
    return 0;
}

int main(int argc, char *argv[]){
    if(argc != 8){
        printf("Usage: [raw_file_name] [sign_file_name] [publickey_file_name] [new_publickey_file_name] \
            [new_privatekey_file_name] [new_signature_file_name] [raw_output_file_name]");
        return 1;
    }

    printf("Going to read hash...\n");

    if(read_file_as_hash(argv[1]) != 0){
        // https://stackoverflow.com/questions/2262386/generate-sha256-with-openssl-and-c
        printf("File(as hash): %s cannot be read.\n", argv[1]);
        return 1;
    }

    printf("Going to read public key...\n");

    if(read_rsa_pub_key(argv[3]) != 0){
        printf("Publickey file: %s cannot be read.\n", argv[3]);
        return 1;
    }

    printf("Going to read signature...\n");

    if(read_signature(argv[2]) != 0){
        printf("signature file: %s cannot be read.\n", argv[2]);
	    EVP_PKEY_free(evp_pkey);
        return 1;
    }

    cout << "base64signature: " << base64signature << endl;

    printf("Going to verify signature...\n");

    if(verify_signature() != 1){
        printf("signautre verfied failed.\n");
        free(base64signature);
        EVP_PKEY_free(evp_pkey);
        return 1;
    }

   /*

    bool result = true;
    unsigned char* encMessage;
    size_t encMessageLength;
    Base64Decode(base64signature, &encMessage, &encMessageLength);

    if(!RSAVerifySignature(keypair, encMessage, encMessageLength, hash_of_file, sizeof(hash_of_file), &result) || !result){
        printf("signautre verfied failed.\n");
        free(base64signature);
        return 1;
    }
    */

    free(base64signature);
	EVP_PKEY_free(evp_pkey);

    if(read_raw_file(argv[1]) != 0){
        printf("raw file: %s cannot be read.\n", argv[1]);
        return 1;
    }

    rsa_key_gen();
    if(new_keypair == NULL || new_evp_pkey == NULL){
        printf("new key gen failed\n");
        return 1;
    }

    if(save_key_pair(argv[4], argv[5]) != 0){
        printf("New public key file: %s cannot be saved or new private key file: %s cannot be saved.\n", argv[4], argv[5]);
    }

    //apply_single_pixel_filter();
    apply_multi_pixel_filter();

    if(save_and_free_output_image_buffer(argv[7]) != 0){
        printf("Raw output file: %s cannot be saved.\n", argv[7]);
        return 1;
    }

    if(read_file_as_hash(argv[7]) != 0){
        // https://stackoverflow.com/questions/2262386/generate-sha256-with-openssl-and-c
        printf("File(as hash): %s cannot be read.\n", argv[7]);
        return 1;
    }

    if(sign_and_save_signature(new_evp_pkey, argv[6]) != 0){
        printf("Signature file: %s cannot be generated.\n", argv[6]);
        return 1;
    }

    

    return 0;
}