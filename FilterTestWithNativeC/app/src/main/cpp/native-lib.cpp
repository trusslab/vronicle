#include <jni.h>
#include <string>
#include <unistd.h>
#include "RawBase.h"
#include "metadata.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include <android/log.h>

const static char* TAG = "native-lib";

#define printf(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__);

FILE *fpriv_key, *fpub_key;
EVP_PKEY *priv_key = nullptr, *pub_key = nullptr;

pixel* blur(pixel* image_buffer, pixel* output_buffer, int row_length, int total_num_of_pixels, int v){
    // Inspired by https://processing.org/examples/blur.html
    float avg_weight = 1.0 / (v * v);
    int pad = v / 2;
    float** kernel = new float*[v];
    for(int i = 0; i < v; ++i){
        kernel[i] = new float[v];
        for(int i2 = 0; i2 < v; ++i2){
            kernel[i][i2] = avg_weight;
        }
    }
    // printf("avg_weight: %f\n", avg_weight);
    // float kernel[3][3] = {{1, 2, 1}, {2, 4, 2}, {1, 2, 1}};
    int column_length = total_num_of_pixels / row_length;   // or height
    for(int y = 0; y < column_length; ++y){
        for(int x = 0; x < row_length; ++x){
            float temp_r = 0.0, temp_g = 0.0, temp_b = 0.0;
            for(int ky = 0 - pad; ky <= pad; ++ky){
                for(int kx = 0 - pad; kx <= pad; ++kx){
                    int pos = (y + ky) * row_length;
                    if(pos >= 0 && pos < total_num_of_pixels - 1 && (x + kx) >= 0 && (x + kx) < row_length){
                        pos += (x + kx);
                        temp_r += kernel[ky + pad][kx + pad] * image_buffer[pos].r;
                        temp_g += kernel[ky + pad][kx + pad] * image_buffer[pos].g;
                        temp_b += kernel[ky + pad][kx + pad] * image_buffer[pos].b;
                    }
                    // printf("y: %d, x: %d, ky: %d, kx: %d\n", y, x, ky, kx);
                }
            }
            /*
            temp_r *= 1.0 / 16.0;
            temp_g *= 1.0 / 16.0;
            temp_b *= 1.0 / 16.0;
            */
            output_buffer[y * row_length + x].r = truncate(temp_r);
            output_buffer[y * row_length + x].g = truncate(temp_g);
            output_buffer[y * row_length + x].b = truncate(temp_b);
        }
    }
    for(int i = 0; i < v; ++i){
        free(kernel[i]);
    }
    free(kernel);
    return output_buffer;
}

void denoise_simple(pixel* image_buffer, pixel* output_buffer, int row_length, int total_num_of_pixels){
    // Modified from https://github.com/m-cody/ImageEditor
    int column_length = total_num_of_pixels / row_length;   // or height
    int yStart, xStart, yEnd, xEnd;
    for (int y = 0; y < column_length - 1; y++)
    {
        for (int x = 0; x < row_length - 1; x++)
        {
            if (y == 0)
            {
                yStart = y;
                yEnd = y + 1;
            }
            else if (y == column_length - 1)
            {
                yStart = y - 1;
                yEnd = y;
            }
            else
            {
                yStart = y - 1;
                yEnd = y + 1;
            }

            if (x == 0)
            {
                xStart = x;
                xEnd = x + 1;
            }
            else if (x == row_length - 1)
            {
                xStart = x - 1;
                xEnd = x;
            }
            else
            {
                xStart = x - 1;
                xEnd = x + 1;
            }

            int red = 0, green = 0, blue = 0;
            for (int i = yStart; i <= yEnd; i++)
            {
                for (int j = xStart; j <= xEnd; j++)
                {
                    red += image_buffer[i * row_length + j].r;
                    green += image_buffer[i * row_length + j].g;
                    blue += image_buffer[i * row_length + j].b;
                }
            }
            output_buffer[y * row_length + x].r = red / 9;
            output_buffer[y * row_length + x].g = green / 9;
            output_buffer[y * row_length + x].b = blue / 9;
        }
    }
}

void gray_frame(pixel* image_buffer, pixel* output_buffer, int row_length, int total_num_of_pixels){
    // Modified from https://github.com/m-cody/ImageEditor
    int column_length = total_num_of_pixels / row_length;   // or height
    int pixelValue;
    for (int i = 0; i < column_length; i++)
    {
        for (int j = 0; j < row_length; j++)
        {
            int current_position = i * row_length + j;
            pixelValue = image_buffer[current_position].r;
            pixelValue += image_buffer[current_position].g;
            pixelValue += image_buffer[current_position].b;
            pixelValue /= 3;
            output_buffer[current_position].r = pixelValue;
            output_buffer[current_position].g = pixelValue;
            output_buffer[current_position].b = pixelValue;
        }
    }
}

extern "C" JNIEXPORT jint JNICALL
Java_com_example_filtertestwithnativec_MainActivity_testFilter(
        JNIEnv* env,
        jobject /* this */,
        int test_num, int num_of_rounds) {
//    std::string hello = "Hello from C++";
//    sleep(1);
    int image_width = 1280;
    int image_height = 720;
    pixel *input_image_buffer, *output_image_buffer;
    size_t processed_pixels_size = sizeof(pixel) * image_height * image_width;

    while(num_of_rounds){
        input_image_buffer = (pixel*)malloc(processed_pixels_size);
        output_image_buffer = (pixel*)malloc(processed_pixels_size);

        switch (test_num) {
            case 0:
                blur((pixel*)input_image_buffer, output_image_buffer, image_width, image_width * image_height, 7);
                break;
            case 1:
                denoise_simple((pixel*)input_image_buffer, output_image_buffer, image_width, image_width * image_height);
                break;
            case 2:
                gray_frame((pixel*)input_image_buffer, output_image_buffer, image_width, image_width * image_height);
                break;
            default:
                break;
        }

        free(input_image_buffer);
        free(output_image_buffer);
        --num_of_rounds;
    }

    return 0;
}

void Base64Encode( const unsigned char* buffer,
                   size_t length,
                   char** base64Text,
                   size_t* actual_base64_len) {
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

    *actual_base64_len = (*bufferPtr).length - 1;

    (*bufferPtr).data[*actual_base64_len] = '\0';
    *base64Text=(*bufferPtr).data;
}

int hash_pubkey (EVP_PKEY* pubkey, char** hash_b64, size_t *hash_b64_len)
{
    EVP_MD_CTX *mdctx = NULL;
    BIO* keybio = BIO_new(BIO_s_mem());
    EVP_PKEY_print_public(keybio, pubkey, 0, NULL);
    int ret = 1;
    char buffer[2048];  // Was originally 1024, however it's not enough...
    unsigned char hash[SHA256_DIGEST_LENGTH];
//    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    do {
        /* Create the Message Digest Context */
        if(!(mdctx = EVP_MD_CTX_create())){
            printf("EVP_MD_CTX_create error: %ld. \n", ERR_get_error());
            break;
        }

//        printf("[hash_pubkey]: 1");

        /* Initialize Digest operation */
        if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
            printf("EVP_DigestInit_ex error: %ld. \n", ERR_get_error());
            break;
        }
//        OpenSSL_add_all_digests();
//        if(1 != EVP_DigestInit_ex(mdctx, EVP_get_digestbyname("MD5"), NULL)) {
//            printf("EVP_DigestInit_ex error: %ld. \n", ERR_get_error());
//            break;
//        }

//        printf("[hash_pubkey]: 2");

        memset(buffer, 0, 2048);
        while (BIO_read(keybio, buffer, 2048) > 0)
        {
//            buffer[1024] = '\n';
//            printf("[hash_pubkey]: 2.1: {%s}\n", buffer);
//            printf("[hash_pubkey]: 2.1: %d\n", strlen(buffer));
            /* Update Digest operation */
            if(1 != EVP_DigestUpdate(mdctx, buffer, strlen(buffer))) {
                printf("EVP_DigestUpdate error: %ld. \n", ERR_get_error());
                break;
            }
            memset(buffer, 0, 2048);
//            printf("[hash_pubkey]: 2.2");
        }

//        printf("[hash_pubkey]: 3");

        /* Finalize Digest operation */
        if(1 != EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
            printf("EVP_DigestFinal_ex error: %ld. \n", ERR_get_error());
            break;
        }

//        printf("[hash_pubkey]: 4");

        /* Encode hash to base 64 format */
//        printf("hash_raw(%d): {%s}\n", hash_len, hash);
        Base64Encode(hash, SHA256_DIGEST_LENGTH, hash_b64, hash_b64_len);

//        printf("[hash_pubkey]: 5");

        ret = 0;
    } while(0);

    BIO_free(keybio);
    EVP_MD_CTX_free(mdctx);
    return ret;
}

int hash (char* str_to_hash, size_t len_of_str_of_hash, char** hash_b64, size_t *hash_b64_len)
{
    EVP_MD_CTX *mdctx = NULL;
    int ret = 1;
    unsigned char hash[SHA256_DIGEST_LENGTH];
//    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    do {
        /* Create the Message Digest Context */
        if(!(mdctx = EVP_MD_CTX_create())){
            printf("EVP_MD_CTX_create error: %ld. \n", ERR_get_error());
            break;
        }

//        printf("[hash_pubkey]: 1");

        /* Initialize Digest operation */
        if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
            printf("EVP_DigestInit_ex error: %ld. \n", ERR_get_error());
            break;
        }
//        OpenSSL_add_all_digests();
//        if(1 != EVP_DigestInit_ex(mdctx, EVP_get_digestbyname("MD5"), NULL)) {
//            printf("EVP_DigestInit_ex error: %ld. \n", ERR_get_error());
//            break;
//        }

//        printf("[hash_pubkey]: 2");

        if(1 != EVP_DigestUpdate(mdctx, str_to_hash, len_of_str_of_hash)) {
            printf("EVP_DigestUpdate error: %ld. \n", ERR_get_error());
            break;
        }

//        printf("[hash_pubkey]: 3");

        /* Finalize Digest operation */
        if(1 != EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
            printf("EVP_DigestFinal_ex error: %ld. \n", ERR_get_error());
            break;
        }

//        printf("[hash_pubkey]: 4");

        /* Encode hash to base 64 format */
//        printf("hash_raw(%d): {%s}\n", hash_len, hash);
        Base64Encode(hash, SHA256_DIGEST_LENGTH, hash_b64, hash_b64_len);

//        printf("[hash_pubkey]: 5");

        ret = 0;
    } while(0);

    EVP_MD_CTX_free(mdctx);
    return ret;
}

size_t calcDecodeLength(const char* b64input) {
    size_t len = strlen(b64input), padding = 0;
    // printf("The len in calc is: %d\n", (int)len);

    if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len-1] == '=') //last char is =
        padding = 1;

    // printf("The padding in calc is: %d\n", (int)padding);
    return (len*3)/4 - padding;
}

void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length) {
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

unsigned char* decode_signature(char* encoded_sig, long encoded_sig_len, size_t* signatureLength){
    // Return signature on success, otherwise, return NULL
    // Need to free the return after finishing using
    // Make sure you have extra char space for puting EOF at the end of encoded_sig

    encoded_sig[encoded_sig_len] = '\0';
    unsigned char* signature;
    Base64Decode(encoded_sig, &signature, signatureLength);

    return signature;
}

void print_public_key(EVP_PKEY* evp_pkey){
    // public key - string
    int len = i2d_PublicKey(evp_pkey, NULL);
    printf("[decoder:TestApp]: For publickey, the size of buf is: %d\n", len);
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
}

void print_private_key(EVP_PKEY* evp_pkey){
    // private key - string
    int len = i2d_PrivateKey(evp_pkey, NULL);
    printf("[decoder:TestApp]: For privatekey, the size of buf is: %d\n", len);
    unsigned char *buf = (unsigned char *) malloc (len + 1);
    unsigned char *tbuf = buf;
    i2d_PrivateKey(evp_pkey, &tbuf);

    // print private key
    printf ("{\"private\":\"");
    int i;
    for (i = 0; i < len; i++) {
        printf("%02x", (unsigned char) buf[i]);
    }
    printf("\"}\n");

    free(buf);
}

int sign (EVP_PKEY* priv_key, void *data_to_be_signed, size_t size_of_data, char **sig_b64, size_t *sig_len_b64)
{
    EVP_MD_CTX *mdctx = NULL;

    /* Create the Message Digest Context */
    if(!(mdctx = EVP_MD_CTX_create())){
        printf("EVP_MD_CTX_create error: %ld. \n", ERR_get_error());
        exit(1);
    }

    /* Initialise the DigestSign operation - SHA-256 has been selected as the message digest function in this example */
    if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, priv_key)){
        printf("EVP_DigestSignInit error: %ld. \n", ERR_get_error());
        exit(1);
    }

    /* Call update with the message */
    if(1 != EVP_DigestSignUpdate(mdctx, data_to_be_signed, size_of_data)){
        printf("EVP_DigestSignUpdate error: %ld. \n", ERR_get_error());
        exit(1);
    }

    /* Finalise the DigestSign operation */
    /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
    * signature. Length is returned in slen */
    size_t size_of_sig = 0;
    if(1 != EVP_DigestSignFinal(mdctx, NULL, &size_of_sig)){
        printf("EVP_DigestSignFinal error: %s. \n", ERR_error_string(ERR_get_error(), NULL));
        exit(1);
    };
    unsigned char *sig = (unsigned char*)malloc(size_of_sig);
    if(1 != EVP_DigestSignFinal(mdctx, sig, &size_of_sig)){
        printf("EVP_DigestSignFinal error: %s. \n", ERR_error_string(ERR_get_error(), NULL));
        exit(1);
    };

    Base64Encode(sig, size_of_sig, sig_b64, sig_len_b64);

    /* Clean up */
    if(mdctx) EVP_MD_CTX_destroy(mdctx);

    return 0;
}

bool verify_hash(void* hash_of_file, int size_of_hash, unsigned char* signature_b64, size_t size_of_siganture_b64, EVP_PKEY* public_key){
    // Return true on success; otherwise, return false
    EVP_MD_CTX *mdctx = NULL;
    const EVP_MD *md = NULL;
    int ret = 1;

    size_t size_of_siganture;
    unsigned char* signature = decode_signature((char*)signature_b64, size_of_siganture_b64, &size_of_siganture);

    OpenSSL_add_all_digests();

    do {
        md = EVP_get_digestbyname("SHA256");

        if (md == NULL) {
            printf("Unknown message digest %s\n", "SHA256");
            ret = 0;
            break;
        }

        mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, md, NULL);

        ret = EVP_VerifyInit_ex(mdctx, EVP_sha256(), NULL);
        if(ret != 1){
            printf("EVP_VerifyInit_ex error. \n");
            break;
        }

        // printf("hash_of_file to be verified: %s (len: %i)\n", hash_of_file, size_of_hash);

        ret = EVP_VerifyUpdate(mdctx, hash_of_file, size_of_hash);
        if(ret != 1){
            printf("EVP_VerifyUpdate error. \n");
            break;
        }

        ret = EVP_VerifyFinal(mdctx, signature, (unsigned int)size_of_siganture, public_key);
        if(ret != 1){
            printf("EVP_VerifyFinal error. \n");
            break;
        }
        // printf("EVP_VerifyFinal result: %d\n", ret);
    } while(0);

    // Below part is for freeing data
    // For freeing evp_md_ctx
    if (mdctx) EVP_MD_CTX_free(mdctx);
    if (signature) free(signature);

    return ret;
}

extern "C" JNIEXPORT int JNICALL
Java_com_example_filtertestwithnativec_MainActivity_read_1keys(
        JNIEnv* env,
        jobject /* this */,
        jstring path_of_prikey_jstr, jstring path_of_pubkey_jstr) {

//    pub_key = EVP_PKEY_new();
//    const char *pubkey_str = (*env).GetStringUTFChars(pubkey_jstr, nullptr);
//    printf("We have pubkey_str(%ld): {%s}\n", (long)strlen(pubkey_str), (const char*)(const unsigned char*)pubkey_str);
//    const char* test_pubkey_str = "-----BEGIN PUBLIC KEY-----\n"
//                                  "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAopF5nggjEqgP3INF663t\n"
//                                  "8+HPt90WZ8z5g6NYr228TfKGywfnmpmLuzt+rc2zMK229lXSNYCnKMvF0ge4gYHI\n"
//                                  "v1rjsQiDIZmGVGNsudIMm02qlBLeLtegFjVNTc5562D561pV96t4dIPHsykpzjZO\n"
//                                  "AMXP8BUuHJeeNdPZFekbfID0ec5NTumLnZGrSxh/PngHEkmWhn6mjUmooVxvliyn\n"
//                                  "1dqbgwOiLSpxf+xmIFPCgXPBJDGhX3jc/j6jEh6ydR3nYw9q4LdC18REmHl6EUmD\n"
//                                  "TBW6KyTHCS1RKEXpWtGgR17o4ahqfELIQKXyQEcOhyOBy8HdIdLsHA4gxVPXYq07\n"
//                                  "Lj8M4RZbtFdtlJlMZuqY1b7wm3GpUGpcPelGaYfeftneQh9VTAfEr3Mx4XbNCCqc\n"
//                                  "3y6YRJacaZcZHaF7hAz/lRPCXIQIE3nG8fQq5wcCkvAJ8hqVxbU6YNe0MswSO72b\n"
//                                  "yG0h6gC/epbiJSUEcPZY5bgoOkcEgveH+u7mC0NCfPh5IrxTGTXmi5qs/vZ/f3nV\n"
//                                  "SLD/oGCuA6Vhe1dt4Ws5e+fVG+0mNI7RZRty2rAY0AYeQOzMEyjKhp9cl6HaHF2c\n"
//                                  "HUaxu/wSQ3D8HFyYmeVjXi0VFTDpu/qmiH36ryncqilBCeeju75Vm4UqH3/0vRto\n"
//                                  "0/89p9eFt0wh+1y+BaN/slcCAwEAAQ==\n"
//                                  "-----END PUBLIC KEY-----";
//    printf("We have pubkey_str(%ld): {%s}\n", (long)strlen(test_pubkey_str), (const char*)(const unsigned char*)test_pubkey_str);
//    pub_key = d2i_PublicKey(EVP_PKEY_RSA, nullptr, (const unsigned char**)(&test_pubkey_str), (long)strlen(test_pubkey_str));
//
//    print_public_key(pub_key);
//
//    priv_key = EVP_PKEY_new();
//    const char *prikey_str = (*env).GetStringUTFChars(prikey_jstr, nullptr);
//    d2i_PrivateKey(EVP_PKEY_RSA, &priv_key, reinterpret_cast<const unsigned char **>(&prikey_str), (long)strlen(prikey_str));
//
//    print_private_key(priv_key);

//    FILE* file = fopen("/sdcard/hello.txt","w+");
//
//    if (file != NULL)
//    {
//        fputs("HELLO WORLD!\n", file);
//        fflush(file);
//        fclose(file);
//    }

    if (!priv_key) {
        const char *path_of_prikey = (*env).GetStringUTFChars(path_of_prikey_jstr, nullptr);
        fpriv_key = fopen(path_of_prikey, "r");
        if (!fpriv_key)
        {
            printf("ERROR: cant open input file %s\n", path_of_prikey);
            return 1;
        }
        priv_key = EVP_PKEY_new();
        priv_key = PEM_read_PrivateKey(fpriv_key, &priv_key, NULL, NULL);
        if (!priv_key)
        {
            printf("ERROR: cant read private key\n");
            return 1;
        }
//    print_private_key(priv_key);
        printf("priv_key is read from: %s\n", path_of_prikey);
    }

    if (!pub_key) {
        const char *path_of_pubkey = (*env).GetStringUTFChars(path_of_pubkey_jstr, nullptr);
        fpub_key = fopen(path_of_pubkey, "r");
        if (!fpub_key)
        {
            printf("ERROR: cant open input file %s\n", path_of_pubkey);
            return 1;
        }
        pub_key = EVP_PKEY_new();
        pub_key = PEM_read_PUBKEY(fpub_key, &pub_key, NULL, NULL);
        if (!pub_key)
        {
            printf("ERROR: cant read public key\n");
            return 1;
        }
//    print_public_key(pub_key);
        printf("pub_key is read from: %s\n", path_of_pubkey);
    }

    char* sig_b64 = NULL;
    size_t sig_len_b64 = 0;

    char* data_to_sign = (char*) malloc(100);
    memset(data_to_sign, 0, 100);
    memcpy(data_to_sign, "test\0", 4);

    sign(priv_key, data_to_sign, 100, &sig_b64, &sig_len_b64);

    bool result_of_verification = verify_hash(data_to_sign, 100, (unsigned char*)sig_b64, sig_len_b64, pub_key);

    printf("result_of_verification(1): %d...\n", result_of_verification);

//    result_of_verification = verify_hash(data_to_sign, 100, (unsigned char*)sig_b64, sig_len_b64, pub_key);
//
//    printf("result_of_verification(2): %d...\n", result_of_verification);
    free(data_to_sign);

    return 0;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_filtertestwithnativec_MainActivity_generate_1metadata(
        JNIEnv* env,
        jobject /* this */,
        int g_w, int g_h, int fps, int num_of_frames,
        jstring first_attestation_report_jstr, jstring second_attestation_report_jstr,
        jobjectArray filter_names, jintArray filter_parameter_nums, jdoubleArray filter_parameters) {
//    std::string hello = "Hello from C++";
//    sleep(1);
//    char test[15] = "This is a test";
//    int len_of_metadata = strlen(test);

    metadata* md = (metadata*)malloc(sizeof(metadata));
    memset(md, 0, sizeof(metadata));
    size_t hash_len = 0;
    md->video_id = (char*)malloc(SHA256_DIGEST_LENGTH * sizeof(char));
//    printf("size of md->video_id: %d\n", SHA256_DIGEST_LENGTH * sizeof(char));
    hash_pubkey(pub_key, &md->video_id, &hash_len);
    md->timestamp = time(NULL);
    md->width = g_w;
    md->height = g_h;
    md->segment_id = 0;
    md->total_segments = 1;
    md->frame_rate = fps;
    md->total_frames = num_of_frames;
    md->total_filters = env->GetArrayLength(filter_names);
    md->filters = (char**)malloc(sizeof(char*) * md->total_filters);
    md->filters_parameters_registry = (int*)malloc(sizeof(int) * md->total_filters);
    int length_of_filter_parameter_nums = env->GetArrayLength(filter_parameter_nums);
    md->total_filters_parameters = 0;
    jint *filter_parameter_nums_temp = env->GetIntArrayElements(filter_parameter_nums, 0);
    for (int i = 0; i < length_of_filter_parameter_nums; ++i) {
        md->filters_parameters_registry[i] = (int) (filter_parameter_nums_temp[i]);
        md->total_filters_parameters += md->filters_parameters_registry[i];
    }
    md->filters_parameters = (double*)malloc(sizeof(double) * md->total_filters_parameters);
    int filter_parameters_counter = 0;
    jdouble *filter_parameters_temp = env->GetDoubleArrayElements(filter_parameters, 0);
    for (int i = 0; i < md->total_filters; ++i) {
        const char *filter_name = env->GetStringUTFChars((jstring)(env->GetObjectArrayElement(filter_names, i)), 0);
//        printf("Java_com_example_filtertestwithnativec_MainActivity_generate_1metadata: filter_name(%d): {%s}\n", strlen(filter_name), filter_name);
        md->filters[i] = (char*)malloc(sizeof(char) * (strlen(filter_name) + 1));
        memcpy(md->filters[i], filter_name, strlen(filter_name));
        *(md->filters[i] + strlen(filter_name)) = '\0';
        for (int a = 0; a < md->filters_parameters_registry[i]; ++a) {
            md->filters_parameters[filter_parameters_counter] = (double) (filter_parameters_temp[filter_parameters_counter]);
            ++filter_parameters_counter;
        }
    }
    md->total_digests = 0;
    md->is_safetynet_presented = 1;
    md->num_of_safetynet_jws = 2;
    md->safetynet_jws = (char**)malloc(sizeof(char*) * md->num_of_safetynet_jws);

    size_t len_of_attestation_report_b64;
    const char *first_attestation_report = (*env).GetStringUTFChars(first_attestation_report_jstr, nullptr);
//    printf("Java_com_example_filtertestwithnativec_MainActivity_generate_1metadata: first_attestation_report(%d): {%s}", strlen(first_attestation_report), first_attestation_report);
    size_t size_of_first_attestation_report = strlen(first_attestation_report) * sizeof(char);
    md->safetynet_jws[0] = (char*) malloc(size_of_first_attestation_report + sizeof(char));
    memset(md->safetynet_jws[0], 0, size_of_first_attestation_report);
    memcpy(md->safetynet_jws[0], first_attestation_report, size_of_first_attestation_report);
    md->safetynet_jws[0][size_of_first_attestation_report] = '\0';
    printf("first_attestation_report size: %d\n", size_of_first_attestation_report);
//    Base64Encode((const unsigned char*)first_attestation_report, strlen(first_attestation_report), &(md->safetynet_jws[0]), &len_of_attestation_report_b64);
//    printf("Java_com_example_filtertestwithnativec_MainActivity_generate_1metadata: first_attestation_report_b64(%d): {%s}", len_of_attestation_report_b64, md->safetynet_jws[0]);
//    printf("first_attestation_report size: %d, after encoded, the new size: %d\n", strlen(first_attestation_report), len_of_attestation_report_b64);
    const char *second_attestation_report = (*env).GetStringUTFChars(second_attestation_report_jstr, nullptr);
    size_t size_of_second_attestation_report = strlen(second_attestation_report) * sizeof(char);
    md->safetynet_jws[1] = (char*) malloc(size_of_second_attestation_report + sizeof(char));
    memset(md->safetynet_jws[1], 0, size_of_second_attestation_report);
    memcpy(md->safetynet_jws[1], second_attestation_report, size_of_second_attestation_report);
    md->safetynet_jws[1][size_of_first_attestation_report] = '\0';
    printf("second_attestation_report size: %d\n", size_of_second_attestation_report);
//    Base64Encode((const unsigned char*)second_attestation_report, strlen(second_attestation_report), &(md->safetynet_jws[1]), &len_of_attestation_report_b64);
//    printf("second_attestation_report size: %d, after encoded, the new size: %d\n", strlen(second_attestation_report), len_of_attestation_report_b64);

    char* json = NULL;
    json = metadata_2_json_without_frame_id(md);
    printf("The final generated metadata_json has a size of: %d\n", strlen(json));

    jstring str_to_ret = ((*env).NewStringUTF(json));

    free(json);
    free_metadata(md);

    return str_to_ret;
}

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

int rsa_key_gen()
{
    BIGNUM *bn = BN_new();
    if (bn == NULL) {
        printf("BN_new failure: %ld\n", ERR_get_error());
        return 1;
    }
    int ret = BN_set_word(bn, RSA_F4);
    if (!ret) {
        printf("BN_set_word failure\n");
        return 1;
    }

    RSA *keypair = RSA_new();
    if (keypair == NULL) {
        printf("RSA_new failure: %ld\n", ERR_get_error());
        return 1;
    }
    ret = RSA_generate_key_ex(keypair, 4096, bn, NULL);
    if (!ret) {
        printf("RSA_generate_key_ex failure: %ld\n", ERR_get_error());
        return 1;
    }

    priv_key = EVP_PKEY_new();
    if (priv_key == NULL) {
        printf("EVP_PKEY_new failure: %ld\n", ERR_get_error());
        return 1;
    }
    EVP_PKEY_assign_RSA(priv_key, keypair);

//    // public key - string
//    int len = i2d_PublicKey(priv_key, NULL);
//    unsigned char *buf = (unsigned char *) malloc (len + 1);
//    unsigned char *tbuf = buf;
//    i2d_PublicKey(priv_key, &tbuf);
//
//    // print public key
//    printf ("{\"public\":\"");
//    int i;
//    for (i = 0; i < len; i++) {
//        printf("%02x", (unsigned char) buf[i]);
//    }
//    printf("\"}\n");
//
//    free(buf);
//
//    // private key - string
//    len = i2d_PrivateKey(priv_key, NULL);
//    buf = (unsigned char *) malloc (len + 1);
//    tbuf = buf;
//    i2d_PrivateKey(priv_key, &tbuf);
//
//    // print private key
//    printf ("{\"private\":\"");
//    for (i = 0; i < len; i++) {
//        printf("%02x", (unsigned char) buf[i]);
//    }
//    printf("\"}\n");
//
//    free(buf);

//    BN_free(bn);

//    pub_key = priv_key;

    BIO *pubkey_bio = BIO_new(BIO_s_mem());
    int result_of_writing_pubkey = PEM_write_bio_RSA_PUBKEY(pubkey_bio, keypair);
//    printf("rsa_key_gen: result_of_writing_pubkey: %d\n", result_of_writing_pubkey);
//    pub_key = EVP_PKEY_new();
    pub_key = PEM_read_bio_PUBKEY(pubkey_bio, &pub_key, NULL, NULL);
    BIO_free(pubkey_bio);
//
//    char* sig_b64 = NULL;
//    size_t sig_len_b64 = 0;
//
//    char* data_to_sign = (char*) malloc(100);
//    memset(data_to_sign, 0, 100);
//    memcpy(data_to_sign, "test", 4);
//
//    sign(priv_key, data_to_sign, 100, &sig_b64, &sig_len_b64);
//
//    bool result_of_verification = verify_hash(data_to_sign, 100, (unsigned char*)sig_b64, sig_len_b64, priv_key);
//
//    printf("result_of_verification(1): %d...\n", result_of_verification);
//
//    result_of_verification = verify_hash(data_to_sign, 100, (unsigned char*)sig_b64, sig_len_b64, pub_key);
//
//    printf("result_of_verification(2): %d...\n", result_of_verification);
//    free(data_to_sign);

//    if (priv_key->pkey.ptr != NULL) {
//        RSA_free(keypair);
//    }

    return 0;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_example_filtertestwithnativec_MainActivity_generate_1keypair(
        JNIEnv* env,
        jobject /* this */) {

    // Return 0 on success, otherwise fail
    return rsa_key_gen();
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_filtertestwithnativec_MainActivity_get_1pubkey(
        JNIEnv* env,
        jobject /* this */) {

    int len = i2d_PublicKey(pub_key, NULL);
    jbyte *buf = (jbyte *) malloc (len);
    unsigned char *tbuf = (unsigned char*)buf;
    i2d_PublicKey(pub_key, &tbuf);

//    char* hash_of_pubkey;
////    printf("SHA256_DIGEST_LENGTH: %d\n", SHA256_DIGEST_LENGTH);
//    size_t size_of_hash_of_pubkey = 0;
//
//    if (!hash_pubkey(pub_key, &hash_of_pubkey, &size_of_hash_of_pubkey)) {
//        printf("Java_com_example_filtertestwithnativec_MainActivity_get_1pubkey: hash of pubkey1: {%s}\n", hash_of_pubkey);
//    } else {
//        printf("Java_com_example_filtertestwithnativec_MainActivity_get_1pubkey: cannot get hash of pubkey...\n");
//    }
//    free(hash_of_pubkey);
//    if (!hash_pubkey(pub_key, &hash_of_pubkey, &size_of_hash_of_pubkey)) {
//        printf("Java_com_example_filtertestwithnativec_MainActivity_get_1pubkey: hash of pubkey2: {%s}\n", hash_of_pubkey);
//    } else {
//        printf("Java_com_example_filtertestwithnativec_MainActivity_get_1pubkey: cannot get hash of pubkey...\n");
//    }
//
//    free(hash_of_pubkey);
//// ==================================================================
//    EVP_PKEY *pubkey_temp = EVP_PKEY_new();
//
//    printf("len_of_buf: %d\n", len);
//    pubkey_temp = d2i_PublicKey(EVP_PKEY_RSA, &pubkey_temp, (const unsigned char**)(&buf), len);
//
//    hash_of_pubkey = (char*)malloc(SHA256_DIGEST_LENGTH * sizeof(char));
//    size_of_hash_of_pubkey = 0;
//
//    if (!hash_pubkey(pubkey_temp, &hash_of_pubkey, &size_of_hash_of_pubkey)) {
//        printf("Java_com_example_filtertestwithnativec_MainActivity_get_1pubkey: hash of pubkey3: {%s}\n", hash_of_pubkey);
//    } else {
//        printf("Java_com_example_filtertestwithnativec_MainActivity_get_1pubkey: cannot get hash of pubkey...\n");
//    }
//    free(hash_of_pubkey);
//    if (!hash_pubkey(pubkey_temp, &hash_of_pubkey, &size_of_hash_of_pubkey)) {
//        printf("Java_com_example_filtertestwithnativec_MainActivity_get_1pubkey: hash of pubkey4: {%s}\n", hash_of_pubkey);
//    } else {
//        printf("Java_com_example_filtertestwithnativec_MainActivity_get_1pubkey: cannot get hash of pubkey...\n");
//    }
//    free(hash_of_pubkey);

//    free(hash_of_pubkey);
//    EVP_PKEY_free(pubkey_temp);

//    char* sig_b64 = NULL;
//    size_t sig_len_b64 = 0;
//
//    char* data_to_sign = (char*) malloc(100);
//    memset(data_to_sign, 0, 100);
//    memcpy(data_to_sign, "test", 4);
//
//    sign(priv_key, data_to_sign, 100, &sig_b64, &sig_len_b64);
//
//    bool result_of_verification = verify_hash(data_to_sign, 100, (unsigned char*)sig_b64, sig_len_b64, priv_key);
//
//    printf("result_of_verification(1): %d...\n", result_of_verification);
//
//    result_of_verification = verify_hash(data_to_sign, 100, (unsigned char*)sig_b64, sig_len_b64, pub_key);
//
//    printf("result_of_verification(2): %d...\n", result_of_verification);
//
//    result_of_verification = verify_hash(data_to_sign, 100, (unsigned char*)sig_b64, sig_len_b64, pubkey_temp);
//
//    printf("result_of_verification(3): %d...\n", result_of_verification);
//
//    EVP_PKEY_free(pubkey_temp);
//    free(data_to_sign);

    char* pubkey_b64;
    size_t size_of_pubkey_b64;
    Base64Encode((const unsigned char*)buf, len, &pubkey_b64, &size_of_pubkey_b64);

//    jbyteArray ret = env->NewByteArray(size_of_pubkey_b64);
//
////    printf("Going to SetByteArrayRegion...\n");
//
//    env->SetByteArrayRegion (ret, 0, size_of_pubkey_b64, (jbyte*)pubkey_b64);
    jstring str_to_ret = ((*env).NewStringUTF(pubkey_b64));

    free(buf);
    free(pubkey_b64);

//    printf("Going to return...\n");

    return str_to_ret;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_example_filtertestwithnativec_MainActivity_print_1hash_1of_1pubkey(
        JNIEnv* env,
        jobject /* this */,
        jstring pubkey_b64_jbarr) {

    // Return 0 on success, otherwise fail

//    const int len_of_pubkey_jbarr = env->GetArrayLength(pubkey_b64_jbarr);
//    const char* pubkey_str_b64 = (char*) env->GetByteArrayElements(pubkey_b64_jbarr, (jboolean *)0);
    const int len_of_pubkey_jbarr = env->GetStringLength(pubkey_b64_jbarr);
    const char* pubkey_str_b64 = env->GetStringUTFChars(pubkey_b64_jbarr, (jboolean *)0);

    unsigned char* pubkey_str;
    size_t size_of_pubkey_str;
    Base64Decode(pubkey_str_b64, &pubkey_str, &size_of_pubkey_str);

    EVP_PKEY *pubkey_temp = EVP_PKEY_new();

//    printf("pubkey_str_b64(%d): {%s}\n", len_of_pubkey_jbarr, pubkey_str_b64);
//    printf("size_of_pubkey_str: %d\n", size_of_pubkey_str);
    pubkey_temp = d2i_PublicKey(EVP_PKEY_RSA, &pubkey_temp, (const unsigned char**)(&pubkey_str), size_of_pubkey_str);

    char* sig_b64 = NULL;
    size_t sig_len_b64 = 0;

    char* data_to_sign = (char*) malloc(100);
    memset(data_to_sign, 0, 100);
    memcpy(data_to_sign, "test", 4);

    sign(priv_key, data_to_sign, 100, &sig_b64, &sig_len_b64);

    bool result_of_verification = verify_hash(data_to_sign, 100, (unsigned char*)sig_b64, sig_len_b64, priv_key);

    printf("result_of_verification(4): %d...\n", result_of_verification);

    result_of_verification = verify_hash(data_to_sign, 100, (unsigned char*)sig_b64, sig_len_b64, pub_key);

    printf("result_of_verification(5): %d...\n", result_of_verification);

    result_of_verification = verify_hash(data_to_sign, 100, (unsigned char*)sig_b64, sig_len_b64, pubkey_temp);

    printf("result_of_verification(6): %d...\n", result_of_verification);

    free(data_to_sign);

    char* hash_of_pubkey;
    size_t size_of_hash_of_pubkey = 0;

    if (!hash_pubkey(pubkey_temp, &hash_of_pubkey, &size_of_hash_of_pubkey)) {
        printf("Java_com_example_filtertestwithnativec_MainActivity_print_1hash_1of_1pubkey: hash of pubkey: {%s}\n", hash_of_pubkey);
    } else {
        printf("Java_com_example_filtertestwithnativec_MainActivity_print_1hash_1of_1pubkey: cannot get hash of pubkey...\n");
        return 1;
    }
//
//    free(hash_of_pubkey);
//    EVP_PKEY_free(pubkey_temp);

    return 0;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_filtertestwithnativec_MainActivity_get_1hash_1of_1pubkey(
        JNIEnv* env,
        jobject /* this */) {

    char* hash_of_pubkey;
    size_t size_of_hash_of_pubkey = 0;

    if (!hash_pubkey(pub_key, &hash_of_pubkey, &size_of_hash_of_pubkey)) {
        printf("Java_com_example_filtertestwithnativec_MainActivity_get_1hash_1of_1pubkey: hash of pubkey: {%s}\n", hash_of_pubkey);
    } else {
        printf("Java_com_example_filtertestwithnativec_MainActivity_get_1hash_1of_1pubkey: cannot get hash of pubkey...\n");
        return ((*env).NewStringUTF(nullptr));
    }

    jstring str_to_ret = ((*env).NewStringUTF(hash_of_pubkey));

    free(hash_of_pubkey);

    return str_to_ret;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_filtertestwithnativec_MainActivity_sign_1video_1and_1metadata(
        JNIEnv* env,
        jobject /* this */,
        jbyteArray video_jbarr, jstring metadata_jstr) {

    const int len_of_video_jbarr = env->GetArrayLength(video_jbarr);
    const char* video_data = (char*) env->GetByteArrayElements(video_jbarr, (jboolean *)0);

    const int len_of_metadata = env->GetStringLength(metadata_jstr);
    const char* metadata_data = env->GetStringUTFChars(metadata_jstr, (jboolean *)0);

    printf("[native-lib: sign_video_and_metadata]: the length of video_data is: %d, the length of metadata_data is: %d\n", len_of_video_jbarr, len_of_metadata);
    printf("[native-lib: sign_video_and_metadata]: the metadata_data we get is: {%s}\n", metadata_data);

    char* sig_b64 = NULL;
    size_t sig_len_b64 = 0;

    size_t size_of_tmp_data_holder_for_signing = len_of_video_jbarr * sizeof(uint8_t) + len_of_metadata * sizeof(uint8_t);
    char* tmp_data_holder_for_signing = (char*) malloc(size_of_tmp_data_holder_for_signing);
    memcpy(tmp_data_holder_for_signing, video_data, len_of_video_jbarr);
    memcpy(tmp_data_holder_for_signing + len_of_video_jbarr, metadata_data, len_of_metadata);

    sign(priv_key, tmp_data_holder_for_signing, size_of_tmp_data_holder_for_signing, &sig_b64, &sig_len_b64);

    free(tmp_data_holder_for_signing);

    return ((*env).NewStringUTF(sig_b64));
}