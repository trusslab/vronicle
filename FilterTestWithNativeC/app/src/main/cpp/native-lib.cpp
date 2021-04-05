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

//        printf("[hash_pubkey]: 2");

        while (BIO_read(keybio, buffer, 1024) > 0)
        {
//            buffer[1024] = '\n';
//            printf("[hash_pubkey]: 2.1: {%s}\n", buffer);
//            printf("[hash_pubkey]: 2.1: %d\n", strlen(buffer));
            /* Update Digest operation */
            if(1 != EVP_DigestUpdate(mdctx, buffer, strlen(buffer))) {
                printf("EVP_DigestUpdate error: %ld. \n", ERR_get_error());
                break;
            }
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
        Base64Encode(hash, SHA256_DIGEST_LENGTH, hash_b64, hash_b64_len);

//        printf("[hash_pubkey]: 5");

        ret = 0;
    } while(0);

    BIO_free(keybio);
    EVP_MD_CTX_free(mdctx);
    return ret;
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

    return 0;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_filtertestwithnativec_MainActivity_generate_1metadata(
        JNIEnv* env,
        jobject /* this */,
        int g_w, int g_h, int fps, int num_of_frames) {
//    std::string hello = "Hello from C++";
//    sleep(1);
    char test[15] = "This is a test";
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
    md->total_filters = 1;
    md->filters = (char**)malloc(sizeof(char*) * md->total_filters);
    md->filters_parameters_registry = (int*)malloc(sizeof(int) * md->total_filters);
    md->total_filters_parameters = 1;
    md->filters_parameters = (double*)malloc(sizeof(double) * md->total_filters_parameters);
    md->filters[0] = "blur\0";
    md->filters_parameters_registry[0] = 1;
    md->filters_parameters[0] = 7.0;
    md->total_digests = 0;
    char* json = NULL;
    json = metadata_2_json_without_frame_id(md);
    int len_of_metadata = strlen(json);

//    jcharArray resultToReturn;
    jchar* j_version = (jchar*)calloc(sizeof(jchar), len_of_metadata + 1);
    for(int i=0; i <= len_of_metadata; i++){
        j_version[i] =  (jchar) json[i];
    }
    j_version[len_of_metadata] = '\0';

    jcharArray j_version_array = env->NewCharArray(len_of_metadata + 1);
    env->SetCharArrayRegion(j_version_array, 0, len_of_metadata , j_version);

    return ((*env).NewStringUTF(json));
}