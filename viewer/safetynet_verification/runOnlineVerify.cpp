#include <iostream>
#include <fstream>
#include <stdio.h>
#include <string.h>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "../metadata.h"

#define SIZE_OF_EXEC_CMD 10000

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

std::string exec(const char* cmd) {
    // https://stackoverflow.com/questions/478898/how-do-i-execute-a-command-and-get-the-output-of-the-command-within-c-using-po
    char buffer[128];
    std::string result = "";
    FILE* pipe = popen(cmd, "r");
    if (!pipe) throw std::runtime_error("popen() failed!");
    try {
        while (fgets(buffer, sizeof buffer, pipe) != NULL) {
            result += buffer;
        }
    } catch (...) {
        pclose(pipe);
        throw;
    }
    pclose(pipe);
    return result;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: ./runOnlineVerify <metadata_file>");
        return 1;
    }

    FILE *md_json_file = fopen(argv[1], "r");

    if (!md_json_file) {
        printf("Invalid metadata_file: %s...\n", argv[1]);
        return 1;
    }

    fseek(md_json_file, 0, SEEK_END);
    size_t md_json_size = ftell(md_json_file);
    fseek(md_json_file, 0, SEEK_SET);
    char *md_json = new char[md_json_size];
    fread(md_json, 1, md_json_size, md_json_file);
    fclose(md_json_file);

    metadata *md_to_be_used = json_2_metadata(md_json, md_json_size);
    delete md_json;

    if (!md_to_be_used->is_safetynet_presented) {
        printf("Safetynet is not presented, skipped...");
        return 1;
    }


    char cmd_to_be_execed[SIZE_OF_EXEC_CMD];

    for (int i = 0; i < md_to_be_used->num_of_safetynet_jws; ++i) {
        // unsigned char *actual_safetynet_report;
        // size_t size_of_actual_saefynet_report = 0;
        // Base64Decode(md_to_be_used->safetynet_jws[i], &actual_safetynet_report, &size_of_actual_saefynet_report);
        memset(cmd_to_be_execed, 0, SIZE_OF_EXEC_CMD);
        snprintf(cmd_to_be_execed, SIZE_OF_EXEC_CMD, 
            "gradle runOnlineVerify -PsignedStatement=%s", 
            md_to_be_used->safetynet_jws[i]);
        std::cout << exec(cmd_to_be_execed);
        // printf("The cmd going to be executed is: {%s}\n", cmd_to_be_execed);
        // free(actual_safetynet_report);
    }

    free_metadata(md_to_be_used);

    return 0;
}