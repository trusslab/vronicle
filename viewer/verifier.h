#pragma once
#include <string>

class Verifier {
public:
    Verifier(const std::string &video_file_name,
             const std::string &sig_file_name,
             const std::string &ias_cert_file_name);
    void verify();
private:
    size_t calcDecodeLength(const char* b64input);
    void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length);
    std::string video_file_name;
    std::string sig_file_name;
    std::string ias_cert_file_name;
};