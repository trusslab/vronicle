// #ifndef _RAWBASE_H_
// #define _RAWBASE_H_

typedef struct pixel {
    unsigned char r = 0;
    unsigned char g = 0;
    unsigned char b = 0;
} pixel;

unsigned char truncate(int value)
{
    if(value < 0) return 0;
    if(value > 255) return 255;

    return value;
}

unsigned char truncate(float value)
{
    if(value < 0.0) return 0;
    if(value > 255.0) return 255;

    return value;
}

pixel* unsigned_chars_to_pixels(unsigned char* uchars, int num_of_pixels){
    // This will allocate new memory and return it (pixels)
    // Return NULL on error
    if(uchars == NULL){
        return NULL;
    }
    pixel* results = (pixel*)malloc(sizeof(pixel) * num_of_pixels);
    memcpy(results, uchars, num_of_pixels * 3);
    return results;
}

unsigned char* pixels_to_unsigned_chars(pixel* pixels, int num_of_pixels){
    // This will allocate new memory and return it (pixels)
    // Return NULL on error
    if(pixels == NULL){
        return NULL;
    }
    unsigned char* results = (unsigned char*)malloc(sizeof(unsigned char) * num_of_pixels * 3);
    memcpy(results, pixels, num_of_pixels * 3);
    return results;
}

// #endif /* !_RAWBASE_H_ */