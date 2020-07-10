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

pixel* jsamples_to_pixels(JSAMPLE* jsamples, int num_of_pixels){
    // This will allocate new memory and return it (pixels)
    // Return NULL on error
    if(jsamples == NULL){
        return NULL;
    }
    pixel* results = (pixel*)malloc(sizeof(pixel) * num_of_pixels);
    memcpy(results, jsamples, num_of_pixels * 3);
    return results;
}

JSAMPLE* pixels_to_jsamples(pixel* pixels, int num_of_pixels){
    // This will allocate new memory and return it (pixels)
    // Return NULL on error
    if(pixels == NULL){
        return NULL;
    }
    JSAMPLE* results = (JSAMPLE*)malloc(sizeof(JSAMPLE) * num_of_pixels * 3);
    memcpy(results, pixels, num_of_pixels * 3);
    return results;
}