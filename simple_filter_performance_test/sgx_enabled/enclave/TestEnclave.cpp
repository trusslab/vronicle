#include <stdio.h>      /* vsnprintf */
#include <stdarg.h>
#include <string.h>

#include <errno.h>
#include <limits.h>

#include "TestEnclave_t.h"

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

void exit (int status) {
    usgx_exit(status);
    abort();
}

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    uprint(buf);
}

#include "SampleFilters.h"

void t_blur(
    void* img_pixels, size_t size_of_img_pixels,
    void* out_pixels
)
{
    // Init variables
    int width = 1280;
    int height = 720;

    // Process image
    pixel* processed_pixels;
	size_t processed_pixels_size = sizeof(pixel) * height * width;
    processed_pixels = (pixel*)malloc(processed_pixels_size);
	blur((pixel*)img_pixels, processed_pixels, width, width * height, 7);

    // Copy processed image to output buffer
    memset(out_pixels, 0, processed_pixels_size);
	memcpy(out_pixels, processed_pixels, processed_pixels_size);

    // Free stuff
    free(processed_pixels);
}