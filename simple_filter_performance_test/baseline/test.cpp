#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bits/stdc++.h> 
#include <sys/stat.h> 
#include <sys/types.h>
#include <time.h>

#include <time.h> /* for time() and ctime() */

typedef struct pixel {
    unsigned char r = 0;
    unsigned char g = 0;
    unsigned char b = 0;
} pixel;

unsigned char truncate(float value)
{
    if(value < 0.0) return 0;
    if(value > 255.0) return 255;

    return value;
}

#include "SampleFilters.h"

using namespace std;

// #include <chrono> 
using namespace std::chrono;

int main(){
    int width = 1280;
    int height = 720;

    pixel* test_input_frame = (pixel*)malloc(width * height * 3);
    pixel* test_output_frame = (pixel*)malloc(width * height * 3);

    auto start = high_resolution_clock::now();

    blur((pixel*)test_input_frame, test_output_frame, width, width * height, 7);
    
    auto end = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(end - start);
    cout << duration.count() << endl; 

    free(test_input_frame);
    free(test_output_frame);

    return 0;
}