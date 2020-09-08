
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

pixel* sharpen(pixel* image_buffer, pixel* output_buffer, int row_length, int total_num_of_pixels, int v){
    // Inspired by https://ai.stanford.edu/~syyeung/cvweb/tutorial1.html
    float avg_weight = 1.0 / ((v * v) - 1);
    int pad = v / 2;
    float** kernel = new float*[v];
    for(int i = 0; i < v; ++i){
        kernel[i] = new float[v];
        for(int i2 = 0; i2 < v; ++i2){
            kernel[i][i2] = 0 - avg_weight;
        }
    }
    kernel[pad][pad] = 2.0;
    // printf("avg_weight: %f\n", 0 - avg_weight);
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
