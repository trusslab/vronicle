
pixel* blur(pixel* image_buffer, int row_length, int total_num_of_pixels, int v){
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
    printf("avg_weight: %f\n", avg_weight);
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
            image_buffer[y * row_length + x].r = truncate(temp_r);
            image_buffer[y * row_length + x].g = truncate(temp_g);
            image_buffer[y * row_length + x].b = truncate(temp_b);
        }
    }
    for(int i = 0; i < v; ++i){
        free(kernel[i]);
    }
    free(kernel);
    return image_buffer;
}

pixel* blur_5(pixel* image_buffer, int row_length, int total_num_of_pixels, float v){
    // Inspired by https://processing.org/examples/blur.html
    // This is a 5 x 5 blur
    float kernel[5][5] = {{ v, v, v, v, v }, { v, v, v, v, v }, { v, v, v, v, v }, { v, v, v, v, v }, { v, v, v, v, v }};
    // float kernel[3][3] = {{1, 2, 1}, {2, 4, 2}, {1, 2, 1}};
    int column_length = total_num_of_pixels / row_length;   // or height
    for(int y = 2; y < column_length - 2; ++y){
        for(int x = 2; x < row_length - 2; ++x){
            float temp_r = 0.0, temp_g = 0.0, temp_b = 0.0;
            for(int ky = -2; ky <= 2; ++ky){
                for(int kx = -2; kx <= 2; ++kx){
                    int pos = (y + ky) * row_length + (x + kx);
                    temp_r += kernel[ky+2][kx+2] * image_buffer[pos].r;
                    temp_g += kernel[ky+2][kx+2] * image_buffer[pos].g;
                    temp_b += kernel[ky+2][kx+2] * image_buffer[pos].b;
                }
            }
            image_buffer[y * row_length + x].r = truncate(temp_r);
            image_buffer[y * row_length + x].g = truncate(temp_g);
            image_buffer[y * row_length + x].b = truncate(temp_b);
        }
    }
    return image_buffer;
}

pixel* sharpen_3(pixel* image_buffer, int row_length, int total_num_of_pixels, float v){
    // Inspired by https://ai.stanford.edu/~syyeung/cvweb/tutorial1.html
    // This is a 3 x 3 sharpen
    // float kernel[5][5] = {{ v, v, v, v, v }, { v, v, v, v, v }, { v, v, v, v, v }, { v, v, v, v, v }, { v, v, v, v, v }};
    float kernel[3][3] = {{-1.0 / 8.0, -1.0 / 8.0, -1.0 / 8.0}, {-1.0 / 8.0, 2.0, -1.0 / 8.0}, {-1.0 / 8.0, -1.0 / 8.0, -1.0 / 8.0}};
    int column_length = total_num_of_pixels / row_length;   // or height
    for(int y = 1; y < column_length - 1; ++y){
        for(int x = 1; x < row_length - 1; ++x){
            float temp_r = 0.0, temp_g = 0.0, temp_b = 0.0;
            for(int ky = -1; ky <= 1; ++ky){
                for(int kx = -1; kx <= 1; ++kx){
                    int pos = (y + ky) * row_length + (x + kx);
                    temp_r += kernel[ky+1][kx+1] * image_buffer[pos].r;
                    temp_g += kernel[ky+1][kx+1] * image_buffer[pos].g;
                    temp_b += kernel[ky+1][kx+1] * image_buffer[pos].b;
                }
            }

            /*
            temp_r *= 9.0;
            temp_g *= 9.0;
            temp_b *= 9.0;
            */

            image_buffer[y * row_length + x].r = truncate(temp_r);
            image_buffer[y * row_length + x].g = truncate(temp_g);
            image_buffer[y * row_length + x].b = truncate(temp_b);
        }
    }
    return image_buffer;
}

pixel* sharpen(pixel* image_buffer, int row_length, int total_num_of_pixels, int v){
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
    printf("avg_weight: %f\n", 0 - avg_weight);
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
            image_buffer[y * row_length + x].r = truncate(temp_r);
            image_buffer[y * row_length + x].g = truncate(temp_g);
            image_buffer[y * row_length + x].b = truncate(temp_b);
        }
    }
    for(int i = 0; i < v; ++i){
        free(kernel[i]);
    }
    free(kernel);
    return image_buffer;
}
