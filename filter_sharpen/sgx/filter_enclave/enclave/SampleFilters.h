pixel* blur(pixel* image_buffer, pixel* output_buffer, int row_length, int total_num_of_pixels, int v){
    // Inspired (not copy) by https://processing.org/examples/blur.html
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
    // Inspired (not copy) by https://ai.stanford.edu/~syyeung/cvweb/tutorial1.html
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

void change_brightness(pixel* image_buffer, pixel* output_buffer, int row_length, int total_num_of_pixels, int target_percentage){
    int column_length = total_num_of_pixels / row_length;   // or height
    for(int y = 0; y < column_length; ++y){
        for(int x = 0; x < row_length; ++x){
            float temp_r = 0.0, temp_g = 0.0, temp_b = 0.0;

            temp_r = image_buffer[y * row_length + x].r * target_percentage;
            temp_g = image_buffer[y * row_length + x].g * target_percentage;
            temp_b = image_buffer[y * row_length + x].b * target_percentage;

            output_buffer[y * row_length + x].r = truncate(temp_r);
            output_buffer[y * row_length + x].g = truncate(temp_g);
            output_buffer[y * row_length + x].b = truncate(temp_b);
        }
    }
}

void change_brightness_r(pixel* image_buffer, pixel* output_buffer, int row_length, int total_num_of_pixels, int target_percentage){
    int column_length = total_num_of_pixels / row_length;   // or height
    for(int y = 0; y < column_length; ++y){
        for(int x = 0; x < row_length; ++x){
            float temp_r = 0.0, temp_g = 0.0, temp_b = 0.0;

            temp_r = image_buffer[y * row_length + x].r * target_percentage;
            temp_g = image_buffer[y * row_length + x].g;
            temp_b = image_buffer[y * row_length + x].b;

            output_buffer[y * row_length + x].r = truncate(temp_r);
            output_buffer[y * row_length + x].g = truncate(temp_g);
            output_buffer[y * row_length + x].b = truncate(temp_b);
        }
    }
}

void change_brightness_g(pixel* image_buffer, pixel* output_buffer, int row_length, int total_num_of_pixels, int target_percentage){
    int column_length = total_num_of_pixels / row_length;   // or height
    for(int y = 0; y < column_length; ++y){
        for(int x = 0; x < row_length; ++x){
            float temp_r = 0.0, temp_g = 0.0, temp_b = 0.0;

            temp_r = image_buffer[y * row_length + x].r;
            temp_g = image_buffer[y * row_length + x].g * target_percentage;
            temp_b = image_buffer[y * row_length + x].b;

            output_buffer[y * row_length + x].r = truncate(temp_r);
            output_buffer[y * row_length + x].g = truncate(temp_g);
            output_buffer[y * row_length + x].b = truncate(temp_b);
        }
    }
}

void change_brightness_b(pixel* image_buffer, pixel* output_buffer, int row_length, int total_num_of_pixels, int target_percentage){
    int column_length = total_num_of_pixels / row_length;   // or height
    for(int y = 0; y < column_length; ++y){
        for(int x = 0; x < row_length; ++x){
            float temp_r = 0.0, temp_g = 0.0, temp_b = 0.0;

            temp_r = image_buffer[y * row_length + x].r;
            temp_g = image_buffer[y * row_length + x].g;
            temp_b = image_buffer[y * row_length + x].b * target_percentage;

            output_buffer[y * row_length + x].r = truncate(temp_r);
            output_buffer[y * row_length + x].g = truncate(temp_g);
            output_buffer[y * row_length + x].b = truncate(temp_b);
        }
    }
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
