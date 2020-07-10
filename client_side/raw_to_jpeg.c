// Modified from https://github.com/LuaDist/libjpeg/blob/master/example.c

#include <stdio.h>
#include "jpeglib.h"
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>

JSAMPLE * image_buffer = NULL;	/* Points to large array of R,G,B-order data */
int image_height = 0;	/* Number of rows in image */
int image_width = 0;		/* Number of columns in image */

int read_raw_file(const char* file_name){
    // Return 0 on success, return 1 on failure
    FILE* input_raw_file = fopen(file_name, "r");
    char buff[257]; // Plus one for eof
    int counter_for_image_info = 0; // First two are width and height
    int counter_for_checking_if_all_rgb_values_read_properly = 0;
    char* info;
    while(fgets(buff, 257, input_raw_file) != NULL){
        // printf("buff: %s\n", buff);
        info = strtok(buff, ",");
        while(info != NULL){
            // printf("Info: %d\n", atoi(info));
            if(counter_for_image_info == 0){
                image_width = atoi(info);
                ++counter_for_image_info;
            } else if (counter_for_image_info == 1){
                image_height = atoi(info);
                ++counter_for_image_info;
                printf("The image has width: %d, and height: %d.\n", image_width, image_height);
                image_buffer = (JSAMPLE*)malloc(sizeof(JSAMPLE) * image_width * image_height * 3);
            } else {
                if(counter_for_checking_if_all_rgb_values_read_properly + 10 >= image_width * image_height * 3){
                    // printf("Current counter: %d, current limit: %d.\n", counter_for_checking_if_all_rgb_values_read_properly, image_width * image_height * 3);
                    // printf("Current info: %d\n", atoi(info));
                }
                image_buffer[counter_for_checking_if_all_rgb_values_read_properly++] = atoi(info);
            }
            info = strtok(NULL, ",");
        }
        // printf("Current buff: %s\n", buff);
    }
    if(image_buffer == NULL || image_height == 0 || image_width == 0 || 
        counter_for_checking_if_all_rgb_values_read_properly != image_width * image_height * 3){
            return 1;
        }
    printf("The very first pixel has RGB value: (%d, %d, %d).\n", image_buffer[0], image_buffer[1], image_buffer[2]);
    return 0;
}

GLOBAL(void)
write_JPEG_file (char * filename, int quality)
{
  /* This struct contains the JPEG compression parameters and pointers to
   * working space (which is allocated as needed by the JPEG library).
   * It is possible to have several such structures, representing multiple
   * compression/decompression processes, in existence at once.  We refer
   * to any one struct (and its associated working data) as a "JPEG object".
   */
  struct jpeg_compress_struct cinfo;
  /* This struct represents a JPEG error handler.  It is declared separately
   * because applications often want to supply a specialized error handler
   * (see the second half of this file for an example).  But here we just
   * take the easy way out and use the standard error handler, which will
   * print a message on stderr and call exit() if compression fails.
   * Note that this struct must live as long as the main JPEG parameter
   * struct, to avoid dangling-pointer problems.
   */
  struct jpeg_error_mgr jerr;
  /* More stuff */
  FILE * outfile;		/* target file */
  JSAMPROW row_pointer[1];	/* pointer to JSAMPLE row[s] */
  int row_stride;		/* physical row width in image buffer */

  /* Step 1: allocate and initialize JPEG compression object */

  /* We have to set up the error handler first, in case the initialization
   * step fails.  (Unlikely, but it could happen if you are out of memory.)
   * This routine fills in the contents of struct jerr, and returns jerr's
   * address which we place into the link field in cinfo.
   */
  cinfo.err = jpeg_std_error(&jerr);
  /* Now we can initialize the JPEG compression object. */
  jpeg_create_compress(&cinfo);

  /* Step 2: specify data destination (eg, a file) */
  /* Note: steps 2 and 3 can be done in either order. */

  /* Here we use the library-supplied code to send compressed data to a
   * stdio stream.  You can also write your own code to do something else.
   * VERY IMPORTANT: use "b" option to fopen() if you are on a machine that
   * requires it in order to write binary files.
   */
  if ((outfile = fopen(filename, "wb")) == NULL) {
    fprintf(stderr, "can't open %s\n", filename);
    exit(1);
  }
  jpeg_stdio_dest(&cinfo, outfile);

  /* Step 3: set parameters for compression */

  /* First we supply a description of the input image.
   * Four fields of the cinfo struct must be filled in:
   */
  cinfo.image_width = image_width; 	/* image width and height, in pixels */
  cinfo.image_height = image_height;
  cinfo.input_components = 3;		/* # of color components per pixel */
  cinfo.in_color_space = JCS_RGB; 	/* colorspace of input image */
  /* Now use the library's routine to set default compression parameters.
   * (You must set at least cinfo.in_color_space before calling this,
   * since the defaults depend on the source color space.)
   */
  jpeg_set_defaults(&cinfo);
  /* Now you can set any non-default parameters you wish to.
   * Here we just illustrate the use of quality (quantization table) scaling:
   */
  jpeg_set_quality(&cinfo, quality, TRUE /* limit to baseline-JPEG values */);

  /* Step 4: Start compressor */

  /* TRUE ensures that we will write a complete interchange-JPEG file.
   * Pass TRUE unless you are very sure of what you're doing.
   */
  jpeg_start_compress(&cinfo, TRUE);

  /* Step 5: while (scan lines remain to be written) */
  /*           jpeg_write_scanlines(...); */

  /* Here we use the library's state variable cinfo.next_scanline as the
   * loop counter, so that we don't have to keep track ourselves.
   * To keep things simple, we pass one scanline per call; you can pass
   * more if you wish, though.
   */
  row_stride = image_width * 3;	/* JSAMPLEs per row in image_buffer */

  while (cinfo.next_scanline < cinfo.image_height) {
    /* jpeg_write_scanlines expects an array of pointers to scanlines.
     * Here the array is only one element long, but you could pass
     * more than one scanline at a time if that's more convenient.
     */
    row_pointer[0] = & image_buffer[cinfo.next_scanline * row_stride];
    (void) jpeg_write_scanlines(&cinfo, row_pointer, 1);
  }

  /* Step 6: Finish compression */

  jpeg_finish_compress(&cinfo);
  /* After finish_compress, we can close the output file. */
  fclose(outfile);

  /* Step 7: release JPEG compression object */

  /* This is an important step since it will release a good deal of memory. */
  jpeg_destroy_compress(&cinfo);

  /* And we're done! */
}

int main(int argc, char *argv[]){
    if(argc != 2){
        printf("Usage: [raw_file_name]");
        return 1;
    }

    read_raw_file(argv[1]);
    write_JPEG_file("jpeg_output.jpeg", 100);

    return 0;
}