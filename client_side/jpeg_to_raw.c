// Modified from https://github.com/LuaDist/libjpeg/blob/master/example.c

#include <stdio.h>
#include "jpeglib.h"
#include <setjmp.h>
#include <stdlib.h>

JSAMPLE * output_image_buffer;     // For storing output R-G-B values
int total_num_of_value_written = 0;     // For locating what's the next value to be written

struct my_error_mgr {
  struct jpeg_error_mgr pub;	/* "public" fields */

  jmp_buf setjmp_buffer;	/* for return to caller */
};

typedef struct my_error_mgr * my_error_ptr;

/*
 * Here's the routine that will replace the standard error_exit method:
 */

METHODDEF(void)
my_error_exit (j_common_ptr cinfo)
{
  /* cinfo->err really points to a my_error_mgr struct, so coerce pointer */
  my_error_ptr myerr = (my_error_ptr) cinfo->err;

  /* Always display the message. */
  /* We could postpone this until after returning, if we chose. */
  (*cinfo->err->output_message) (cinfo);

  /* Return control to the setjmp point */
  longjmp(myerr->setjmp_buffer, 1);
}

void write_to_output_image_buffer(JSAMPLE * single_row_rgb_values, int len_of_row){
    for(int i = 0; i < len_of_row; ++i){
        output_image_buffer[total_num_of_value_written++] = single_row_rgb_values[i];
    }
    // printf("Testing RGB value: (%d, %d, %d)\n", output_image_buffer[total_num_of_value_written - len_of_row], 
    //     output_image_buffer[total_num_of_value_written - len_of_row + 1], output_image_buffer[total_num_of_value_written - len_of_row + 2]);

    // printf("Correct RGB value: (%d, %d, %d)\n", single_row_rgb_values[0], single_row_rgb_values[1], single_row_rgb_values[2]);
}

int save_and_free_output_image_buffer(const char* file_name, int width, int height){
    // First check if the number of pixels (RGB values) is correct
    // Return 0 if success, otherwise, return 1
    if(total_num_of_value_written != width * height * 3){
        free(output_image_buffer);
        return 1;
    }

    FILE* output_file = fopen(file_name, "w+");
    fprintf(output_file, "%07d,%07d,", width, height);
    for(int i = 0; i < total_num_of_value_written - 1; ++i){
        fprintf(output_file, "%03d,", output_image_buffer[i]);
    }
    fprintf(output_file, "%03d", output_image_buffer[total_num_of_value_written - 1]);
    fclose(output_file);
    
    free(output_image_buffer);
    return 0;
}

GLOBAL(int)
read_JPEG_file (char * filename, char * newfilename)
{
    printf("Reading jpeg file: %s\n", filename);
    /* This struct contains the JPEG decompression parameters and pointers to
    * working space (which is allocated as needed by the JPEG library).
    */
    struct jpeg_decompress_struct cinfo;
    /* We use our private extension JPEG error handler.
    * Note that this struct must live as long as the main JPEG parameter
    * struct, to avoid dangling-pointer problems.
    */
    struct my_error_mgr jerr;
    /* More stuff */
    FILE * infile;		/* source file */
    JSAMPARRAY buffer;		/* Output row buffer */
    int row_stride;		/* physical row width in output buffer */

    /* In this example we want to open the input file before doing anything else,
    * so that the setjmp() error recovery below can assume the file is open.
    * VERY IMPORTANT: use "b" option to fopen() if you are on a machine that
    * requires it in order to read binary files.
    */

    if ((infile = fopen(filename, "rb")) == NULL) {
        fprintf(stderr, "can't open %s\n", filename);
        return 0;
    }

    /* Step 1: allocate and initialize JPEG decompression object */

    /* We set up the normal JPEG error routines, then override error_exit. */
    cinfo.err = jpeg_std_error(&jerr.pub);
    jerr.pub.error_exit = my_error_exit;
    /* Establish the setjmp return context for my_error_exit to use. */
    if (setjmp(jerr.setjmp_buffer)) {
        /* If we get here, the JPEG code has signaled an error.
        * We need to clean up the JPEG object, close the input file, and return.
        */
        jpeg_destroy_decompress(&cinfo);
        fclose(infile);
        return 0;
    }
    /* Now we can initialize the JPEG decompression object. */
    jpeg_create_decompress(&cinfo);

    /* Step 2: specify data source (eg, a file) */

    jpeg_stdio_src(&cinfo, infile);

    /* Step 3: read file parameters with jpeg_read_header() */

    (void) jpeg_read_header(&cinfo, TRUE);
    /* We can ignore the return value from jpeg_read_header since
    *   (a) suspension is not possible with the stdio data source, and
    *   (b) we passed TRUE to reject a tables-only JPEG file as an error.
    * See libjpeg.txt for more info.
    */

    /* Step 4: set parameters for decompression */

    /* In this example, we don't need to change any of the defaults set by
    * jpeg_read_header(), so we do nothing here.
    */

    /* Step 5: Start decompressor */

    (void) jpeg_start_decompress(&cinfo);
    /* We can ignore the return value since suspension is not possible
    * with the stdio data source.
    */

    /* We may need to do some setup of our own at this point before reading
    * the data.  After jpeg_start_decompress() we have the correct scaled
    * output image dimensions available, as well as the output colormap
    * if we asked for color quantization.
    * In this example, we need to make an output work buffer of the right size.
    */ 
    /* JSAMPLEs per row in output buffer */
    row_stride = cinfo.output_width * cinfo.output_components;
    /* Make a one-row-high sample array that will go away when done with image */
    buffer = (*cinfo.mem->alloc_sarray)
            ((j_common_ptr) &cinfo, JPOOL_IMAGE, row_stride, 1);

    // allocate output_image_buffer
    output_image_buffer = (JSAMPLE*)malloc(sizeof(JSAMPLE) * cinfo.output_height * row_stride);
    // printf("The size of output_image_buffer is: %d\n", cinfo.output_height * row_stride);

    /* Step 6: while (scan lines remain to be read) */
    /*           jpeg_read_scanlines(...); */

    /* Here we use the library's state variable cinfo.output_scanline as the
    * loop counter, so that we don't have to keep track ourselves.
    */
    printf("The height of image is: %d, and the width is: %d.\n", cinfo.output_height, row_stride);
    int max_value = 0;
    int min_value = 255;
    printf("Starting scanline at line: %d.\n", cinfo.output_scanline);
    while (cinfo.output_scanline < cinfo.output_height) {
        /* jpeg_read_scanlines expects an array of pointers to scanlines.
        * Here the array is only one element long, but you could ask for
        * more than one scanline at a time if that's more convenient.
        */
        //int nums_of_lines_read = jpeg_read_scanlines(&cinfo, buffer, 1);
        jpeg_read_scanlines(&cinfo, buffer, 1);
        for(int i = 0; i < row_stride; ++i){
            if(buffer[0][i] > max_value){
                max_value = buffer[0][i];
            }
            if(buffer[0][i] < min_value){
                min_value = buffer[0][i];
            }
        }
        // printf("Number of lines read: %d.", nums_of_lines_read);
        // printf("Testing RGB value: (%d, %d, %d)\n", buffer[0][0], buffer[0][1], buffer[0][2]);
        /* Assume put_scanline_someplace wants a pointer and sample count. */
        write_to_output_image_buffer(buffer[0], row_stride);
    }
    printf("Ending scanline at line: %d.\n", cinfo.output_scanline);
    printf("max_value: %d, min_value: %d.\n", max_value, min_value);

    int result = save_and_free_output_image_buffer(newfilename, row_stride / 3, cinfo.output_height);
    if(result != 0) {
        printf("Error happened when try to save raw, error code: %d\n", result);
        return result;
    }

    /* Step 7: Finish decompression */

    (void) jpeg_finish_decompress(&cinfo);
    /* We can ignore the return value since suspension is not possible
    * with the stdio data source.
    */

    /* Step 8: Release JPEG decompression object */

    /* This is an important step since it will release a good deal of memory. */
    jpeg_destroy_decompress(&cinfo);

    /* After finish_decompress, we can close the input file.
    * Here we postpone it until after no more JPEG errors are possible,
    * so as to simplify the setjmp error logic above.  (Actually, I don't
    * think that jpeg_destroy can do an error exit, but why assume anything...)
    */
    fclose(infile);

    /* At this point you may want to check to see whether any corrupt-data
    * warnings occurred (test whether jerr.pub.num_warnings is nonzero).
    */

    /* And we're done! */
    return 1;
}

int main(int argc, char *argv[]){
    if(argc != 2){
        printf("Usage: [num_of_photos]");
        return 1;
    }

    int num_of_frames = atoi(argv[1]);

    char buf[25];
    char outbuf[25];

    for(int i = 0; i < num_of_frames; ++i){
        snprintf(buf, 25, "./out_raw_jpg/out_%d.jpg", i);
        snprintf(outbuf, 25, "./out_raw/out_raw_%d", i);
        read_JPEG_file(buf, outbuf);
        total_num_of_value_written = 0;
    }

    return 0;
}
