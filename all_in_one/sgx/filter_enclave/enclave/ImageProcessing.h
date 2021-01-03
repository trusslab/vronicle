#include <iostream>
#include <stdio.h>
#include <fstream>
#include <string>
#include <chrono>
#include <future>
#include <map>
#include "cmath";
#include <iostream>
#include <vector>

#include "RawBase.h"
#include "Color.h"

unsigned char truncate(int value);
unsigned char truncate(float value);
pixel* unsigned_chars_to_pixels(unsigned char* uchars, int num_of_pixels);
unsigned char* pixels_to_unsigned_chars(pixel* pixels, int num_of_pixels);

// C++ Wraper
#ifdef __cplusplus
extern "C" {
#endif

using namespace std;

class ImageProcessing 
{
public :
	/*<-----------FILE SECTION------------->*/

	/*Check if file exists*/
	static bool fileExists(const std::string& name);

	/*Decode png data from file*/
	// static std::vector<unsigned char> decodeImage(const char* filename, unsigned int &w, unsigned int &h);

	/*Save PNG file using data*/
	// static void encodeImage(const char* filename, std::vector<unsigned char>& image, unsigned width, unsigned height);

	/*<-----------EDITING SECTION------------->*/
	/*Edit Image*/
	static void EditImage(pixel* input_frame, pixel* output_frame, int frame_width, int frame_height);

	/*Convert vector<unsigned char> to vector<Color>*/
	static void DecodePixels(Color out[], vector<unsigned char>& inputImagePtr, int imageSize, int speedUpAmout);
	
	/*Convert pixel* to vector<Color>*/
	static void DecodePixels(Color out[], pixel* inputImagePtr, int imageSize, int speedUpAmout);

	/*Sort pixels by brigthness using look up table where index = R+G+B*/
	static void SortPixels(vector<vector<Color*>>& outLookupTable, int(&outColCount)[766], Color imageCols[], int imageSize, int speedUpAmout);

	/*Find average white color using brightest pixels, using HSV->RGB , RGB->HSV conversions*/
	static void FindWhiteColor(float* outWhiteColor, vector<vector<Color*>>& sortedColorsLookupTable, int imageSize, int speedUpAmout, int& outWhiteLimit);

	/*Apply changes to image*/
	static void ApplyChanges(pixel* inImgPtr, pixel* outImgPtr, Color imageCols[], float* whiteRef, int imageSize);
};

#ifdef __cplusplus
}
#endif  /* #ifdef __cplusplus */