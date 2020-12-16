#include "ImageProcessing.h"

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

#pragma warning(disable:4996)

#pragma region File Managing
// /*Check if file exists*/
// bool ImageProcessing::fileExists(const std::string& name) {
// 	if (FILE *file = fopen(name.c_str(), "r")) {
// 		fclose(file);
// 		return true;
// 	}
// 	else {
// 		return false;
// 	}
// }

// /*Decode png data from file*/
// std::vector<unsigned char> ImageProcessing::decodeImage(const char* filename, unsigned int &w, unsigned int &h) {
// 	std::vector<unsigned char> image;
// 	unsigned error = lodepng::decode(image, w, h, filename);
// 	if (error) std::cout << "decoder error " << error << ": " << lodepng_error_text(error) << std::endl;
// 	return image;
// }

// /*Save PNG file using data*/
// void ImageProcessing::encodeImage(const char* filename, std::vector<unsigned char>& image, unsigned width, unsigned height) {
// 	unsigned error = lodepng::encode(filename, image, width, height);
// 	if (error) std::cout << "encoder error " << error << ": " << lodepng_error_text(error) << std::endl;
// }
#pragma endregion


#pragma region ImageEditing
/*Convert vector<unsigned char> to vector<Color>*/
void ImageProcessing::DecodePixels(Color out[], vector<unsigned char>& inputImagePtr, int imageSize, int speedUpAmout)
{
	//auto start = std::chrono::high_resolution_clock::now();

	const int p = 4 * speedUpAmout;
	const int max = (imageSize * 4) - 1;

	for (int i = 0; i <  max;i += p)
		out[i >> 2] = Color(inputImagePtr[i],inputImagePtr[i + 1],inputImagePtr[i + 2]);

	/*Progress bar & time of execution*/
	//auto elapsed_extracting = std::chrono::high_resolution_clock::now() - start;
	//float extractionTime = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed_extracting).count() / 1000.0;

	int ExtractingkBytesProcessed = sizeof(vector<Color*>) + (sizeof(Color) * imageSize / 1000.0);
	// float ExtractingkBytesPerSec = ExtractingkBytesProcessed / extractionTime;

	//std::cout << "[" << extractionTime << "s][" << ExtractingkBytesPerSec << "kB/s] " << "Extracting colors (100%)" << endl;
}

/*Convert pixel to vector<Color>*/
void ImageProcessing::DecodePixels(Color* out, pixel* inputImagePtr, int imageSize, int speedUpAmout)
{
	//auto start = std::chrono::high_resolution_clock::now();

	const int p = speedUpAmout;
	const int max = imageSize - 1;

	int counter = 0;

	for (int i = 0; i <  max;i += p){
		// printf("Reading pixel #: %d, which is: %d\n", i, i >> 2);
		out[i] = Color(inputImagePtr[i].r,inputImagePtr[i].g,inputImagePtr[i].b);
		++counter;
	}
	// printf("Hey we finish decodePixel with counter: %d...\n", counter);

	/*Progress bar & time of execution*/
	//auto elapsed_extracting = std::chrono::high_resolution_clock::now() - start;
	//float extractionTime = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed_extracting).count() / 1000.0;

	// int ExtractingkBytesProcessed = sizeof(vector<Color*>) + (sizeof(Color) * imageSize / 1000.0);
	// float ExtractingkBytesPerSec = ExtractingkBytesProcessed / extractionTime;

	//std::cout << "[" << extractionTime << "s][" << ExtractingkBytesPerSec << "kB/s] " << "Extracting colors (100%)" << endl;
}


void ImageProcessing::SortPixels(vector<vector<Color*>>& outLookupTable, int(&outColCount)[766], Color imageCols[], int imageSize,int speedUpAmout)
{
	//auto start = std::chrono::high_resolution_clock::now(); /*timer*/

	Color col;
	int counter = 0;

	for (int i = 0; i < imageSize; i+=speedUpAmout)
	{
		//printf("1111111111111111\n");
		int index = imageCols[i].data[0] + imageCols[i].data[1] + imageCols[i].data[2];
		//printf("2222222222222222\n");
		//printf("2.5..............%d\n", imageCols[i].data[1]);
		outLookupTable[index];
		outLookupTable[index].push_back(&imageCols[i]);
		//printf("3333333333333333\n");
		outColCount[index]++;
		//printf("4444444444444444\n");
		//printf("Current counter is: %d\n", ++counter);
		//printf("5555555555555555\n");
	}

	/*Progess bar & time of exec*/
	//auto elapsed_sorting = std::chrono::high_resolution_clock::now() - start;
	//float sortingTime = (std::chrono::duration_cast<std::chrono::milliseconds>(elapsed_sorting).count() / 1000.0);

	// int SortingkBytesProcessed = (sizeof(vector<vector<Color*>>) + sizeof(Color*) * imageSize) / 1000.0;
	// float SortingBytesPerSec = SortingkBytesProcessed / sortingTime;

	//std::cout << "[" << sortingTime << "s][" << SortingBytesPerSec << "kB/s] " << "Sorting colors (100%)" << endl;
	/*Progess bar & time of exec end*/
}

void ImageProcessing::FindWhiteColor(float* outWhiteColor, vector<vector<Color*>>& sortedColorsLookupTable, int imageSize,int speedUpAmout,int& outWhiteLimit)
{
	//auto start = std::chrono::high_resolution_clock::now(); /*timer*/

	/*Count of "white" pixels i want to produce white reference pixel -> 0.8%*/
	const int whiteCount = round(0.8 / 100.0*imageSize)*speedUpAmout;
	int currentCount = 0;
	bool whiteLimitContinue = true;

	for (int i = 765; i > -1; i--)
	{
		// printf("FindWhiteColor for loop: %d\n", i);
		if (currentCount < whiteCount)
		{
			int size = sortedColorsLookupTable[i].size();
			// printf("The size is: %d\n", size);
			if (size > 0)
			{
				for (int j = 0; j < size; j++)
				{
					if (currentCount < whiteCount)
					{
						float* HSV = (sortedColorsLookupTable[i][j])->RGBtoHSV();
						// printf("Currently, we have outWhiteColor: %f, %f, %f\n", outWhiteColor[0], outWhiteColor[1], outWhiteColor[2]);
						// printf("Which is going to be plused with: %f, %f, %f\n", HSV[0], HSV[1], HSV[2]);
						outWhiteColor[0] += HSV[0];
						outWhiteColor[1] += HSV[1];
						outWhiteColor[2] += HSV[2];
						delete [] HSV;
						currentCount++;
					}
					else
					{
						break;
					}
				}
			}
		}
	}

	outWhiteColor[0] /= (float)whiteCount;
	outWhiteColor[1] /= (float)whiteCount;
	outWhiteColor[2] /= (float)whiteCount;

	/*Progress bar*/
	
	//auto elapsed_whiteref = std::chrono::high_resolution_clock::now() - start;
	//float whiterefTime = (std::chrono::duration_cast<std::chrono::milliseconds>(elapsed_whiteref).count() / 1000.0);

	//std::cout << "[" << whiterefTime << "s] " << "Calculating Avrg. White color(HSV) (100%)" << endl;

	//outWhiteColor.HSVtoRGB();

	/*Progress bar end*/



}

void ImageProcessing::ApplyChanges(pixel* inImgPtr, pixel* outImgPtr, Color imageCols[], float* whiteRef, int imageSize)
{
	//auto start = std::chrono::high_resolution_clock::now(); /*timer*/

	whiteRef = Color::HSVtoRGB(whiteRef);

	// printf("The whiteRef we get are: %f, %f, %f\n", whiteRef[0], whiteRef[1], whiteRef[2]);

	whiteRef[0] = 1.0 / (whiteRef[0] / 255.0);
	whiteRef[1] = 1.0 / (whiteRef[1] / 255.0);
	whiteRef[2] = 1.0 / (whiteRef[2] / 255.0);

	if (whiteRef[0] > 3)
		whiteRef[0] = 3;
	if (whiteRef[1] > 3)
		whiteRef[1] = 3;
	if (whiteRef[2] > 3)
		whiteRef[2] = 3;

	float _R_ = 1.0*whiteRef[0];
	float _G_ = 1.0*whiteRef[1];
	float _B_ = 1.0*whiteRef[2];

	// printf("The reference RGB you get are: %f, %f, %f\n", _R_, _G_, _B_);

	delete [] whiteRef;

	for (int i = 0; i < imageSize; i++)
	{
		// printf("ApplyChanges for loop: current i is: %d, with original r: %d, g: %d, b: %d\n", i, (outImgPtr)[i].r, (outImgPtr)[i].g, (outImgPtr)[i].b);
		int R = (int)floor(((float)((inImgPtr)[i].r) * _R_)+0.5);
		int G = (int)floor(((float)((inImgPtr)[i].g) * _G_)+0.5);
		int B = (int)floor(((float)((inImgPtr)[i].b) * _B_)+0.5);

		if (R > 255)
			R = 255;
		if (G > 255)
			G = 255;
		if (B > 255)
			B = 255;

		// printf("The new rgb are: r: %d, g: %d, b: %d\n", R, G, B);

		(outImgPtr)[i].r = (char)R;
		(outImgPtr)[i].g = (char)G;
		(outImgPtr)[i].b = (char)B;

		// printf("After applying it, the original rgb are: r: %d, g: %d, b: %d\n", (outImgPtr)[i].r, (outImgPtr)[i].g, (outImgPtr)[i].b);
	}

	/*Progess bar*/
	//auto elapsed_apply = std::chrono::high_resolution_clock::now() - start;
	//float applyTime = (std::chrono::duration_cast<std::chrono::milliseconds>(elapsed_apply).count() / 1000.0);

	//std::cout << "[" << applyTime << "s] " << "Applying changes (100%)" << endl;
	/*Progress bar end*/
}

void  ImageProcessing::EditImage(pixel* input_frame, pixel* output_frame, int frame_width, int frame_height) {

	unsigned int w = frame_width;
	unsigned int h = frame_height;
	// std::vector<unsigned char> image;

	/*Decode image from file*/
	// std::vector<unsigned char> image = ImageProcessing::decodeImage(path.c_str(), w, h);

	//auto start = std::chrono::high_resolution_clock::now(); /*timer*/

															/*Size of image in memory*/
	// float sizeMb = 3.0 * 32.0 * w * h / 1000.0 / 1000.0;
	/*3x times because Color class has 3 floats so it is 96bit per col instead of 32bit , so 3 times more*/

	//cout << "Image decoded from [" << path << "][w:" << w << ";h:" << h << "][" << sizeMb << "MB]\n\n";

	const int imageSize = w * h;

	int speedUp = 2; /*Loss of precision,by skipping pixels*/

					 /*Convert from char to Color class*/
	// Color* imageCols = (Color*)malloc(sizeof(pixel) * (imageSize / speedUp + 1));
	Color* imageCols = new Color[imageSize];
	// Color* imageCols = new Color();
	// imageCols->pixels_data = (pixel*)malloc(sizeof(pixel) * (imageSize / speedUp + 1));
	// imageCols->pixels_data[5].r = 111;
	// imageCols->pixels_data[5].g = 122;
	// imageCols->pixels_data[5].b = 133;
	// printf("Testing if assigning is successful: r: %d; g: %d; b: %d\n", imageCols->pixels_data[5].r, imageCols->pixels_data[5].g, imageCols->pixels_data[5].b);

	// printf("Going to do decodePixels...\n");
	ImageProcessing::DecodePixels(imageCols, input_frame, imageSize, speedUp);

	/*Sort colors using lookup table where the index is R+G+B*/
	vector<vector<Color*>> sortedColorsLookupTable(766); /*Multiple color can have the same sum*/

														 /*Count of occurences for each sum value*/
	int colCount[766];
	memset(colCount, 0, sizeof(colCount));

	// printf("Going to do sortPixels...\n");
	ImageProcessing::SortPixels(sortedColorsLookupTable, colCount, imageCols, imageSize, speedUp);

	/*Image white pixel*/
	int whiteLimitVal = 0;
	float *referenceWhite = new float[3]{ 0,0,0 };
	// printf("Going to do FindWhiteColor...\n");
	ImageProcessing::FindWhiteColor(referenceWhite, sortedColorsLookupTable, imageSize, speedUp, whiteLimitVal);

	//cout << "White limit : " << whiteLimitVal << endl;

	// printf("Going to do ApplyChanges...\n");
	ImageProcessing::ApplyChanges(input_frame, output_frame, imageCols, referenceWhite, imageSize);

	// printf("Going to do delte...\n");

	delete [] imageCols;
	// printf("First delete completed...\n");
	delete [] referenceWhite;

	// printf("The end of EditChanges...\n");

	//auto elapsed = std::chrono::high_resolution_clock::now() - start;
	//long milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();

	//printf("\nTotal time of execution(without decoding/encoding) : ");
	//cout << milliseconds << "ms" << endl;

	//cout << "Saving image...\n";
	// ImageProcessing::encodeImage((path).c_str(), image, w, h);
	//cout << "Image Saved!\n" << endl;
}

#pragma endregion
