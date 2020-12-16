/*
Color class for easy color space manipulations between RGB, XYZ and HSL
*/

typedef struct pixel {
    unsigned char r = 0;
    unsigned char g = 0;
    unsigned char b = 0;
} pixel;

class Color
{
public:
	unsigned char data[3]; /*RGB*/
	// pixel* pixels_data;

	/*Current color space*/
	//enum ColorType { RGB, XYZ, HSV };
	//ColorType ColorSpace;

	/*Constructors*/
	Color(unsigned char a, unsigned char b, unsigned char c);
	Color();

	/*Switch to any color space*/
	//void SwitchTo(ColorType type);

	/*Direct switch between color spaces
	(You need to be sure in what space your in but it
	can be faster by avoiding the checking in SwitchTo function)
	*/
//	void XYZtoRGB();
	//void RGBtoXYZ();
	static float* HSVtoRGB(float* HSV);
	float* RGBtoHSV();

	/*Outputs current color temperature(in any color space)*/
	//float getTemperature();

private:
	float min(float a, float b);
	float max(float a, float b);
	
};