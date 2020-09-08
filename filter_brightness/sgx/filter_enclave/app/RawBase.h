#ifndef _RAWBASE_H_
#define _RAWBASE_H_

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

#endif /* !_RAWBASE_H_ */