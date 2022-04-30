//
// Created by lyx98 on 11/12/2020.
//

#ifndef FILTERTESTWITHNATIVEC_RAWBASE_H
#define FILTERTESTWITHNATIVEC_RAWBASE_H

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

#endif //FILTERTESTWITHNATIVEC_RAWBASE_H
