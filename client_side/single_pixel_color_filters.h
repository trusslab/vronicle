
JSAMPLE truncate(JSAMPLE value)
{
    if(value < 0) return 0;
    if(value > 255) return 255;

    return value;
}

void change_brightness(JSAMPLE* red, JSAMPLE* green, JSAMPLE* blue, JSAMPLE value){
    *red += value;
    *red = truncate(*red);
    *green += value;
    *green = truncate(*green);
    *blue += value;
    *blue = truncate(*blue);
}