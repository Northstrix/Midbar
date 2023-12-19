/*
Midbar
Distributed under the MIT License
© Copyright Maxim Bortnikov 2023
For more information please visit
https://sourceforge.net/projects/midbar/
https://github.com/Northstrix/Midbar
Required libraries:
https://github.com/zhouyangchao/AES
https://github.com/peterferrie/serpent
https://github.com/ddokkaebi/Blowfish
https://github.com/Northstrix/DES_and_3DES_Library_for_MCUs
https://github.com/ulwanski/sha512
https://github.com/Bodmer/TFT_eSPI
https://github.com/intrbiz/arduino-crypto
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/techpaul/PS2KeyMap
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/adafruit/Adafruit-ST7735-Library
https://github.com/Chris--A/Keypad
*/
#include "SPI.h"
#include "Adafruit_GFX.h"
#include "Adafruit_ILI9341.h"

#define TFT_CS         PB4                  
#define TFT_DC         PA15                
#define TFT_RST        PB3  

Adafruit_ILI9341 tft = Adafruit_ILI9341(TFT_CS, TFT_DC, TFT_RST);

const uint16_t pattern PROGMEM [80][80] = {
{65535,65535,65535,65535,65535,65535,50975,1085,1053,50975,65535,61375,32254,1085,1053,1053,7325,40574,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,15613,15613,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,48862,13565,1053,1053,1085,23966,57215,65535,50975,1085,1053,50975,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,50975,1053,5245,53055,42654,9405,1053,1053,3165,28126,59295,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,1021,1021,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,38494,7293,1053,1053,5245,36414,48895,1085,1053,50975,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,53055,23934,40574,17725,1053,1053,1053,19773,53055,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,59295,26046,3133,1053,1085,40574,1085,1053,50975,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,57215,28094,3165,1053,1053,11453,42654,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,50975,17693,3133,40574,1085,1053,50975,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,63455,38494,7325,1053,1053,5213,34334,61375,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,21854,989,1085,1053,1053,1053,1053,1085,989,21854,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65503,42654,44734,1085,1085,42654,34334,61375,65535,65535,65535,65535},
{65535,65535,65535,48895,13565,1053,1053,1085,23934,55135,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,50975,1085,1085,40574,1085,9405,42654,65535,65535,65535},
{65535,55135,23934,1085,1053,1053,13565,40574,28094,53055,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,50975,1085,1085,40574,3165,1053,1053,19773,53055,65535},
{55135,19773,1053,1053,7325,38494,53055,9373,1053,50975,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,50975,1085,1053,48895,44734,9405,1053,1053,3165,30174},
{9373,36414,34334,28126,59295,65535,50975,1053,1053,50975,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,50975,1085,1053,50975,65535,61375,32254,5213,1053,1053},
{1053,1053,17693,50975,65535,65535,50975,1085,1053,50975,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,21854,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,21854,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,50975,1085,1053,50975,65535,65535,55103,42654,21854,1085},
{11485,1053,1053,3133,26046,59295,53055,1085,1053,50975,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,50975,1085,1053,50975,61343,30174,3165,3165,28126,40574},
{63455,34334,5245,1053,1053,7325,26014,1085,1053,50975,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,50975,1085,1085,26014,9373,1053,1053,3165,32254,63455},
{65535,65535,57215,23934,1085,1053,1053,1053,1053,50975,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,21822,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,21822,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,50975,1085,1053,1053,1053,1085,21854,55135,65535,65535},
{65535,65535,65535,65535,48895,13565,1053,1053,1053,50975,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,50975,1085,1053,1053,13533,46814,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,63455,38494,7293,1053,50975,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,21854,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,21854,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,50975,1053,7293,36414,63455,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,59295,28094,53023,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,53055,26014,57215,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,21854,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,21854,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,21854,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,21854,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,13533,38494,7325,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,7325,38494,13533,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,21854,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,13565,65535,57215,28094,3133,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,3165,28094,57215,65535,15613,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,21854,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,13565,63455,65535,65535,50975,17694,1053,1053,1053,1053,1053,1053,1053,1053,17726,50975,65535,65535,63455,15613,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,21854,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,13565,63455,65535,65535,65535,63455,40574,9405,1053,1053,1053,1053,9405,42655,63455,65535,65535,65535,63455,15613,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,21854,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,13565,63455,63455,38494,57215,65535,65535,59295,30174,3165,3133,32286,59295,65535,65535,57215,38494,63455,63455,15613,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,13565,63455,63455,13565,7293,38494,63423,65535,65535,53055,23934,34366,61375,61375,36414,5245,13533,63455,63455,15613,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,63455,21854,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,13565,63455,63455,15613,1053,1053,13565,46815,65535,65535,63455,42655,21886,11485,1053,1053,13565,63455,63455,15613,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,21854,63455,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,13565,63455,65503,15613,1053,7293,34366,32254,28094,55135,65535,65535,59295,32254,5213,1053,13565,63455,63455,15613,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,13565,65535,57215,11485,26046,57215,65535,65535,46815,9405,34334,61375,65535,65535,55135,21854,15613,63455,63455,15613,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,11485,36446,23934,48895,65535,65535,63455,42654,9405,1053,1053,11485,44735,65503,65535,61375,23934,63455,63455,15613,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,9405,40574,63455,65535,65535,50975,17726,1053,1053,1053,1053,1053,1085,21854,55135,63455,23966,63455,63455,15613,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535},
{65535,65535,65535,63455,21854,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,3165,30206,59295,65535,65535,57215,28094,3133,1053,1053,1053,1053,1053,1053,1053,1053,5213,30174,21886,63455,65503,21854,21886,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,21854,63455,65535,65535,65535},
{65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,21854,53055,65535,65535,61375,38494,7325,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,13565,63455,63455,23966,61375,48895,15613,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535},
{65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,11485,44735,63455,65535,65535,46815,23934,38526,13565,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,13565,63455,63455,23966,61375,65535,63455,38494,7325,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535},
{63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,5245,34366,61375,65535,65535,55135,21886,11453,57215,65535,15613,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,13565,63455,63455,15646,28126,59295,65535,65535,57215,28094,3133,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455},
{15613,1021,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,23934,57215,65535,65535,63455,32286,5213,1053,13565,63455,63455,15613,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,13565,63455,63455,15613,1053,9373,38526,63455,65535,65535,50975,17726,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,1021,15613},
{15613,1021,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,17694,50975,65535,65535,63455,40574,9373,1053,13565,63455,63455,15613,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,13565,63455,63455,15613,1053,5213,32254,63455,65535,65535,57215,23966,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,1021,15613},
{63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,3133,26046,57215,65535,65535,59295,28126,15646,63455,63455,15613,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,13565,65535,59263,11485,21886,55135,65535,65535,61375,36414,7293,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455},
{65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,7325,38494,63423,65535,63455,23934,63455,63455,15613,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,13533,40574,23934,46815,65535,65535,65503,44767,13533,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535},
{65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,15613,48895,61375,23966,63455,63455,15613,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,7325,36446,61375,65535,65535,53055,21854,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535},
{65535,65535,65535,63455,21854,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,21886,19806,63455,63455,21886,30174,5213,1053,1053,1053,1053,1053,1053,1053,1053,3133,26046,57215,65535,65535,59295,32254,5213,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,21854,63455,65535,65535,65535},
{65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,13565,63455,63455,23966,63455,55135,21854,1085,1053,1053,1053,1053,1053,17694,50975,65535,65535,63455,40574,9405,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,13565,63455,63455,23934,61375,65535,65503,44767,13533,1053,1053,9405,40574,63455,65535,65535,50975,23966,36414,11485,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,13565,63455,63455,15646,21854,55135,65535,65535,61375,34366,9405,44735,65535,65535,57215,26046,11485,55135,65535,15613,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,13565,63455,63455,15613,1053,5213,32254,59295,65535,65535,55135,28094,30206,36414,7325,1053,13565,63455,63455,15613,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,63455,21854,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,13565,63455,63455,15613,1053,1053,11485,21886,42655,63455,65535,65535,46815,13565,1053,1053,13565,63455,63455,15613,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,21854,63455,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,13565,63455,63455,13565,5245,36414,61375,61375,34366,23934,53055,65535,65535,63423,38494,7293,13533,63455,63455,15613,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,13565,63455,63455,38494,55167,65535,65535,61343,34334,3133,3165,30174,59295,65535,65535,57215,38494,63455,63455,15613,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,21854,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,13565,63455,65535,65535,65535,63455,42655,11453,1053,1053,1053,1053,9373,40574,63455,65535,65535,65535,63455,15613,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,21854,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,13565,63455,65535,65535,50975,17726,1053,1053,1053,1053,1053,1053,1053,1053,17694,50975,65535,65535,63455,15613,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,21854,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,13565,65535,59263,28126,3165,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,3133,26046,57215,65535,15613,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,21854,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,13533,38494,7325,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,7325,36446,13533,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,21854,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,21854,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,21854,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,21854,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,65535,59263,26046,53023,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,53055,26046,59263,65535,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,63455,36414,7293,1053,50975,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,21854,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,21854,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,50975,1053,7293,38494,63455,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,46814,13533,1053,1053,1085,50975,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,50975,1085,1053,1053,13565,48895,65535,65535,65535,65535},
{65535,65535,55135,21886,1085,1053,1053,1053,1085,50975,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,21854,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,21854,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,50975,1085,1053,1053,1053,1085,23934,57215,65535,65535},
{63455,32254,5213,1053,1053,7325,26014,1085,1053,50975,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,50975,1085,1085,26014,7325,1053,1053,5245,34334,63455},
{40574,30174,3165,3165,28094,59295,53055,1085,1085,50975,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,50975,1085,1053,50975,59295,28094,3133,1053,1053,11485},
{1085,21854,42622,53055,65535,65535,50975,1085,1085,50975,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,21854,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,21854,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,50975,1085,1053,50975,65535,65535,50975,17693,1053,1053},
{1053,1053,5213,32254,61375,65535,50975,1085,1085,50975,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,50975,1085,1053,50975,65535,59295,30174,32254,36414,9373},
{30174,3165,1053,1053,9405,44702,50975,1085,1085,50975,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,50975,1053,7325,53055,38494,7325,1053,1053,17693,55135},
{65535,53055,19773,1053,1053,3133,40574,1085,1053,50975,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,53055,28094,40574,15613,1053,1053,1085,23934,55135,65535},
{65535,65535,65535,42654,11453,1085,40574,1085,1053,50975,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1053,1053,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,55135,23934,1085,1053,1053,13565,46815,65535,65535,65535},
{65535,65535,65535,65535,61375,34334,42654,1085,1053,42654,42654,65503,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,21854,989,1085,1053,1053,1053,1053,1085,989,21854,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,61375,34334,5245,1053,1053,7293,38494,63455,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,50975,1085,1053,38494,3165,15645,50975,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1053,1053,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,44734,11453,1053,1053,3133,26014,57215,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,50975,1085,1053,40574,3133,1053,1085,26014,59263,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,989,1085,1085,989,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,53055,19773,1053,1053,1053,17693,40574,23966,53023,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,50975,1085,1085,48895,36414,5245,1053,1053,7293,38494,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,19774,1021,1021,19774,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,59295,30174,3165,1053,1053,9405,42654,55103,7293,1053,50975,65535,65535,65535,65535,65535,65535},
{65535,65535,65535,65535,65535,65535,50975,1085,1053,50975,65535,57215,26014,1085,1053,1053,13565,46815,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,63455,15613,15613,63455,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,65535,40574,7325,1053,1053,1085,32254,61375,65535,50975,1085,1053,50975,65535,65535,65535,65535,65535,65535}
};

void setup() {
  tft.begin();
  tft.fillScreen(0x0000);
  tft.setRotation(1);
  for (int n = 0; n < 240; n += 80) { // Columns
    for (int m = 0; m < 320; m += 80) { // Rows
      for (int i = 0; i < 80; i++) {
        for (int j = 0; j < 80; j++) {
          tft.drawPixel(i + m, j + n, pattern[i][j]);
        }
      }
    }
  }
}

void loop() {

}
