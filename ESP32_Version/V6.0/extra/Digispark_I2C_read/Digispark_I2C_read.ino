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
#include "DigiKeyboard.h"
#include <TinyWireS.h>

void receiveEvent(uint8_t howMany)
{
  DigiKeyboard.print(char(TinyWireS.receive()));
  TinyWireS_stop_check();
}


void setup()
{
  DigiKeyboard.println("I2C test:");
  TinyWireS.begin(13);
  TinyWireS.onReceive(receiveEvent);
}

void loop()
{
    tws_delay(1);
    //TinyWireS_stop_check();
}
