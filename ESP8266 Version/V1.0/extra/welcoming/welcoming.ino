/*
Midbar
Distributed under the MIT License
© Copyright Maxim Bortnikov 2022
For more information please visit
https://sourceforge.net/projects/midbar/
https://osdn.net/projects/midbar/
https://github.com/Northstrix/Midbar
Required libraries:
https://github.com/zhouyangchao/AES
https://github.com/peterferrie/serpent
https://github.com/ddokkaebi/Blowfish
https://github.com/ulwanski/sha512
https://github.com/adafruit/Adafruit_SSD1306
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/intrbiz/arduino-crypto
https://github.com/Northstrix/DES_and_3DES_Library_for_MCUs
https://github.com/GyverLibs/EncButton
*/
#include <SPI.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include "midbaricon.h"

Adafruit_SSD1306 oled(128, 64, &Wire);

void display_midbar_icon(){
  oled.clearDisplay();
  for (int i = 0; i < 68; i++){
    for (int j = 0; j < 16; j++){
      if (mdbicon[i][j] == false)
        oled.drawPixel(i + 29, j, WHITE); 
    }
  }
  for (int i = 0; i < 12; i++)
    oled.drawPixel(97, 4 + i, WHITE); 
  oled.display();
}

void disp_centered_text(String text, int h) {
  int16_t x1;
  int16_t y1;
  uint16_t width;
  uint16_t height;

  oled.getTextBounds(text, 0, 0, &x1, &y1, &width, &height);
  oled.setCursor((128 - width) / 2, h);
  oled.print(text);
  oled.display();
}

void setup()
{  
  Serial.begin(115200);
  oled.begin(SSD1306_SWITCHCAPVCC, 0x3C);
  display_midbar_icon();
  oled.setTextColor(WHITE);
  oled.setTextSize(2);
  disp_centered_text("Midbar", 20);
  oled.setTextSize(1);
  disp_centered_text("Double-click", 40);
  disp_centered_text("the encoder button", 48);
  disp_centered_text("to continue", 56);
}

void loop()
{
}
