/*
Project Midbar
Distributed under the MIT License
© Copyright Maxim Bortnikov 2022
For more information please visit
https://github.com/Northstrix/Midbar
Required libraries:
https://github.com/zhouyangchao/AES
https://github.com/peterferrie/serpent
https://github.com/ulwanski/sha512
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_ILI9341
https://github.com/GyverLibs/GyverBus
https://github.com/PaulStoffregen/PS2Keyboard
https://github.com/siara-cc/esp32_arduino_sqlite3_lib
*/

#include <Adafruit_GFX.h>                                                   // include Adafruit graphics library
#include <Adafruit_ILI9341.h>                                               // include Adafruit ILI9341 TFT library
#define TFT_CS    15                                                        // TFT CS  pin is connected to ESP32 pin D15
#define TFT_RST   4                                                         // TFT RST pin is connected to ESP32 pin D4
#define TFT_DC    2                                                         // TFT DC  pin is connected to ESP32 pin D2
                                                                            // SCK (CLK) ---> ESP32 pin D18
                                                                            // MOSI(DIN) ---> ESP32 pin D23

Adafruit_ILI9341 tft = Adafruit_ILI9341(TFT_CS, TFT_DC, TFT_RST);
String keyb_inp = ";1234567890-=][poiuytrewqasdfghjkl;'/.,mnbvcxz";
void keyb_input(){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter the text to encrypt:");
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  tft.fillRect(0, 210, 320, 240, 0xe73c);
  tft.setTextColor(0x3186, 0xe73c);
  tft.setTextSize(2);
  tft.setCursor(18,218);
  tft.print("Length:");
  int inpl = keyb_inp.length();
  tft.setCursor(100,218);
  tft.print("    ");
  tft.setCursor(100,218);
  tft.print(inpl);
}

void setup() {
   tft.begin(); 
   tft.setRotation(1);
   keyb_input();
}
void loop(){
  
}
