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

void Unlock_device(){
   tft.fillScreen(0x059a);
   tft.fillRect(10, 120, 300, 20, 0xe73c);

   tft.setTextColor(0xe73c, 0x059a);
   tft.setTextSize(4);
   tft.setCursor(89,40);
   tft.print("MIDBAR");
   
   tft.setTextColor(0x2126, 0xe73c);  
   tft.setTextSize(1);
   tft.setCursor(15,127);
   tft.print("Enter the Master Password...");

   tft.fillRect(0, 210, 320, 240, 0xe73c);
   tft.setTextColor(0x3186, 0xe73c);
   tft.setTextSize(2);
   tft.setCursor(18,218);
   tft.print("Password Length:");
   tft.setCursor(210,218);
   tft.print("99 chars"); 
}

void Derived(){
    tft.setTextSize(2);
    tft.fillScreen(0x059a);
    tft.setTextColor(0xe73c, 0x059a);
    tft.setCursor(0,10);
    tft.println("      Device unlocked");
    tft.setCursor(0,30);
    tft.println("       successfully!");
    tft.setCursor(5,100);
    tft.print("Verification number is ");
    tft.print("255");
    //tft.print(ct2.b[14]);
    tft.setCursor(5,200);
    tft.print("Press any key to return to");
    tft.setCursor(5,220);
    tft.print("the main menu.");
}

void setup() {
   tft.begin(); 
   tft.setRotation(1);
   Derived();
}
void loop(){
  
}
