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
//https://thesolaruniverse.wordpress.com/2021/05/02/wiring-an-ili9341-spi-tft-display-with-esp8266-based-microcontroller-boards-nodemcu-and-wemos-d1-mini/

// pins: TFT SPI ILI9341 to ESP8266 NodeMCU
// VCC       ------------     VCC  - note- wemos - 5V
// GND       ------------     GND 
// CS        ------------     D2
// RST       ------------     D3
// D/C       ------------     D4
// MOSI      ------------     D7  
// SCK       ------------     D5       
// BL        ------------     VCC - wnote - emos 5V

#include <Adafruit_GFX.h>                                                    // include Adafruit graphics library
#include <Adafruit_ILI9341.h>                                                // include Adafruit ILI9341 TFT library
#define TFT_CS    D2                                                         // TFT CS  pin is connected to NodeMCU pin D2
#define TFT_RST   D3                                                         // TFT RST pin is connected to NodeMCU pin D3
#define TFT_DC    D4                                                         // TFT DC  pin is connected to NodeMCU pin D4
                                                                             // SCK (CLK) ---> NodeMCU pin D5 (GPIO14)
                                                                             // MOSI(DIN) ---> NodeMCU pin D7 (GPIO13)

Adafruit_ILI9341 tft = Adafruit_ILI9341(TFT_CS, TFT_DC, TFT_RST);

void show_main_menu(){
   tft.fillScreen(0x12ea);
   clear_right_side();
   tft.setTextColor(0xe73c, 0x12ea);
   tft.setTextSize(2);
   tft.setCursor(26,20);
   tft.print("Login");
   tft.setCursor(26,40);
   tft.print("Credit Card");
   tft.setCursor(26,60);
   tft.print("Note");
   tft.setCursor(26,80);
   tft.print("Phone number");
   tft.setCursor(26,100);
   tft.print("Encryption");
   tft.setCursor(26,120);
   tft.print("SQLite3");
   tft.setCursor(26,140);
   tft.print("SHA-512");
   tft.setCursor(26,160);
   tft.print("File system");
   show_state();
}

void show_state(){
   tft.fillRect(0, 210, 320, 240, 0xe73c);
   tft.setTextColor(0x3186, 0xe73c);
   tft.setTextSize(2);
   tft.setCursor(18,218);
   tft.print("SPIFFS:OK AES:256 Key:"); 
}

void last_pressed_key(){
   tft.setCursor(280,218);
   tft.print("7F");
}

void clear_right_side(){
   tft.fillRect(188, 0, 320, 210, 0x3186);
}

void disp_login_menu(){
   tft.setTextColor(0xe73c, 0x3186);
   tft.setTextSize(2);
   tft.setCursor(196, 20);
   tft.print("1.Add");
   tft.setCursor(196, 40);
   tft.print("2.Modify"); 
   tft.setCursor(196, 60);
   tft.print("3.Remove"); 
   tft.setCursor(196, 80);
   tft.print("4.View"); 
   tft.setCursor(196, 100);
   tft.print("5.Show all"); 
 
}

void setup() {
   tft.begin(); 
   tft.setRotation(1);
   show_main_menu();
   show_state();
   disp_login_menu();
}
void loop(){
  
}
