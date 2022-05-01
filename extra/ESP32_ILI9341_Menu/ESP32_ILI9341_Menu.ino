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
void disp_cur_pos(){
  tft.setTextColor(0xe73c, 0x12ea);
  tft.setTextSize(2);
  if (cur_pos == 0){
    tft.setCursor(5,20);
    tft.print("*");
    tft.setCursor(5,40);
    tft.print(" ");
    tft.setCursor(5,60);
    tft.print(" ");
    tft.setCursor(5,80);
    tft.print(" ");
    tft.setCursor(5,100);
    tft.print(" ");
    tft.setCursor(5,120);
    tft.print(" ");
    tft.setCursor(5,140);
    tft.print(" ");
    tft.setCursor(5,160);
  }
  if (cur_pos == 1){
    tft.setCursor(5,4);
    tft.print(" ");
    tft.setCursor(5,14);
    tft.print("*");
    tft.setCursor(5,24);
    tft.print(" ");
    tft.setCursor(5,34);
    tft.print(" ");
    tft.setCursor(5,44);
    tft.print(" ");
    tft.setCursor(5,54);
    tft.print(" ");
    tft.setCursor(5,64);
    tft.print(" ");
    tft.setCursor(5,74);
    tft.print(" ");
    tft.setCursor(5,84);
    tft.print(" ");
    tft.setCursor(5,94);
    tft.print(" ");
  }
  if (cur_pos == 2){
    tft.setCursor(5,4);
    tft.print(" ");
    tft.setCursor(5,14);
    tft.print(" ");
    tft.setCursor(5,24);
    tft.print("*");
    tft.setCursor(5,34);
    tft.print(" ");
    tft.setCursor(5,44);
    tft.print(" ");
    tft.setCursor(5,54);
    tft.print(" ");
    tft.setCursor(5,64);
    tft.print(" ");
    tft.setCursor(5,74);
    tft.print(" ");
    tft.setCursor(5,84);
    tft.print(" ");
    tft.setCursor(5,94);
    tft.print(" ");
  }
  if (cur_pos == 3){
    tft.setCursor(5,4);
    tft.print(" ");
    tft.setCursor(5,14);
    tft.print(" ");
    tft.setCursor(5,24);
    tft.print(" ");
    tft.setCursor(5,34);
    tft.print("*");
    tft.setCursor(5,44);
    tft.print(" ");
    tft.setCursor(5,54);
    tft.print(" ");
    tft.setCursor(5,64);
    tft.print(" ");
    tft.setCursor(5,74);
    tft.print(" ");
    tft.setCursor(5,84);
    tft.print(" ");
    tft.setCursor(5,94);
    tft.print(" ");
  }
  if (cur_pos == 4){
    tft.setCursor(5,4);
    tft.print(" ");
    tft.setCursor(5,14);
    tft.print(" ");
    tft.setCursor(5,24);
    tft.print(" ");
    tft.setCursor(5,34);
    tft.print(" ");
    tft.setCursor(5,44);
    tft.print("*");
    tft.setCursor(5,54);
    tft.print(" ");
    tft.setCursor(5,64);
    tft.print(" ");
    tft.setCursor(5,74);
    tft.print(" ");
    tft.setCursor(5,84);
    tft.print(" ");
    tft.setCursor(5,94);
    tft.print(" ");
  }
  if (cur_pos == 5){
    tft.setCursor(5,4);
    tft.print(" ");
    tft.setCursor(5,14);
    tft.print(" ");
    tft.setCursor(5,24);
    tft.print(" ");
    tft.setCursor(5,34);
    tft.print(" ");
    tft.setCursor(5,44);
    tft.print(" ");
    tft.setCursor(5,54);
    tft.print("*");
    tft.setCursor(5,64);
    tft.print(" ");
    tft.setCursor(5,74);
    tft.print(" ");
    tft.setCursor(5,84);
    tft.print(" ");
    tft.setCursor(5,94);
    tft.print(" ");
  }
  if (cur_pos == 6){
    tft.setCursor(5,4);
    tft.print(" ");
    tft.setCursor(5,14);
    tft.print(" ");
    tft.setCursor(5,24);
    tft.print(" ");
    tft.setCursor(5,34);
    tft.print(" ");
    tft.setCursor(5,44);
    tft.print(" ");
    tft.setCursor(5,54);
    tft.print(" ");
    tft.setCursor(5,64);
    tft.print("*");
    tft.setCursor(5,74);
    tft.print(" ");
    tft.setCursor(5,84);
    tft.print(" ");
    tft.setCursor(5,94);
    tft.print(" ");
  }
  if (cur_pos == 7){
    tft.setCursor(5,4);
    tft.print(" ");
    tft.setCursor(5,14);
    tft.print(" ");
    tft.setCursor(5,24);
    tft.print(" ");
    tft.setCursor(5,34);
    tft.print(" ");
    tft.setCursor(5,44);
    tft.print(" ");
    tft.setCursor(5,54);
    tft.print(" ");
    tft.setCursor(5,64);
    tft.print(" ");
    tft.setCursor(5,74);
    tft.print("*");
    tft.setCursor(5,84);
    tft.print(" ");
    tft.setCursor(5,94);
    tft.print(" ");
  }
  if (cur_pos == 8){
    tft.setCursor(5,4);
    tft.print(" ");
    tft.setCursor(5,14);
    tft.print(" ");
    tft.setCursor(5,24);
    tft.print(" ");
    tft.setCursor(5,34);
    tft.print(" ");
    tft.setCursor(5,44);
    tft.print(" ");
    tft.setCursor(5,54);
    tft.print(" ");
    tft.setCursor(5,64);
    tft.print(" ");
    tft.setCursor(5,74);
    tft.print(" ");
    tft.setCursor(5,84);
    tft.print("*");
    tft.setCursor(5,94);
    tft.print(" ");
  }
  if (cur_pos == 9){
    tft.setCursor(5,4);
    tft.print(" ");
    tft.setCursor(5,14);
    tft.print(" ");
    tft.setCursor(5,24);
    tft.print(" ");
    tft.setCursor(5,34);
    tft.print(" ");
    tft.setCursor(5,44);
    tft.print(" ");
    tft.setCursor(5,54);
    tft.print(" ");
    tft.setCursor(5,64);
    tft.print(" ");
    tft.setCursor(5,74);
    tft.print(" ");
    tft.setCursor(5,84);
    tft.print(" ");
    tft.setCursor(5,94);
    tft.print("*");
  }
}

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
   tft.print("File");
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

void disp_login_cred_card_note_phone_menu(){
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

void disp_encr_menu(){
   tft.setTextColor(0xe73c, 0x3186);
   tft.setTextSize(1);
   tft.setCursor(196, 20);
   tft.print("1.Encrypt input from");
   tft.setCursor(196, 30);
   tft.print("keyboard with AES +"); 
   tft.setCursor(196, 40);
   tft.print("Serpent + AES in"); 
   tft.setCursor(196, 50);
   tft.print("counter mode"); 
   tft.setCursor(196, 65);
   tft.print("2.Encrypt input from");
   tft.setCursor(196, 75);
   tft.print("the Serial Monitor"); 
   tft.setCursor(196, 85);
   tft.print("with AES + Serpent +"); 
   tft.setCursor(196, 95);
   tft.print("AES in counter mode");
   tft.setCursor(196, 110);
   tft.print("3.Decrypt with AES +"); 
   tft.setCursor(196, 120);
   tft.print("Serpent + AES in"); 
   tft.setCursor(196, 130);
   tft.print("counter mode");
   tft.setCursor(196, 145);
   tft.print("4.Encrypt with");
   tft.setCursor(196, 155);
   tft.print("Serpent");
   tft.setCursor(196, 170);
   tft.print("5.Decrypt with");
   tft.setCursor(196, 180);
   tft.print("Serpent"); 
}

void disp_sqlite_menu(){
   tft.setTextColor(0xe73c, 0x3186);
   tft.setTextSize(1);
   tft.setCursor(196, 20);
   tft.print("1.Execute SQL");
   tft.setCursor(196, 30);
   tft.print("statement from the"); 
   tft.setCursor(196, 40);
   tft.print("Serial Monitor"); 
   tft.setCursor(196, 55);
   tft.print("2.Execute SQL");
   tft.setCursor(196, 65);
   tft.print("statement from"); 
   tft.setCursor(196, 75);
   tft.print("keyboard"); 
}

void disp_hash_menu(){
   tft.setTextColor(0xe73c, 0x3186);
   tft.setTextSize(1);
   tft.setCursor(196, 20);
   tft.print("1.Take the input");
   tft.setCursor(196, 30);
   tft.print("from keyboard and"); 
   tft.setCursor(196, 40);
   tft.print("hash it using");
   tft.setCursor(196, 50);
   tft.print("SHA-512"); 
   tft.setCursor(196, 65);
   tft.print("2.Take the input");
   tft.setCursor(196, 75);
   tft.print("from the Serial"); 
   tft.setCursor(196, 85);
   tft.print("Monitor and hash it");
   tft.setCursor(196, 95);
   tft.print("using SHA-512"); 
}

void disp_fs_menu(){
   tft.setTextColor(0xe73c, 0x3186);
   tft.setTextSize(2);
   tft.setCursor(196, 20);
   tft.print("1.Create");
   tft.setCursor(196, 40);
   tft.print("2.Remove"); 
   tft.setCursor(196, 60);
   tft.print("3.View"); 
   tft.setCursor(196, 80);
   tft.print("4.List all"); 
}

void setup() {
   tft.begin(); 
   tft.setRotation(1);
   show_main_menu();
   show_state();
   disp_fs_menu();
}
void loop(){
  
}
