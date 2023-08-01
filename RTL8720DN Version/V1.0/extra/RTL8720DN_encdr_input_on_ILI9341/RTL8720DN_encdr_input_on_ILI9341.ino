/*
Midbar
Distributed under the MIT License
© Copyright Maxim Bortnikov 2023
For more information please visit
https://sourceforge.net/projects/midbar/
https://osdn.net/projects/midbar/
https://github.com/Northstrix/Midbar
Required libraries:
https://github.com/zhouyangchao/AES
https://github.com/ddokkaebi/Blowfish
https://github.com/intrbiz/arduino-crypto
https://github.com/GyverLibs/EncButton
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/techpaul/PS2KeyMap
*/
#include "SPI.h"
#include "AmebaILI9341.h"
#include <Wire.h>

// For all supported boards (AMB21/AMB22, AMB23, BW16/BW16-TypeC, AW-CU488_ThingPlus), 
// Select 2 GPIO pins connect to TFT_RESET and TFT_DC. And default SPI_SS/SPI1_SS connect to TFT_CS.
#define TFT_RESET       6
#define TFT_DC          2
#define TFT_CS          9
#define SPI_BUS         SPI

AmebaILI9341 tft = AmebaILI9341(TFT_CS, TFT_DC, TFT_RESET, SPI_BUS);

#define ILI9341_SPI_FREQUENCY 20000000

String keyboard_input;
int curr_key;
byte i2c_data;
const uint16_t current_inact_clr = 0x051b;
bool finish_input;
bool act;
bool rec_d;

void receiveEvent(int howMany) {
    howMany = howMany;              // clear warning msg
    /*
    while(1 < Wire.available()) {   // loop through all but the last
        char c = Wire.read();         // receive byte as a character
        Serial.print(c);              // print the character
    }
    
    int x = Wire.read();            // receive byte as an integer
    Serial.println(x);              // print the integer
    */
    i2c_data = Wire.read();
    rec_d = true;
}

void set_stuff_for_input(String blue_inscr) {
  curr_key = 65;
  tft.fillScreen(0x0000);
  tft.setFontSize(2);
  tft.setForeground(0xffff);
  tft.setCursor(2, 0);
  tft.print("Char'");
  tft.setCursor(74, 0);
  tft.print("'");
  disp();
  tft.setCursor(0, 24);
  tft.setFontSize(2);
  tft.setForeground(current_inact_clr);
  tft.print(blue_inscr);
  tft.fillRectangle(312, 0, 8, 240, current_inact_clr);
  tft.setForeground(0x07e0);
  tft.setCursor(216, 0);
  tft.print("ASCII:");
}

void check_bounds_and_change_char() {
  if (curr_key < 32)
    curr_key = 126;

  if (curr_key > 126)
    curr_key = 32;
  curr_key = keyboard_input.charAt(keyboard_input.length() - 1);
}

void disp() {
  //gfx->fillScreen(0x0000);
  tft.setFontSize(2);
  tft.setForeground(0xffff);
  tft.fillRectangle(62, 0, 10, 16, 0x0000);
  tft.setCursor(62, 0);
  tft.print(char(curr_key));
  tft.fillRectangle(288, 0, 22, 14, 0x0000);
  tft.setCursor(288, 0);
  String hexstr;
  if (curr_key < 16)
    hexstr += 0;
  hexstr += String(curr_key, HEX);
  hexstr.toUpperCase();
  tft.setForeground(0x07e0);
  tft.print(hexstr);
  tft.setForeground(0xffff);
  tft.setFontSize(2);
  tft.setCursor(0, 48);
  tft.print(keyboard_input);
}

void disp_stars() {
  //gfx->fillScreen(0x0000);
  tft.setFontSize(2);
  tft.setForeground(0xffff);
  tft.fillRectangle(62, 0, 10, 16, 0x0000);
  tft.setCursor(62, 0);
  tft.print(char(curr_key));
  tft.fillRectangle(288, 0, 22, 14, 0x0000);
  tft.setCursor(288, 0);
  String hexstr;
  if (curr_key < 16)
    hexstr += 0;
  hexstr += String(curr_key, HEX);
  hexstr.toUpperCase();
  tft.setForeground(0x07e0);
  tft.print(hexstr);
  int plnt = keyboard_input.length();
  String stars = "";
  for (int i = 0; i < plnt; i++) {
    stars += "*";
  }
  tft.setForeground(0xffff);
  tft.setFontSize(2);
  tft.setCursor(0, 48);
  tft.print(stars);
}

void encdr_and_keyb_input() {
  finish_input = false;
  rec_d = false;
  while (finish_input == false) {
    if (rec_d == true) {
      rec_d = false;

      if (i2c_data > 31 && i2c_data < 127) {
        curr_key = i2c_data;
        keyboard_input += char(curr_key);
        //Serial.println(keyboard_input);
        disp();
      }

      if (i2c_data == 27) {
        act = false;
        finish_input = true;
      }

      if (i2c_data == 13) {
        finish_input = true;
      }

      if (i2c_data == 130) {
        curr_key++;
        disp();
        if (curr_key < 32)
          curr_key = 126;

        if (curr_key > 126)
          curr_key = 32;
      }

      if (i2c_data == 129) {
        curr_key--;
        disp();
        if (curr_key < 32)
          curr_key = 126;

        if (curr_key > 126)
          curr_key = 32;
      }

      if (i2c_data == 131 || i2c_data == 133) {
        keyboard_input += char(curr_key);
        //Serial.println(keyboard_input);
        disp();
      }

      if (i2c_data == 132 || i2c_data == 8) {
        if (keyboard_input.length() > 0)
          keyboard_input.remove(keyboard_input.length() - 1, 1);
        //Serial.println(keyboard_input);
        tft.fillRectangle(0, 48, 312, 192, 0x0000);
        //Serial.println(keyboard_input);
        disp();
      }
      //Serial.println(i2c_data);
    }
    delayMicroseconds(400);
  }
}

void star_encdr_and_keyb_input() {
  finish_input = false;
  rec_d = false;
  while (finish_input == false) {
    if (rec_d == true) {
      rec_d = false;

      if (i2c_data > 31 && i2c_data < 127) {
        curr_key = i2c_data;
        keyboard_input += char(curr_key);
        //Serial.println(keyboard_input);
        disp_stars();
      }

      if (i2c_data == 27) {
        act = false;
        finish_input = true;
      }

      if (i2c_data == 13) {
        finish_input = true;
      }

      if (i2c_data == 130) {
        curr_key++;
        disp_stars();
        if (curr_key < 32)
          curr_key = 126;

        if (curr_key > 126)
          curr_key = 32;
      }

      if (i2c_data == 129) {
        curr_key--;
        disp_stars();
        if (curr_key < 32)
          curr_key = 126;

        if (curr_key > 126)
          curr_key = 32;
      }

      if (i2c_data == 131 || i2c_data == 133) {
        keyboard_input += char(curr_key);
        //Serial.println(keyboard_input);
        disp_stars();
      }

      if (i2c_data == 132 || i2c_data == 8) {
        if (keyboard_input.length() > 0)
          keyboard_input.remove(keyboard_input.length() - 1, 1);
        //Serial.println(keyboard_input);
        tft.fillRectangle(0, 48, 312, 192, 0x0000);
        //Serial.println(keyboard_input);
        disp_stars();
      }
    }
    delayMicroseconds(400);
  }
}

void setup() {
  tft.begin();
  SPI_BUS.setDefaultFrequency(ILI9341_SPI_FREQUENCY);
  tft.fillScreen(0x0000);
  tft.setRotation(1);
  Wire.begin(13);                // join i2c bus with address #13
  Wire.onReceive(receiveEvent); // register event
  Serial.begin(115200);         // start serial for output
  pinMode(3, OUTPUT);
  digitalWrite(3, LOW);
}

void loop() {
  act = true;
  //clear_variables();
  keyboard_input = "";
  tft.fillScreen(0x0000);
  tft.setForeground(0xffff);
  tft.setCursor(0, 20);
  tft.setFontSize(1);
  set_stuff_for_input("Enter string:");
  encdr_and_keyb_input();
  if (act == true) {
    Serial.println("Continue");
    Serial.println(keyboard_input);
    tft.fillScreen(0x0000);
    tft.setForeground(0xffff);
    tft.setCursor(0, 0);
    tft.setFontSize(2);
    tft.print("Contnue with \"");
    tft.print(keyboard_input);
    tft.print("\"");
    delay(2500);
  }
  else{
    Serial.println("Cancel");
    Serial.println(keyboard_input);
    tft.fillScreen(0x0000);
    tft.setForeground(0xffff);
    tft.setCursor(0, 0);
    tft.setFontSize(2);
    tft.print("Cancel (input) \"");
    tft.print(keyboard_input);
    tft.print("\"");
    delay(2500);
  }
}
