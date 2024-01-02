/*
Midbar
Distributed under the MIT License
© Copyright Maxim Bortnikov 2024
For more information please visit
https://sourceforge.net/projects/midbar/
https://github.com/Northstrix/Midbar
Required libraries:
https://github.com/zhouyangchao/AES
https://github.com/peterferrie/serpent
https://github.com/ddokkaebi/Blowfish
https://github.com/Northstrix/DES_and_3DES_Library_for_MCUs
https://github.com/ulwanski/sha512
https://github.com/adafruit/Adafruit-ST7735-Library
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/intrbiz/arduino-crypto
*/
#include "USBHost_t36.h"
#define SHOW_KEYBOARD_DATA

#include <Adafruit_GFX.h>
#include <Adafruit_ST7735.h>
#define TFT_CS1    39                                                        // TFT CS  pin is connected to Teensy pin 39
#define TFT_RST1   40                                                        // TFT RST pin is connected to Teensy pin 40
#define TFT_DC1    41                                                        // TFT DC  pin is connected to Teensy pin 41
                                                                            // SCK (CLK) ---> Teensy pin 13
                                                                            // MOSI(DIN) ---> Teensy pin 11
Adafruit_ST7735 tft = Adafruit_ST7735(TFT_CS1, TFT_DC1, TFT_RST1);

String keyboard_input;
int curr_key;
int prsd_key;
const uint16_t current_inact_clr = 0x051b;
const uint16_t stripe_on_the_right_color = 0xfa40;
bool finish_input;
bool act;
bool usb_keyb_inp;

USBHost myusb;
USBHub hub1(myusb);
KeyboardController keyboard1(myusb);

USBHIDParser hid1(myusb);
USBHIDParser hid2(myusb);
USBHIDParser hid3(myusb);

uint8_t keyboard_modifiers = 0;  // try to keep a reasonable value
#ifdef KEYBOARD_INTERFACE
uint8_t keyboard_last_leds = 0;
#endif

void OnPress(int key) {
  prsd_key = key;
  usb_keyb_inp = true;
  Serial.println(prsd_key);
}

void set_stuff_for_input(String blue_inscr) {
  curr_key = 65;
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  tft.setCursor(2, 0);
  tft.print("Char'");
  tft.setCursor(74, 0);
  tft.print("'");
  disp();
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  tft.setTextColor(current_inact_clr);
  tft.print(blue_inscr);
  tft.fillRect(155, 0, 4, 128, stripe_on_the_right_color);
}

void check_bounds_and_change_char() {
  if (curr_key < 32)
    curr_key = 126;

  if (curr_key > 126)
    curr_key = 32;
  curr_key = keyboard_input.charAt(keyboard_input.length() - 1);
}

void disp() {
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  tft.fillRect(62, 0, 10, 16, 0x0000);
  tft.setCursor(62, 0);
  tft.print(char(curr_key));
  tft.setTextColor(0x07e0);
  String hexstr;
  if (curr_key < 16)
    hexstr += 0;
  hexstr += String(curr_key, HEX);
  hexstr.toUpperCase();
  tft.fillRect(125, 0, 22, 14, 0x0000);
  tft.setCursor(125, 0);
  tft.print(hexstr);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 32);
  tft.print(keyboard_input);
}

void disp_stars() {
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  tft.fillRect(62, 0, 10, 16, 0x0000);
  tft.setCursor(62, 0);
  tft.print(char(curr_key));
  tft.setTextColor(0x07e0);
  String hexstr;
  if (curr_key < 16)
    hexstr += 0;
  hexstr += String(curr_key, HEX);
  hexstr.toUpperCase();
  tft.fillRect(125, 0, 22, 14, 0x0000);
  tft.setCursor(125, 0);
  tft.print(hexstr);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 32);
  int plnt = keyboard_input.length();
  String stars = "";
  for (int i = 0; i < plnt; i++) {
    stars += "*";
  }
  tft.print(stars);
}


void encdr_and_keyb_input() {
  finish_input = false;
  usb_keyb_inp = false;
  while (finish_input == false) {
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;
      if (prsd_key == 127) { // Backspace
        if (keyboard_input.length() > 0)
          keyboard_input.remove(keyboard_input.length() - 1, 1);
        //Serial.println(keyboard_input);
        tft.fillRect(0, 32, 155, 96, 0x0000);
        //Serial.println(keyboard_input);
        disp();
      }

      if (prsd_key > 31 && prsd_key < 127) {
        curr_key = prsd_key;
        keyboard_input += char(curr_key);
        //Serial.println(keyboard_input);
        disp();
      }

      if (prsd_key == 27) {
        act = false;
        finish_input = true;
      }

      if (prsd_key == 10) {
        finish_input = true;
      }

      if (prsd_key == 215) {
        curr_key++;
        disp();
        if (curr_key < 32)
          curr_key = 126;

        if (curr_key > 126)
          curr_key = 32;
      }

      if (prsd_key == 216) {
        curr_key--;
        disp();
        if (curr_key < 32)
          curr_key = 126;

        if (curr_key > 126)
          curr_key = 32;
      }

      if (prsd_key == 218) {
        keyboard_input += char(curr_key);
        //Serial.println(keyboard_input);
        disp();
      }

      if (prsd_key == 217) {
        if (keyboard_input.length() > 0)
          keyboard_input.remove(keyboard_input.length() - 1, 1);
        //Serial.println(keyboard_input);
        tft.fillRect(0, 32, 155, 96, 0x0000);
        //Serial.println(keyboard_input);
        disp();
      }
      
      if (prsd_key == 212) {
        keyboard_input = "";
        //Serial.println(keyboard_input);
        tft.fillRect(0, 32, 155, 96, 0x0000);
        //Serial.println(keyboard_input);
        disp();
      }
      //Serial.println(prsd_key);
    }
    delayMicroseconds(400);
  }
}

void star_encdr_and_keyb_input() {
  finish_input = false;
  usb_keyb_inp = false;
  while (finish_input == false) {
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;
      if (prsd_key == 127) {
        if (keyboard_input.length() > 0)
          keyboard_input.remove(keyboard_input.length() - 1, 1);
        //Serial.println(keyboard_input);
        tft.fillRect(0, 32, 155, 96, 0x0000);
        //Serial.println(keyboard_input);
        disp_stars();
      }

      if (prsd_key > 31 && prsd_key < 127) {
        curr_key = prsd_key;
        keyboard_input += char(curr_key);
        //Serial.println(keyboard_input);
        disp_stars();
      }

      if (prsd_key == 27) {
        act = false;
        finish_input = true;
      }

      if (prsd_key == 10) {
        finish_input = true;
      }

      if (prsd_key == 215) {
        curr_key++;
        disp_stars();
        if (curr_key < 32)
          curr_key = 126;

        if (curr_key > 126)
          curr_key = 32;
      }

      if (prsd_key == 216) {
        curr_key--;
        disp_stars();
        if (curr_key < 32)
          curr_key = 126;

        if (curr_key > 126)
          curr_key = 32;
      }

      if (prsd_key == 218) {
        keyboard_input += char(curr_key);
        //Serial.println(keyboard_input);
        disp_stars();
      }

      if (prsd_key == 217) {
        if (keyboard_input.length() > 0)
          keyboard_input.remove(keyboard_input.length() - 1, 1);
        //Serial.println(keyboard_input);
        tft.fillRect(0, 32, 155, 96, 0x0000);
        //Serial.println(keyboard_input);
        disp_stars();
      }

      if (prsd_key == 212) {
        keyboard_input = "";
        //Serial.println(keyboard_input);
        tft.fillRect(0, 32, 155, 96, 0x0000);
        //Serial.println(keyboard_input);
        disp();
      }
      
    }
    delayMicroseconds(400);
  }
}

void setup() {
  tft.initR(INITR_BLACKTAB);
  tft.setRotation(1);
  tft.fillScreen(0x0000);
  myusb.begin();
  keyboard1.attachPress(OnPress);
  Serial.begin(115200);
  Serial.println("Input Test:");
}

void loop() {
  act = true;
  //clear_variables();
  keyboard_input = "";
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter string:");
  encdr_and_keyb_input();
  if (act == true) {
    Serial.println("Continue");
    Serial.println(keyboard_input);
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.setTextSize(2);
    tft.print("Contnue with \"");
    tft.print(keyboard_input);
    tft.print("\"");
    delay(2500);
  }
  else{
    Serial.println("Cancel");
    Serial.println(keyboard_input);
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.setTextSize(2);
    tft.print("Cancel (input) \"");
    tft.print(keyboard_input);
    tft.print("\"");
    delay(2500);
  }
}
