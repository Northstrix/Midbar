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
https://github.com/peterferrie/serpent
https://github.com/ddokkaebi/Blowfish
https://github.com/Northstrix/DES_and_3DES_Library_for_MCUs
https://github.com/ulwanski/sha512
https://github.com/adafruit/Adafruit_ILI9341
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/intrbiz/arduino-crypto
https://github.com/GyverLibs/EncButton
*/
#include "USBHost_t36.h"
#define SHOW_KEYBOARD_DATA

#include <Adafruit_GFX.h>                                                   // include Adafruit graphics library
#include <Adafruit_ILI9341.h>                                               // include Adafruit ILI9341 TFT library
#define TFT_CS    39                                                        // TFT CS  pin is connected to Teensy pin 39
#define TFT_RST   40                                                        // TFT RST pin is connected to Teensy pin 40
#define TFT_DC    41                                                        // TFT DC  pin is connected to Teensy pin 41
                                                                            // SCK (CLK) ---> Teensy pin 13
                                                                            // MOSI(DIN) ---> Teensy pin 11
#include <EncButton2.h>

Adafruit_ILI9341 tft = Adafruit_ILI9341(TFT_CS, TFT_DC, TFT_RST);

String keyboard_input;
int curr_key;
int prsd_key;
const uint16_t current_inact_clr = 0x051b;
bool finish_input;
bool act;
bool usb_keyb_inp;

EncButton2 < EB_ENC > enc0(INPUT, 14, 15);
EncButton2 < EB_BTN > encoder_button(INPUT, 16);
EncButton2 < EB_BTN > a_button(INPUT, 17);
EncButton2 < EB_BTN > b_button(INPUT, 18);

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
  tft.setCursor(0, 24);
  tft.setTextSize(2);
  tft.setTextColor(current_inact_clr);
  tft.print(blue_inscr);
  tft.fillRect(312, 0, 8, 240, current_inact_clr);
  tft.setTextColor(0x07e0);
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
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  tft.fillRect(62, 0, 10, 16, 0x0000);
  tft.setCursor(62, 0);
  tft.print(char(curr_key));
  tft.fillRect(288, 0, 22, 14, 0x0000);
  tft.setCursor(288, 0);
  String hexstr;
  if (curr_key < 16)
    hexstr += 0;
  hexstr += String(curr_key, HEX);
  hexstr.toUpperCase();
  tft.setTextColor(0x07e0);
  tft.print(hexstr);
  tft.setTextColor(0xffff);
  tft.setTextSize(2);
  tft.setCursor(0, 48);
  tft.print(keyboard_input);
}

void disp_stars() {
  //gfx->fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  tft.fillRect(62, 0, 10, 16, 0x0000);
  tft.setCursor(62, 0);
  tft.print(char(curr_key));
  tft.fillRect(288, 0, 22, 14, 0x0000);
  tft.setCursor(288, 0);
  String hexstr;
  if (curr_key < 16)
    hexstr += 0;
  hexstr += String(curr_key, HEX);
  hexstr.toUpperCase();
  tft.setTextColor(0x07e0);
  tft.print(hexstr);
  int plnt = keyboard_input.length();
  String stars = "";
  for (int i = 0; i < plnt; i++) {
    stars += "*";
  }
  tft.setTextColor(0xffff);
  tft.setTextSize(2);
  tft.setCursor(0, 48);
  tft.print(stars);
}

void encdr_and_keyb_input() {
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
        tft.fillRect(0, 48, 312, 192, 0x0000);
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
        tft.fillRect(0, 48, 312, 192, 0x0000);
        //Serial.println(keyboard_input);
        disp();
      }
      //Serial.println(prsd_key);
    }

    enc0.tick();
    if (enc0.left()) {
      curr_key--;
      disp();
    }
    if (enc0.right()) {
      curr_key++;
      disp();
    }

    if (curr_key < 32)
      curr_key = 126;

    if (curr_key > 126)
      curr_key = 32;

    if (enc0.turn()) {
      //Serial.println(char(curr_key));
      disp();
    }
    delayMicroseconds(400);

    a_button.tick();
    if (a_button.press()) {
      keyboard_input += char(curr_key);
      //Serial.println(keyboard_input);
      disp();
    }
    delayMicroseconds(400);

    b_button.tick();
    if (b_button.press()) {
      if (keyboard_input.length() > 0)
        keyboard_input.remove(keyboard_input.length() - 1, 1);
      //Serial.println(keyboard_input);
      tft.fillRect(0, 48, 312, 192, 0x0000);
      //Serial.println(keyboard_input);
      disp();
    }

    delayMicroseconds(400);
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      //Serial.println(keyboard_input);
      finish_input = true;
    }
    if (encoder_button.hasClicks(5)) {
      //Serial.println(keyboard_input);
      act = false;
      finish_input = true;
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
        tft.fillRect(0, 48, 312, 192, 0x0000);
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
        tft.fillRect(0, 48, 312, 192, 0x0000);
        //Serial.println(keyboard_input);
        disp_stars();
      }
    }

    enc0.tick();
    if (enc0.left()) {
      curr_key--;
      disp_stars();
    }
    if (enc0.right()) {
      curr_key++;
      disp_stars();
    }

    if (curr_key < 32)
      curr_key = 126;

    if (curr_key > 126)
      curr_key = 32;

    if (enc0.turn()) {
      //Serial.println(char(curr_key));
      disp_stars();
    }
    delayMicroseconds(400);

    a_button.tick();
    if (a_button.press()) {
      keyboard_input += char(curr_key);
      //Serial.println(keyboard_input);
      disp_stars();
    }
    delayMicroseconds(400);

    b_button.tick();
    if (b_button.press()) {
      if (keyboard_input.length() > 0)
        keyboard_input.remove(keyboard_input.length() - 1, 1);
      //Serial.println(keyboard_input);
      tft.fillRect(0, 48, 312, 192, 0x0000);
      //Serial.println(keyboard_input);
      disp_stars();
    }

    delayMicroseconds(400);
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      //Serial.println(keyboard_input);
      finish_input = true;
    }
    if (encoder_button.hasClicks(5)) {
      //Serial.println(keyboard_input);
      act = false;
      finish_input = true;
    }
    delayMicroseconds(400);
  }
}

void setup() {
  tft.begin();
  tft.fillScreen(0x0000);
  tft.setRotation(1);
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
