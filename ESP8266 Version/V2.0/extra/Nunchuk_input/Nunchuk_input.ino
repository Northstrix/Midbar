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
https://github.com/dmadison/NintendoExtensionCtrl
https://github.com/adafruit/Adafruit-ST7735-Library
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/intrbiz/arduino-crypto
https://github.com/marvinroger/ESP8266TrueRandom
*/
#include <Adafruit_GFX.h>
#include <Adafruit_ST7735.h>
#include <NintendoExtensionCtrl.h>
#define TFT_CS1         D3
#define TFT_RST1        D6
#define TFT_DC1         D4
Adafruit_ST7735 tft = Adafruit_ST7735(TFT_CS1, TFT_DC1, TFT_RST1);

Nunchuk wii_nunchuk;

bool pressed_c;
bool pressed_z;
bool held_left;
bool held_up;
bool held_right;
bool held_down;
byte threshold = 16;
int wait_till_fast_scroll = 550;
int delay_for_fast_scroll = 90;
bool right_fast_scroll;
bool do_right_fast_scroll;
bool left_fast_scroll;
bool do_left_fast_scroll;
String wii_nunch_input;
int curr_key;
const uint16_t current_inact_clr = 0x051b;
const uint16_t stripe_on_the_right_color = 0xfa40;
bool finish_input;
bool act;
bool nunchuk_av;

bool stick_up_to_add_char = true;
bool c_functions_as_enter = true;

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
  tft.print(wii_nunch_input);
}

void nunchuk_input() {
  finish_input = false;
  boolean success;
  nunchuk_av = true;
  right_fast_scroll = false;
  left_fast_scroll = false;
  while (finish_input == false) {
    success = wii_nunchuk.update(); // Get new data from the controller
    if (!success) { // Ruh roh
      if (nunchuk_av == true){
        tft.fillRect(125, 0, 22, 14, 0x0000);
        tft.setCursor(125, 0);
        tft.setTextColor(0xf800);
        tft.setTextSize(2);
        tft.print("NC");
        nunchuk_av = false;
      }
      delay(48);
      success = wii_nunchuk.update(); // Get new data from the controller
      if (success) {
        disp();
      }
      tft.setTextSize(1);
    } if (success) {
      nunchuk_av = true;
      if (wii_nunchuk.buttonC() == true) {
        if (pressed_c == false) {
          if (c_functions_as_enter == true){
            finish_input = true;
          }
          else{
            act = false;
            finish_input = true;
          }
        }
        pressed_c = true;
      } else {
        pressed_c = false;
      }

      if (wii_nunchuk.buttonZ() == true) {
        if (pressed_z == false) {
          if (c_functions_as_enter == true){
            act = false;
            finish_input = true;
          }
          else{
            finish_input = true;
          }
        }
        pressed_z = true;
      } else {
        pressed_z = false;
      }

      byte XAxis = wii_nunchuk.joyX();
      byte YAxis = wii_nunchuk.joyY();

      if (XAxis > (255 - threshold)) {
        if (held_right == true) {
          if (right_fast_scroll == false){
            do_right_fast_scroll = true;
            for (int i = 0; i < wait_till_fast_scroll; i++){
              success = wii_nunchuk.update();
              delay(1);
              if (wii_nunchuk.joyX() < (255 - threshold)){
                do_right_fast_scroll = false;
                break;
              }
            }
            if (do_right_fast_scroll == true)
              right_fast_scroll = true;
          }
          if (right_fast_scroll == true) { // Fast Scroll
            curr_key++;
            if (curr_key < 32)
              curr_key = 126;

            if (curr_key > 126)
              curr_key = 32;
            disp();
            delay(delay_for_fast_scroll);
          }
        }
        if (held_right == false) {
          curr_key++;
          if (curr_key < 32)
            curr_key = 126;

          if (curr_key > 126)
            curr_key = 32;
          disp();
        }
        held_right = true;
      } else {
        right_fast_scroll = false;
        held_right = false;
      }

      if (XAxis < threshold) {
        if (held_left == true) {
          if (left_fast_scroll == false){
            do_left_fast_scroll = true;
            for (int i = 0; i < wait_till_fast_scroll; i++){
              success = wii_nunchuk.update();
              delay(1);
              if (wii_nunchuk.joyX() > threshold){
                do_left_fast_scroll = false;
                break;
              }
            }
            if (do_left_fast_scroll == true)
              left_fast_scroll = true;
          }
          if (left_fast_scroll == true) { // Fast Scroll
            curr_key--;
            if (curr_key < 32)
              curr_key = 126;

            if (curr_key > 126)
              curr_key = 32;
            disp();
            delay(delay_for_fast_scroll);
          }
        }
        if (held_left == false) {
          curr_key--;
          if (curr_key < 32)
            curr_key = 126;

          if (curr_key > 126)
            curr_key = 32;
          disp();
        }
        held_left = true;
      } else {
        left_fast_scroll = false;
        held_left = false;
      }

      if (YAxis > (255 - threshold)) {
        if (held_up == false) {
          if (stick_up_to_add_char == true){
            wii_nunch_input += char(curr_key);
            disp();
          }
          else{
            if (wii_nunch_input.length() > 0)
              wii_nunch_input.remove(wii_nunch_input.length() - 1, 1);
            //Serial.println(wii_nunch_input);
            tft.fillRect(0, 32, 155, 96, 0x0000);
            //Serial.println(wii_nunch_input);
            disp();
          }
        }
        held_up = true;
      } else {
        held_up = false;
      }

      if (YAxis < threshold) {
        if (held_down == false) {
          if (stick_up_to_add_char == true){
            if (wii_nunch_input.length() > 0)
              wii_nunch_input.remove(wii_nunch_input.length() - 1, 1);
            //Serial.println(wii_nunch_input);
            tft.fillRect(0, 32, 155, 96, 0x0000);
            //Serial.println(wii_nunch_input);
            disp();
          }
          else{
            wii_nunch_input += char(curr_key);
            disp();
          }
        }
        held_down = true;
      } else {
        held_down = false;
      }
    }
    delay(1);
  }
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
  int plnt = wii_nunch_input.length();
  String stars = "";
  for (int i = 0; i < plnt; i++) {
    stars += "*";
  }
  tft.print(stars);
}

void starred_nunchuk_input() {
  finish_input = false;
  boolean success;
  nunchuk_av = true;
  right_fast_scroll = false;
  left_fast_scroll = false;
  while (finish_input == false) {
    success = wii_nunchuk.update(); // Get new data from the controller
    if (!success) { // Ruh roh
      if (nunchuk_av == true){
        tft.fillRect(125, 0, 22, 14, 0x0000);
        tft.setCursor(125, 0);
        tft.setTextColor(0xf800);
        tft.setTextSize(2);
        tft.print("NC");
        nunchuk_av = false;
      }
      delay(48);
      success = wii_nunchuk.update(); // Get new data from the controller
      if (success) {
        disp_stars();
      }
      tft.setTextSize(1);
    } if (success) {
      nunchuk_av = true;
      if (wii_nunchuk.buttonC() == true) {
        if (pressed_c == false) {
          if (c_functions_as_enter == true){
            finish_input = true;
          }
          else{
            act = false;
            finish_input = true;
          }
        }
        pressed_c = true;
      } else {
        pressed_c = false;
      }

      if (wii_nunchuk.buttonZ() == true) {
        if (pressed_z == false) {
          if (c_functions_as_enter == true){
            act = false;
            finish_input = true;
          }
          else{
            finish_input = true;
          }
        }
        pressed_z = true;
      } else {
        pressed_z = false;
      }

      byte XAxis = wii_nunchuk.joyX();
      byte YAxis = wii_nunchuk.joyY();

      if (XAxis > (255 - threshold)) {
        if (held_right == true) {
          if (right_fast_scroll == false){
            do_right_fast_scroll = true;
            for (int i = 0; i < wait_till_fast_scroll; i++){
              success = wii_nunchuk.update();
              delay(1);
              if (wii_nunchuk.joyX() < (255 - threshold)){
                do_right_fast_scroll = false;
                break;
              }
            }
            if (do_right_fast_scroll == true)
              right_fast_scroll = true;
          }
          if (right_fast_scroll == true) { // Fast Scroll
            curr_key++;
            if (curr_key < 32)
              curr_key = 126;

            if (curr_key > 126)
              curr_key = 32;
            disp_stars();
            delay(delay_for_fast_scroll);
          }
        }
        if (held_right == false) {
          curr_key++;
          if (curr_key < 32)
            curr_key = 126;

          if (curr_key > 126)
            curr_key = 32;
          disp_stars();
        }
        held_right = true;
      } else {
        right_fast_scroll = false;
        held_right = false;
      }

      if (XAxis < threshold) {
        if (held_left == true) {
          if (left_fast_scroll == false){
            do_left_fast_scroll = true;
            for (int i = 0; i < wait_till_fast_scroll; i++){
              success = wii_nunchuk.update();
              delay(1);
              if (wii_nunchuk.joyX() > threshold){
                do_left_fast_scroll = false;
                break;
              }
            }
            if (do_left_fast_scroll == true)
              left_fast_scroll = true;
          }
          if (left_fast_scroll == true) { // Fast Scroll
            curr_key--;
            if (curr_key < 32)
              curr_key = 126;

            if (curr_key > 126)
              curr_key = 32;
            disp_stars();
            delay(delay_for_fast_scroll);
          }
        }
        if (held_left == false) {
          curr_key--;
          if (curr_key < 32)
            curr_key = 126;

          if (curr_key > 126)
            curr_key = 32;
          disp_stars();
        }
        held_left = true;
      } else {
        left_fast_scroll = false;
        held_left = false;
      }

      if (YAxis > (255 - threshold)) {
        if (held_up == false) {
          if (stick_up_to_add_char == true){
            wii_nunch_input += char(curr_key);
            disp_stars();
          }
          else{
            if (wii_nunch_input.length() > 0)
              wii_nunch_input.remove(wii_nunch_input.length() - 1, 1);
            //Serial.println(wii_nunch_input);
            tft.fillRect(0, 32, 155, 96, 0x0000);
            //Serial.println(wii_nunch_input);
            disp_stars();
          }
        }
        held_up = true;
      } else {
        held_up = false;
      }

      if (YAxis < threshold) {
        if (held_down == false) {
          if (stick_up_to_add_char == true){
            if (wii_nunch_input.length() > 0)
              wii_nunch_input.remove(wii_nunch_input.length() - 1, 1);
            //Serial.println(wii_nunch_input);
            tft.fillRect(0, 32, 155, 96, 0x0000);
            //Serial.println(wii_nunch_input);
            disp_stars();
          }
          else{
            wii_nunch_input += char(curr_key);
            disp_stars();
          }
        }
        held_down = true;
      } else {
        held_down = false;
      }
    }
    delay(1);
  }
}

void disp_centered_text(String t_disp, int y){
  if (t_disp.length() < 27){
    int16_t x1, y1;
    uint16_t w, h;
    tft.getTextBounds(t_disp, 160, 0, &x1, &y1, &w, &h);
    tft.setCursor(80 - (w / 2), y);
    tft.print(t_disp);
  }
  else{
    tft.setCursor(0, y);
    tft.print(t_disp);
  }
}

void setup() {
  tft.initR(INITR_BLACKTAB);
  tft.setRotation(1);
  tft.fillScreen(0x0000);
  wii_nunchuk.begin();
  Serial.begin(115200);
  while (!wii_nunchuk.connect()) {
    Serial.println("Nunchuk not detected!");
    tft.fillRect(0, 120, 155, 8, 0x0000);
    disp_centered_text("Connect Nunchuk", 120);
    delay(24);
  }
}

void loop() {
  act = true;
  //clear_variables();
  wii_nunch_input = "";
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter Cardholder Name");
  //starred_nunchuk_input();
  nunchuk_input();
  if (act == true) {
    Serial.println("Continue");
    Serial.println(wii_nunch_input);
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.setTextSize(1);
    tft.print("Contnue with \"");
    tft.print(wii_nunch_input);
    tft.print("\"");
    delay(2500);
  }
  else{
    Serial.println("Cancel");
    Serial.println(wii_nunch_input);
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.setTextSize(1);
    tft.print("Cancel (input) \"");
    tft.print(wii_nunch_input);
    tft.print("\"");
    delay(2500);
  }
}
