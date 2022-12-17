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
https://github.com/Northstrix/DES_and_3DES_Library_for_MCUs
https://github.com/ulwanski/sha512
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit-SSD1351-library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/GyverLibs/GyverBus
https://github.com/PaulStoffregen/PS2Keyboard
https://github.com/siara-cc/esp32_arduino_sqlite3_lib
https://github.com/intrbiz/arduino-crypto
https://github.com/GyverLibs/EncButton
https://github.com/Chris--A/Keypad
https://github.com/platisd/nokia-5110-lcd-library
*/
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1351.h>
#include <SPI.h>
#include <EncButton2.h>

#define SCLK_PIN 18
#define MOSI_PIN 23
#define DC_PIN 2
#define CS_PIN 15
#define RST_PIN 4
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 128

Adafruit_SSD1351 oled = Adafruit_SSD1351(SCREEN_WIDTH, SCREEN_HEIGHT, & SPI, CS_PIN, DC_PIN, RST_PIN);
EncButton2 < EB_ENC > enc0(INPUT, 26, 27);
int curr_key;

void disp_centered_text(String text, int h) {
  int16_t x1;
  int16_t y1;
  uint16_t width;
  uint16_t height;

  oled.getTextBounds(text, 0, 0, & x1, & y1, & width, & height);
  oled.setCursor((128 - width) / 2, h);
  oled.print(text);
}

void main_menu(int curr_pos) {
  oled.setTextSize(1);
  byte sdown = 30;
  if (curr_pos == 0) {
    oled.setTextColor(0xffff);
    disp_centered_text("Encoder", sdown + 10);
    oled.setTextColor(0x001f);
    disp_centered_text("PS/2 Keyboard", sdown + 20);
    disp_centered_text("Encoder + Keyboard", sdown + 30);
    disp_centered_text("Serial Terminal", sdown + 40);
  }
  if (curr_pos == 1) {
    oled.setTextColor(0x001f);
    disp_centered_text("Encoder", sdown + 10);
    oled.setTextColor(0xffff);
    disp_centered_text("PS/2 Keyboard", sdown + 20);
    oled.setTextColor(0x001f);
    disp_centered_text("Encoder + Keyboard", sdown + 30);
    disp_centered_text("Serial Terminal", sdown + 40);
  }
  if (curr_pos == 2) {
    oled.setTextColor(0x001f);
    disp_centered_text("Encoder", sdown + 10);
    disp_centered_text("PS/2 Keyboard", sdown + 20);
    oled.setTextColor(0xffff);
    disp_centered_text("Encoder + Keyboard", sdown + 30);
    oled.setTextColor(0x001f);
    disp_centered_text("Serial Terminal", sdown + 40);
  }
  if (curr_pos == 3) {
    oled.setTextColor(0x001f);
    disp_centered_text("Encoder", sdown + 10);
    disp_centered_text("PS/2 Keyboard", sdown + 20);
    disp_centered_text("Encoder + Keyboard", sdown + 30);
    oled.setTextColor(0xffff);
    disp_centered_text("Serial Terminal", sdown + 40);
  }
}

void setup() {
  oled.begin();
  oled.fillScreen(0x0000);
  oled.setTextColor(0x001f);
  disp_centered_text("Choose Input Source", 10);
  oled.setTextColor(0x07e0);
  oled.setCursor(0, 110);
  oled.print("A:Continue");
  oled.setTextColor(0xf800);
  oled.setCursor(0, 120);
  oled.print("B:Cancel");
  curr_key = 0;
  main_menu(curr_key);
}

void loop() {
  enc0.tick();
  if (enc0.left())
    curr_key--;
  if (enc0.right())
    curr_key++;

  if (curr_key < 0)
    curr_key = 3;

  if (curr_key > 3)
    curr_key = 0;

  if (enc0.turn()) {
    main_menu(curr_key);
  }
}
