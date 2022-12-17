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
#include <SoftwareSerial.h>
#include <SPI.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1351.h>
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
SoftwareSerial mySerial(34, 35); // RX, TX
EncButton2 < EB_BTN > encoder_button(INPUT, 33);#include "GBUS.h"

GBUS bus( & mySerial, 3, 10);
int curr_key;
String encoder_input;

struct myStruct {
  char x;
};

void disp() {
  //oled.fillScreen(0x0000);
  oled.setTextSize(2);
  oled.setTextColor(0xffff);
  oled.fillRect(62, 0, 10, 16, 0x0000);
  oled.setCursor(62, 0);
  oled.print(char(curr_key));
  oled.fillRect(104, 0, 22, 14, 0x0000);
  oled.setCursor(104, 0);
  String hexstr;
  if (curr_key < 16)
    hexstr += 0;
  hexstr += String(curr_key, HEX);
  hexstr.toUpperCase();
  oled.setTextColor(0x07e0);
  oled.print(hexstr);
  oled.setTextColor(0xffff);
  oled.setTextSize(1);
  oled.setCursor(0, 40);
  oled.print(encoder_input);
}

void setup(void) {
  curr_key = 65;
  Serial.begin(115200);
  mySerial.begin(9600);
  oled.begin();
  oled.fillScreen(0x0000);
  oled.setTextSize(2);
  oled.setTextColor(0xffff);
  oled.setCursor(2, 0);
  oled.print("Char'");
  oled.setCursor(74, 0);
  oled.print("'");
  disp();
  oled.setCursor(0, 28);
  oled.setTextSize(1);
  oled.setTextColor(0x001f);
  oled.print("Enter anything here:");
}

void loop() {
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

  bus.tick();
  if (bus.gotData()) {
    myStruct data;
    bus.readData(data);
    if (data.x == 21)
      curr_key++;
    if (data.x == 8)
      curr_key--;

    if (curr_key < 32)
      curr_key = 126;

    if (curr_key > 126)
      curr_key = 32;

    if (data.x == 13) {
      Serial.println(encoder_input);
    }

    if (data.x == 131) {
      encoder_input += char(curr_key);
      Serial.println(encoder_input);
    }

    if (data.x == 132 || data.x == 127) {
      if (encoder_input.length() > 0)
        encoder_input.remove(encoder_input.length() - 1, 1);
      Serial.println(encoder_input);
      oled.fillRect(0, 40, 128, 88, 0x0000);
    }

    if (data.x > 31 && data.x < 127) {
      encoder_input += data.x;
      Serial.println(encoder_input);
      curr_key = data.x;
    }
    disp();
  }
  delayMicroseconds(400);
  encoder_button.tick();
  if (encoder_button.hasClicks(4)) {
    Serial.println(encoder_input);
  }
  delayMicroseconds(400);
}
