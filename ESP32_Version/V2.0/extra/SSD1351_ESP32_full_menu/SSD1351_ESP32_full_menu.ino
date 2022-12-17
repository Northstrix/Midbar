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
#include <SoftwareSerial.h>
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
SoftwareSerial mySerial(34, 35); // RX, TX
#include "GBUS.h"

GBUS bus( & mySerial, 3, 10);
int curr_key;

struct myStruct {
  char x;
};

const bool midbar_icon PROGMEM [70][18] = {
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{true,true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{true,true,true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false},
{false,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true},
{false,false,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true},
{false,false,false,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true},
{false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,true,true,true},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,true,true,true},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,true,true,true},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,true,true,true},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,true,true,true},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,true,true,true},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,true,true,true},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,true,true,true},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,true,true,true},
{true,true,true,true,false,false,false,false,false,false,false,false,false,false,false,true,true,true},
{true,true,true,true,true,false,false,false,false,false,false,false,false,false,false,true,true,true},
{false,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true},
{false,false,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true},
{false,false,false,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true},
{false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,true,true,true},
{false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,true,true,true},
{false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,true,true,true},
{false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true},
{true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true},
{true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false},
{true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,true,true},
{true,true,true,true,true,false,false,false,false,false,false,false,true,true,true,true,true,true},
{true,true,true,true,true,true,true,false,true,true,true,true,true,true,true,true,true,true},
{false,false,true,true,true,true,true,true,true,true,true,true,true,true,true,true,false,false},
{false,false,false,false,true,true,true,true,true,true,true,true,false,false,false,false,false,false},
{false,false,true,true,true,true,true,true,false,false,false,false,false,false,false,false,false,false},
{false,true,true,true,true,true,false,false,false,false,false,false,false,false,false,false,false,false},
{false,true,true,true,false,false,false,false,false,false,false,false,false,false,false,true,true,true},
{true,true,true,true,false,false,false,false,false,false,false,false,false,false,false,true,true,true},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,true,true,true},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,true,true,true},
{true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,true,true,true},
{true,true,true,true,false,false,false,false,false,false,false,false,false,false,false,true,true,true},
{true,true,true,true,true,false,false,false,false,false,false,false,false,false,false,true,true,true},
{false,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true},
{false,false,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true},
{false,false,false,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true}
};

void disp_centered_text(String text, int h) {
  int16_t x1;
  int16_t y1;
  uint16_t width;
  uint16_t height;

  oled.getTextBounds(text, 0, 0, & x1, & y1, & width, & height);
  oled.setCursor((128 - width) / 2, h);
  oled.print(text);
}

void disp_button_designation() {
  oled.setTextColor(0x07e0);
  oled.setCursor(0, 120);
  oled.print("A:Continue");
  oled.setTextColor(0xf800);
  oled.setCursor(80, 120);
  oled.print("B:Cancel");
}

void call_main_menu() {
  oled.fillScreen(0x0000);
  for (int i = 0; i < 70; i++) {
    for (int j = 0; j < 18; j++) {
      if (midbar_icon[i][j] == true)
        oled.drawPixel(i + 26, j + 6, 0x001f);
    }
  }
  curr_key = 0;
  main_menu(curr_key);
}

void main_menu(int curr_pos) {
  oled.setTextSize(1);
  byte sdown = 30;
  if (curr_pos == 0) {
    oled.setTextColor(0xffff);
    disp_centered_text("Data in ESP32's Flash", sdown + 10);
    oled.setTextColor(0x001f);
    disp_centered_text("Data on extrnl EEPROM", sdown + 20);
    disp_centered_text("Encryption Algorithms", sdown + 30);
    disp_centered_text("Hash Functions", sdown + 40);
    disp_centered_text("SQLite3", sdown + 50);
    disp_centered_text("Password Projection", sdown + 60);
    disp_centered_text("Other Options", sdown + 70);
  }
  if (curr_pos == 1) {
    oled.setTextColor(0x001f);
    disp_centered_text("Data in ESP32's Flash", sdown + 10);
    oled.setTextColor(0xffff);
    disp_centered_text("Data on extrnl EEPROM", sdown + 20);
    oled.setTextColor(0x001f);
    disp_centered_text("Encryption Algorithms", sdown + 30);
    disp_centered_text("Hash Functions", sdown + 40);
    disp_centered_text("SQLite3", sdown + 50);
    disp_centered_text("Password Projection", sdown + 60);
    disp_centered_text("Other Options", sdown + 70);
  }
  if (curr_pos == 2) {
    oled.setTextColor(0x001f);
    disp_centered_text("Data in ESP32's Flash", sdown + 10);
    disp_centered_text("Data on extrnl EEPROM", sdown + 20);
    oled.setTextColor(0xffff);
    disp_centered_text("Encryption Algorithms", sdown + 30);
    oled.setTextColor(0x001f);
    disp_centered_text("Hash Functions", sdown + 40);
    disp_centered_text("SQLite3", sdown + 50);
    disp_centered_text("Password Projection", sdown + 60);
    disp_centered_text("Other Options", sdown + 70);
  }
  if (curr_pos == 3) {
    oled.setTextColor(0x001f);
    disp_centered_text("Data in ESP32's Flash", sdown + 10);
    disp_centered_text("Data on extrnl EEPROM", sdown + 20);
    disp_centered_text("Encryption Algorithms", sdown + 30);
    oled.setTextColor(0xffff);
    disp_centered_text("Hash Functions", sdown + 40);
    oled.setTextColor(0x001f);
    disp_centered_text("SQLite3", sdown + 50);
    disp_centered_text("Password Projection", sdown + 60);
    disp_centered_text("Other Options", sdown + 70);
  }
  if (curr_pos == 4) {
    oled.setTextColor(0x001f);
    disp_centered_text("Data in ESP32's Flash", sdown + 10);
    disp_centered_text("Data on extrnl EEPROM", sdown + 20);
    disp_centered_text("Encryption Algorithms", sdown + 30);
    disp_centered_text("Hash Functions", sdown + 40);
    oled.setTextColor(0xffff);
    disp_centered_text("SQLite3", sdown + 50);
    oled.setTextColor(0x001f);
    disp_centered_text("Password Projection", sdown + 60);
    disp_centered_text("Other Options", sdown + 70);
  }
  if (curr_pos == 5) {
    oled.setTextColor(0x001f);
    disp_centered_text("Data in ESP32's Flash", sdown + 10);
    disp_centered_text("Data on extrnl EEPROM", sdown + 20);
    disp_centered_text("Encryption Algorithms", sdown + 30);
    disp_centered_text("Hash Functions", sdown + 40);
    disp_centered_text("SQLite3", sdown + 50);
    oled.setTextColor(0xffff);
    disp_centered_text("Password Projection", sdown + 60);
    oled.setTextColor(0x001f);
    disp_centered_text("Other Options", sdown + 70);
  }
  if (curr_pos == 6) {
    oled.setTextColor(0x001f);
    disp_centered_text("Data in ESP32's Flash", sdown + 10);
    disp_centered_text("Data on extrnl EEPROM", sdown + 20);
    disp_centered_text("Encryption Algorithms", sdown + 30);
    disp_centered_text("Hash Functions", sdown + 40);
    disp_centered_text("SQLite3", sdown + 50);
    disp_centered_text("Password Projection", sdown + 60);
    oled.setTextColor(0xffff);
    disp_centered_text("Other Options", sdown + 70);
  }
}

void input_source_for_data_in_flash_menu(int curr_pos) {
  oled.setTextSize(1);
  byte sdown = 30;
  if (curr_pos == 0) {
    oled.setTextColor(0xffff);
    disp_centered_text("Encoder + Keyboard", sdown + 10);
    oled.setTextColor(0x001f);
    disp_centered_text("Serial Terminal", sdown + 20);
  }
  if (curr_pos == 1) {
    oled.setTextColor(0x001f);
    disp_centered_text("Encoder + Keyboard", sdown + 10);
    oled.setTextColor(0xffff);
    disp_centered_text("Serial Terminal", sdown + 20);
  }
}

void input_source_for_data_in_flash(byte record_type) {
  oled.fillScreen(0x0000);
  oled.setTextColor(0x001f);
  disp_centered_text("Choose Input Source", 10);
  curr_key = 0;
  input_source_for_data_in_flash_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 1;

    if (curr_key > 1)
      curr_key = 0;

    if (enc0.turn()) {
      input_source_for_data_in_flash_menu(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.x == 10)
        curr_key++;
      if (data.x == 11)
        curr_key--;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        if (record_type == 0)
          Serial.println("Add Login to SQLite3 from Encoder + Keyboard");
        if (record_type == 1)
          Serial.println("Add Credit Card to SQLite3 from Encoder + Keyboard");
        if (record_type == 2)
          Serial.println("Add Note to SQLite3 from Encoder + Keyboard");
        if (record_type == 3)
          Serial.println("Add Phone Number to SQLite3 from Encoder + Keyboard");
        cont_to_next = true;
      }

      if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        if (record_type == 0)
          Serial.println("Add Login to SQLite3 from Serial Terminal");
        if (record_type == 1)
          Serial.println("Add Credit Card to SQLite3 from Serial Terminal");
        if (record_type == 2)
          Serial.println("Add Note to SQLite3 from Serial Terminal");
        if (record_type == 3)
          Serial.println("Add Phone Number to SQLite3 from Serial Terminal");
        cont_to_next = true;
      }

      if (data.x == 10 || data.x == 11)
        input_source_for_data_in_flash_menu(curr_key);

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
        cont_to_next = true;
    }
  }
  call_main_menu();
}

void action_for_data_in_flash_menu(int curr_pos) {
  oled.setTextSize(1);
  byte sdown = 30;
  if (curr_pos == 0) {
    oled.setTextColor(0xffff);
    disp_centered_text("Add", sdown + 10);
    oled.setTextColor(0x001f);
    disp_centered_text("Edit", sdown + 20);
    disp_centered_text("Delete", sdown + 30);
    disp_centered_text("View", sdown + 40);
  }
  if (curr_pos == 1) {
    oled.setTextColor(0x001f);
    disp_centered_text("Add", sdown + 10);
    oled.setTextColor(0xffff);
    disp_centered_text("Edit", sdown + 20);
    oled.setTextColor(0x001f);
    disp_centered_text("Delete", sdown + 30);
    disp_centered_text("View", sdown + 40);
  }
  if (curr_pos == 2) {
    oled.setTextColor(0x001f);
    disp_centered_text("Add", sdown + 10);
    disp_centered_text("Edit", sdown + 20);
    oled.setTextColor(0xffff);
    disp_centered_text("Delete", sdown + 30);
    oled.setTextColor(0x001f);
    disp_centered_text("View", sdown + 40);
  }
  if (curr_pos == 3) {
    oled.setTextColor(0x001f);
    disp_centered_text("Add", sdown + 10);
    disp_centered_text("Edit", sdown + 20);
    disp_centered_text("Delete", sdown + 30);
    oled.setTextColor(0xffff);
    disp_centered_text("View", sdown + 40);
  }
}

void action_for_data_in_flash(String menu_title, byte record_type) {
  oled.fillScreen(0x0000);
  oled.setTextColor(0x001f);
  disp_centered_text(menu_title, 10);
  curr_key = 0;
  action_for_data_in_flash_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
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
      action_for_data_in_flash_menu(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.x == 10)
        curr_key++;
      if (data.x == 11)
        curr_key--;

      if (curr_key < 0)
        curr_key = 3;

      if (curr_key > 3)
        curr_key = 0;

      if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        if (record_type == 0)
          input_source_for_data_in_flash(record_type);
        if (record_type == 1)
          input_source_for_data_in_flash(record_type);
        if (record_type == 2)
          input_source_for_data_in_flash(record_type);
        if (record_type == 3)
          input_source_for_data_in_flash(record_type);
        cont_to_next = true;
      }

      if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        if (record_type == 0)
          Serial.println("Edit Login");
        if (record_type == 1)
          Serial.println("Edit Credit Card");
        if (record_type == 2)
          Serial.println("Edit Note");
        if (record_type == 3)
          Serial.println("Edit Phone Number");
        cont_to_next = true;
      }

      if (curr_key == 2 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        if (record_type == 0)
          Serial.println("Delete Login from SQLite");
        if (record_type == 1)
          Serial.println("Delete Credit Card from SQLite");
        if (record_type == 2)
          Serial.println("Delete Note from SQLite");
        if (record_type == 3)
          Serial.println("Delete Phone Number from SQLite");
        cont_to_next = true;
      }

      if (curr_key == 3 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        if (record_type == 0)
          Serial.println("View Login from SQLite");
        if (record_type == 1)
          Serial.println("View Credit Card from SQLite");
        if (record_type == 2)
          Serial.println("View Note from SQLite");
        if (record_type == 3)
          Serial.println("View Phone Number from SQLite");
        cont_to_next = true;
      }

      if (data.x == 10 || data.x == 11)
        action_for_data_in_flash_menu(curr_key);

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
        cont_to_next = true;
    }
  }
  call_main_menu();
}

void data_in_flash_menu(int curr_pos) {
  oled.setTextSize(1);
  byte sdown = 30;
  if (curr_pos == 0) {
    oled.setTextColor(0xffff);
    disp_centered_text("Logins", sdown + 10);
    oled.setTextColor(0x001f);
    disp_centered_text("Credit Cards", sdown + 20);
    disp_centered_text("Notes", sdown + 30);
    disp_centered_text("Phone Numbers", sdown + 40);
  }
  if (curr_pos == 1) {
    oled.setTextColor(0x001f);
    disp_centered_text("Logins", sdown + 10);
    oled.setTextColor(0xffff);
    disp_centered_text("Credit Cards", sdown + 20);
    oled.setTextColor(0x001f);
    disp_centered_text("Notes", sdown + 30);
    disp_centered_text("Phone Numbers", sdown + 40);
  }
  if (curr_pos == 2) {
    oled.setTextColor(0x001f);
    disp_centered_text("Logins", sdown + 10);
    disp_centered_text("Credit Cards", sdown + 20);
    oled.setTextColor(0xffff);
    disp_centered_text("Notes", sdown + 30);
    oled.setTextColor(0x001f);
    disp_centered_text("Phone Numbers", sdown + 40);
  }
  if (curr_pos == 3) {
    oled.setTextColor(0x001f);
    disp_centered_text("Logins", sdown + 10);
    disp_centered_text("Credit Cards", sdown + 20);
    disp_centered_text("Notes", sdown + 30);
    oled.setTextColor(0xffff);
    disp_centered_text("Phone Numbers", sdown + 40);
  }
}

void data_in_flash() {
  oled.fillScreen(0x0000);
  oled.setTextColor(0x001f);
  disp_centered_text("Data in ESP32's Flash", 10);
  curr_key = 0;
  data_in_flash_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
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
      data_in_flash_menu(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.x == 10)
        curr_key++;
      if (data.x == 11)
        curr_key--;

      if (curr_key < 0)
        curr_key = 3;

      if (curr_key > 3)
        curr_key = 0;

      if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        action_for_data_in_flash("Logins Menu", curr_key);
        cont_to_next = true;
      }

      if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        action_for_data_in_flash("Credit Cards Menu", curr_key);
        cont_to_next = true;
      }

      if (curr_key == 2 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        action_for_data_in_flash("Notes Menu", curr_key);
        cont_to_next = true;
      }

      if (curr_key == 3 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        action_for_data_in_flash("Phone Numbers Menu", curr_key);
        cont_to_next = true;
      }

      if (data.x == 10 || data.x == 11)
        data_in_flash_menu(curr_key);

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
        cont_to_next = true;
    }
  }
  call_main_menu();
}

void action_for_data_on_eeprom_menu(int curr_pos) {
  oled.setTextSize(1);
  byte sdown = 30;
  if (curr_pos == 0) {
    oled.setTextColor(0xffff);
    disp_centered_text("Add", sdown + 10);
    oled.setTextColor(0x001f);
    disp_centered_text("Delete", sdown + 20);
    disp_centered_text("View", sdown + 30);
  }
  if (curr_pos == 1) {
    oled.setTextColor(0x001f);
    disp_centered_text("Add", sdown + 10);
    oled.setTextColor(0xffff);
    disp_centered_text("Delete", sdown + 20);
    oled.setTextColor(0x001f);
    disp_centered_text("View", sdown + 30);
  }
  if (curr_pos == 2) {
    oled.setTextColor(0x001f);
    disp_centered_text("Add", sdown + 10);
    disp_centered_text("Delete", sdown + 20);
    oled.setTextColor(0xffff);
    disp_centered_text("View", sdown + 30);
  }
}

void action_for_data_on_eeprom(String menu_title, byte record_type) {
  oled.fillScreen(0x0000);
  oled.setTextColor(0x001f);
  disp_centered_text(menu_title, 10);
  curr_key = 0;
  action_for_data_on_eeprom_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 2;

    if (curr_key > 2)
      curr_key = 0;

    if (enc0.turn()) {
      action_for_data_on_eeprom_menu(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.x == 10)
        curr_key++;
      if (data.x == 11)
        curr_key--;

      if (curr_key < 0)
        curr_key = 2;

      if (curr_key > 2)
        curr_key = 0;

      if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        if (record_type == 0)
          input_source_for_data_on_eeprom(record_type);
        if (record_type == 1)
          input_source_for_data_on_eeprom(record_type);
        cont_to_next = true;
      }

      if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        if (record_type == 0)
          Serial.println("Delete Login from EEPROM");
        if (record_type == 1)
          Serial.println("Delete Credit Card from EEPROM");
        cont_to_next = true;
      }

      if (curr_key == 2 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        if (record_type == 0)
          Serial.println("View Login from EEPROM");
        if (record_type == 1)
          Serial.println("View Credit Card from EEPROM");
        cont_to_next = true;
      }

      if (data.x == 10 || data.x == 11)
        action_for_data_on_eeprom_menu(curr_key);

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
        cont_to_next = true;
    }
  }
  call_main_menu();
}

void input_source_for_data_on_eeprom_menu(int curr_pos) {
  oled.setTextSize(1);
  byte sdown = 30;
  if (curr_pos == 0) {
    oled.setTextColor(0xffff);
    disp_centered_text("Encoder + Keyboard", sdown + 10);
    oled.setTextColor(0x001f);
    disp_centered_text("Serial Terminal", sdown + 20);
  }
  if (curr_pos == 1) {
    oled.setTextColor(0x001f);
    disp_centered_text("Encoder + Keyboard", sdown + 10);
    oled.setTextColor(0xffff);
    disp_centered_text("Serial Terminal", sdown + 20);
  }
}

void input_source_for_data_on_eeprom(byte record_type) {
  oled.fillScreen(0x0000);
  oled.setTextColor(0x001f);
  disp_centered_text("Choose Input Source", 10);
  curr_key = 0;
  input_source_for_data_on_eeprom_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 1;

    if (curr_key > 1)
      curr_key = 0;

    if (enc0.turn()) {
      input_source_for_data_on_eeprom_menu(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.x == 10)
        curr_key++;
      if (data.x == 11)
        curr_key--;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        if (record_type == 0)
          Serial.println("Add Login to external EEPROM from Encoder + Keyboard");
        if (record_type == 1)
          Serial.println("Add Credit Card to external EEPROM from Encoder + Keyboard");
        cont_to_next = true;
      }

      if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        if (record_type == 0)
          Serial.println("Add Login to external EEPROM from Serial Terminal");
        if (record_type == 1)
          Serial.println("Add Credit Card to external EEPROM from Serial Terminal");
        cont_to_next = true;
      }

      if (data.x == 10 || data.x == 11)
        input_source_for_data_on_eeprom_menu(curr_key);

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
        cont_to_next = true;
    }
  }
  call_main_menu();
}

void data_on_eeprom_menu(int curr_pos) {
  oled.setTextSize(1);
  byte sdown = 30;
  if (curr_pos == 0) {
    oled.setTextColor(0xffff);
    disp_centered_text("Logins", sdown + 10);
    oled.setTextColor(0x001f);
    disp_centered_text("Credit Cards", sdown + 20);
  }
  if (curr_pos == 1) {
    oled.setTextColor(0x001f);
    disp_centered_text("Logins", sdown + 10);
    oled.setTextColor(0xffff);
    disp_centered_text("Credit Cards", sdown + 20);
  }
}

void data_on_eeprom() {
  oled.fillScreen(0x0000);
  oled.setTextColor(0x001f);
  disp_centered_text("Data on extrnl EEPROM", 10);
  curr_key = 0;
  data_on_eeprom_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 1;

    if (curr_key > 1)
      curr_key = 0;

    if (enc0.turn()) {
      data_on_eeprom_menu(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.x == 10)
        curr_key++;
      if (data.x == 11)
        curr_key--;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if (data.x == 10 || data.x == 11)
        data_on_eeprom_menu(curr_key);

      if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        action_for_data_on_eeprom("Logins Menu", curr_key);
        cont_to_next = true;
      }

      if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        action_for_data_on_eeprom("Credit Cards Menu", curr_key);
        cont_to_next = true;
      }

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
        cont_to_next = true;
    }
  }
  call_main_menu();
}

void input_source_for_encr_algs_menu(int curr_pos) {
  oled.setTextSize(1);
  byte sdown = 30;
  if (curr_pos == 0) {
    oled.setTextColor(0xffff);
    disp_centered_text("Encoder + Keyboard", sdown + 10);
    oled.setTextColor(0x001f);
    disp_centered_text("Serial Terminal", sdown + 20);
  }
  if (curr_pos == 1) {
    oled.setTextColor(0x001f);
    disp_centered_text("Encoder + Keyboard", sdown + 10);
    oled.setTextColor(0xffff);
    disp_centered_text("Serial Terminal", sdown + 20);
  }
}

void input_source_for_encr_algs(byte record_type) {
  oled.fillScreen(0x0000);
  oled.setTextColor(0x001f);
  disp_centered_text("Choose Input Source", 10);
  curr_key = 0;
  input_source_for_encr_algs_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 1;

    if (curr_key > 1)
      curr_key = 0;

    if (enc0.turn()) {
      input_source_for_encr_algs_menu(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.x == 10)
        curr_key++;
      if (data.x == 11)
        curr_key--;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        if (record_type == 0)
          Serial.println("Encrypt with 3DES+AES+Blfish+Serp (Encoder + Keyboard)");
        if (record_type == 1)
          Serial.println("Encrypt with Blowfish+AES+Serp+AES (Encoder + Keyboard)");
        if (record_type == 2)
          Serial.println("Encrypt with AES+Serpent+AES (Encoder + Keyboard)");
        if (record_type == 3)
          Serial.println("Encrypt with Blowfish+Serpent (Encoder + Keyboard)");
        if (record_type == 4)
          Serial.println("Encrypt with AES+Serpent (Encoder + Keyboard)");
        if (record_type == 5)
          Serial.println("Encrypt with Serpent (Encoder + Keyboard)");
        if (record_type == 6)
          Serial.println("Encrypt with Triple DES (Encoder + Keyboard)");
        cont_to_next = true;
      }

      if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        if (record_type == 0)
          Serial.println("Encrypt with 3DES+AES+Blfish+Serp (Serial Terminal)");
        if (record_type == 1)
          Serial.println("Encrypt with Blowfish+AES+Serp+AES (Serial Terminal)");
        if (record_type == 2)
          Serial.println("Encrypt with AES+Serpent+AES (Serial Terminal)");
        if (record_type == 3)
          Serial.println("Encrypt with Blowfish+Serpent (Serial Terminal)");
        if (record_type == 4)
          Serial.println("Encrypt with AES+Serpent (Serial Terminal)");
        if (record_type == 5)
          Serial.println("Encrypt with Serpent (Serial Terminal)");
        if (record_type == 6)
          Serial.println("Encrypt with Triple DES (Serial Terminal)");
        cont_to_next = true;
      }

      if (data.x == 10 || data.x == 11)
        input_source_for_encr_algs_menu(curr_key);

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
        cont_to_next = true;
    }
  }
  call_main_menu();
}

void what_to_do_with_encr_alg_menu(int curr_pos) {
  oled.setTextSize(1);
  byte sdown = 30;
  if (curr_pos == 0) {
    oled.setTextColor(0xffff);
    disp_centered_text("Encrypt String", sdown + 10);
    oled.setTextColor(0x001f);
    disp_centered_text("Decrypt String", sdown + 20);
  }
  if (curr_pos == 1) {
    oled.setTextColor(0x001f);
    disp_centered_text("Encrypt String", sdown + 10);
    oled.setTextColor(0xffff);
    disp_centered_text("Decrypt String", sdown + 20);
  }
}

void what_to_do_with_encr_alg(String menu_title, byte record_type) {
  oled.fillScreen(0x0000);
  oled.setTextColor(0x001f);
  disp_centered_text(menu_title, 10);
  curr_key = 0;
  what_to_do_with_encr_alg_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 1;

    if (curr_key > 1)
      curr_key = 0;

    if (enc0.turn()) {
      what_to_do_with_encr_alg_menu(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.x == 10)
        curr_key++;
      if (data.x == 11)
        curr_key--;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if (data.x == 10 || data.x == 11)
        what_to_do_with_encr_alg_menu(curr_key);

      if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        input_source_for_encr_algs(record_type);
        cont_to_next = true;
      }

      if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        if (record_type == 0)
          Serial.println("Decrypt with 3DES+AES+Blfish+Serp (Serial Terminal)");
        if (record_type == 1)
          Serial.println("Decrypt with Blowfish+AES+Serp+AES (Serial Terminal)");
        if (record_type == 2)
          Serial.println("Decrypt with AES+Serpent+AES (Serial Terminal)");
        if (record_type == 3)
          Serial.println("Decrypt with Blowfish+Serpent (Serial Terminal)");
        if (record_type == 4)
          Serial.println("Decrypt with AES+Serpent (Serial Terminal)");
        if (record_type == 5)
          Serial.println("Decrypt with Serpent (Serial Terminal)");
        if (record_type == 6)
          Serial.println("Decrypt with Triple DES (Serial Terminal)");
        cont_to_next = true;
      }

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
        cont_to_next = true;
    }
  }
  call_main_menu();
}

void encryption_algorithms_menu(int curr_pos) {
  oled.setTextSize(1);
  byte sdown = 30;
  if (curr_pos == 0) {
    oled.setTextColor(0xffff);
    disp_centered_text("3DES+AES+Blfish+Serp", sdown + 10);
    oled.setTextColor(0x001f);
    disp_centered_text("Blowfish+AES+Serp+AES", sdown + 20);
    disp_centered_text("AES+Serpent+AES", sdown + 30);
    disp_centered_text("Blowfish+Serpent", sdown + 40);
    disp_centered_text("AES+Serpent", sdown + 50);
    disp_centered_text("Serpent", sdown + 60);
    disp_centered_text("Triple DES", sdown + 70);
  }
  if (curr_pos == 1) {
    oled.setTextColor(0x001f);
    disp_centered_text("3DES+AES+Blfish+Serp", sdown + 10);
    oled.setTextColor(0xffff);
    disp_centered_text("Blowfish+AES+Serp+AES", sdown + 20);
    oled.setTextColor(0x001f);
    disp_centered_text("AES+Serpent+AES", sdown + 30);
    disp_centered_text("Blowfish+Serpent", sdown + 40);
    disp_centered_text("AES+Serpent", sdown + 50);
    disp_centered_text("Serpent", sdown + 60);
    disp_centered_text("Triple DES", sdown + 70);
  }
  if (curr_pos == 2) {
    oled.setTextColor(0x001f);
    disp_centered_text("3DES+AES+Blfish+Serp", sdown + 10);
    disp_centered_text("Blowfish+AES+Serp+AES", sdown + 20);
    oled.setTextColor(0xffff);
    disp_centered_text("AES+Serpent+AES", sdown + 30);
    oled.setTextColor(0x001f);
    disp_centered_text("Blowfish+Serpent", sdown + 40);
    disp_centered_text("AES+Serpent", sdown + 50);
    disp_centered_text("Serpent", sdown + 60);
    disp_centered_text("Triple DES", sdown + 70);
  }
  if (curr_pos == 3) {
    oled.setTextColor(0x001f);
    disp_centered_text("3DES+AES+Blfish+Serp", sdown + 10);
    disp_centered_text("Blowfish+AES+Serp+AES", sdown + 20);
    disp_centered_text("AES+Serpent+AES", sdown + 30);
    oled.setTextColor(0xffff);
    disp_centered_text("Blowfish+Serpent", sdown + 40);
    oled.setTextColor(0x001f);
    disp_centered_text("AES+Serpent", sdown + 50);
    disp_centered_text("Serpent", sdown + 60);
    disp_centered_text("Triple DES", sdown + 70);
  }
  if (curr_pos == 4) {
    oled.setTextColor(0x001f);
    disp_centered_text("3DES+AES+Blfish+Serp", sdown + 10);
    disp_centered_text("Blowfish+AES+Serp+AES", sdown + 20);
    disp_centered_text("AES+Serpent+AES", sdown + 30);
    disp_centered_text("Blowfish+Serpent", sdown + 40);
    oled.setTextColor(0xffff);
    disp_centered_text("AES+Serpent", sdown + 50);
    oled.setTextColor(0x001f);
    disp_centered_text("Serpent", sdown + 60);
    disp_centered_text("Triple DES", sdown + 70);
  }
  if (curr_pos == 5) {
    oled.setTextColor(0x001f);
    disp_centered_text("3DES+AES+Blfish+Serp", sdown + 10);
    disp_centered_text("Blowfish+AES+Serp+AES", sdown + 20);
    disp_centered_text("AES+Serpent+AES", sdown + 30);
    disp_centered_text("Blowfish+Serpent", sdown + 40);
    disp_centered_text("AES+Serpent", sdown + 50);
    oled.setTextColor(0xffff);
    disp_centered_text("Serpent", sdown + 60);
    oled.setTextColor(0x001f);
    disp_centered_text("Triple DES", sdown + 70);
  }
  if (curr_pos == 6) {
    oled.setTextColor(0x001f);
    disp_centered_text("3DES+AES+Blfish+Serp", sdown + 10);
    disp_centered_text("Blowfish+AES+Serp+AES", sdown + 20);
    disp_centered_text("AES+Serpent+AES", sdown + 30);
    disp_centered_text("Blowfish+Serpent", sdown + 40);
    disp_centered_text("AES+Serpent", sdown + 50);
    disp_centered_text("Serpent", sdown + 60);
    oled.setTextColor(0xffff);
    disp_centered_text("Triple DES", sdown + 70);
  }
}

void encryption_algorithms() {
  oled.fillScreen(0x0000);
  oled.setTextColor(0x001f);
  disp_centered_text("Encryption Algorithms", 10);
  curr_key = 0;
  encryption_algorithms_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 6;

    if (curr_key > 6)
      curr_key = 0;

    if (enc0.turn()) {
      encryption_algorithms_menu(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.x == 10)
        curr_key++;
      if (data.x == 11)
        curr_key--;

      if (curr_key < 0)
        curr_key = 6;

      if (curr_key > 6)
        curr_key = 0;

      if (data.x == 10 || data.x == 11)
        encryption_algorithms_menu(curr_key);

      if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        what_to_do_with_encr_alg("3DES+AES+Blfish+Serp", curr_key);
        cont_to_next = true;
      }

      if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        what_to_do_with_encr_alg("Blowfish+AES+Serp+AES", curr_key);
        cont_to_next = true;
      }

      if (curr_key == 2 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        what_to_do_with_encr_alg("AES+Serpent+AES", curr_key);
        cont_to_next = true;
      }

      if (curr_key == 3 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        what_to_do_with_encr_alg("Blowfish+Serpent", curr_key);
        cont_to_next = true;
      }

      if (curr_key == 4 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        what_to_do_with_encr_alg("AES+Serpent", curr_key);
        cont_to_next = true;
      }

      if (curr_key == 5 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        what_to_do_with_encr_alg("Serpent", curr_key);
        cont_to_next = true;
      }

      if (curr_key == 6 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        what_to_do_with_encr_alg("Triple DES", curr_key);
        cont_to_next = true;
      }

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
        cont_to_next = true;
    }
  }
  call_main_menu();
}

void hash_functions_menu(int curr_pos) {
  oled.setTextSize(1);
  byte sdown = 30;
  if (curr_pos == 0) {
    oled.setTextColor(0xffff);
    disp_centered_text("SHA-256", sdown + 10);
    oled.setTextColor(0x001f);
    disp_centered_text("SHA-512", sdown + 20);
  }
  if (curr_pos == 1) {
    oled.setTextColor(0x001f);
    disp_centered_text("SHA-256", sdown + 10);
    oled.setTextColor(0xffff);
    disp_centered_text("SHA-512", sdown + 20);
  }
}

void hash_functions() {
  oled.fillScreen(0x0000);
  oled.setTextColor(0x001f);
  disp_centered_text("Hash Functions", 10);
  curr_key = 0;
  hash_functions_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 1;

    if (curr_key > 1)
      curr_key = 0;

    if (enc0.turn()) {
      hash_functions_menu(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.x == 10)
        curr_key++;
      if (data.x == 11)
        curr_key--;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if (data.x == 10 || data.x == 11)
        hash_functions_menu(curr_key);

      if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        Serial.println("Hash with SHA-256");
        cont_to_next = true;
      }

      if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        Serial.println("Hash with SHA-512");
        cont_to_next = true;
      }

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
        cont_to_next = true;
    }
  }
  call_main_menu();
}

void input_source_for_sql_query(int curr_pos) {
  oled.setTextSize(1);
  byte sdown = 30;
  if (curr_pos == 0) {
    oled.setTextColor(0xffff);
    disp_centered_text("Encoder + Keyboard", sdown + 10);
    oled.setTextColor(0x001f);
    disp_centered_text("Serial Terminal", sdown + 20);
  }
  if (curr_pos == 1) {
    oled.setTextColor(0x001f);
    disp_centered_text("Encoder + Keyboard", sdown + 10);
    oled.setTextColor(0xffff);
    disp_centered_text("Serial Terminal", sdown + 20);
  }
}

void input_source_for_sql_query() {
  oled.fillScreen(0x0000);
  oled.setTextColor(0x001f);
  disp_centered_text("Choose Input Source", 10);
  curr_key = 0;
  input_source_for_sql_query(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 1;

    if (curr_key > 1)
      curr_key = 0;

    if (enc0.turn()) {
      input_source_for_sql_query(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.x == 10)
        curr_key++;
      if (data.x == 11)
        curr_key--;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        Serial.println("Execute SQL query from Encoder + Keyboard");
        cont_to_next = true;
      }

      if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        Serial.println("Execute SQL query from Serial Terminal");
        cont_to_next = true;
      }

      if (data.x == 10 || data.x == 11)
        input_source_for_sql_query(curr_key);

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
        cont_to_next = true;
    }
  }
  call_main_menu();
}

void sqlite3_menu() {
  oled.fillScreen(0x0000);
  oled.setTextColor(0x001f);
  disp_centered_text("SQLite3", 10);
  curr_key = 0;
  oled.setTextColor(0xffff);
  disp_centered_text("Execute SQL query", 40);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);

      if (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97) {
        input_source_for_sql_query();
        cont_to_next = true;
      }

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
        cont_to_next = true;
    }
  }
  call_main_menu();
}

void input_source_for_password_proj(int curr_pos) {
  oled.setTextSize(1);
  byte sdown = 30;
  if (curr_pos == 0) {
    oled.setTextColor(0xffff);
    disp_centered_text("Encoder + Keyboard", sdown + 10);
    oled.setTextColor(0x001f);
    disp_centered_text("Serial Terminal", sdown + 20);
  }
  if (curr_pos == 1) {
    oled.setTextColor(0x001f);
    disp_centered_text("Encoder + Keyboard", sdown + 10);
    oled.setTextColor(0xffff);
    disp_centered_text("Serial Terminal", sdown + 20);
  }
}

void input_source_for_password_proj() {
  oled.fillScreen(0x0000);
  oled.setTextColor(0x001f);
  disp_centered_text("Choose Input Source", 10);
  curr_key = 0;
  input_source_for_password_proj(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 1;

    if (curr_key > 1)
      curr_key = 0;

    if (enc0.turn()) {
      input_source_for_password_proj(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.x == 10)
        curr_key++;
      if (data.x == 11)
        curr_key--;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        Serial.println("Project Password from Encoder + Keyboard");
        cont_to_next = true;
      }

      if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        Serial.println("Project Password from Serial Terminal");
        cont_to_next = true;
      }

      if (data.x == 10 || data.x == 11)
        input_source_for_password_proj(curr_key);

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
        cont_to_next = true;
    }
  }
  call_main_menu();
}

void password_projection_menu() {
  oled.fillScreen(0x0000);
  oled.setTextColor(0x001f);
  disp_centered_text("Password Projection", 10);
  curr_key = 0;
  oled.setTextColor(0xffff);
  disp_centered_text("Project Password", 40);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);

      if (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97) {
        input_source_for_password_proj();
        cont_to_next = true;
      }

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
        cont_to_next = true;
    }
  }
  call_main_menu();
}

void other_options_menu(int curr_pos) {
  oled.setTextSize(1);
  byte sdown = 30;
  if (curr_pos == 0) {
    oled.setTextColor(0xffff);
    disp_centered_text("Generate new key for", sdown + 10);
    disp_centered_text("Password Projection", sdown + 20);
    oled.setTextColor(0x001f);
    disp_centered_text("Clear EEPROM", sdown + 30);
    disp_centered_text("Delete Midbar.db", sdown + 40);
    disp_centered_text("Factory Reset", sdown + 50);
  }
  if (curr_pos == 1) {
    oled.setTextColor(0x001f);
    disp_centered_text("Generate new key for", sdown + 10);
    disp_centered_text("Password Projection", sdown + 20);
    oled.setTextColor(0xf800);
    disp_centered_text("Clear EEPROM", sdown + 30);
    oled.setTextColor(0x001f);
    disp_centered_text("Delete Midbar.db", sdown + 40);
    disp_centered_text("Factory Reset", sdown + 50);
  }
  if (curr_pos == 2) {
    oled.setTextColor(0x001f);
    disp_centered_text("Generate new key for", sdown + 10);
    disp_centered_text("Password Projection", sdown + 20);
    disp_centered_text("Clear EEPROM", sdown + 30);
    oled.setTextColor(0xf800);
    disp_centered_text("Delete Midbar.db", sdown + 40);
    oled.setTextColor(0x001f);
    disp_centered_text("Factory Reset", sdown + 50);
  }
  if (curr_pos == 3) {
    oled.setTextColor(0x001f);
    disp_centered_text("Generate new key for", sdown + 10);
    disp_centered_text("Password Projection", sdown + 20);
    disp_centered_text("Clear EEPROM", sdown + 30);
    disp_centered_text("Delete Midbar.db", sdown + 40);
    oled.setTextColor(0xf800);
    disp_centered_text("Factory Reset", sdown + 50);
  }
}

void other_options() {
  oled.fillScreen(0x0000);
  oled.setTextColor(0x001f);
  disp_centered_text("Other Options", 10);
  curr_key = 0;
  other_options_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
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
      other_options_menu(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.x == 10)
        curr_key++;
      if (data.x == 11)
        curr_key--;

      if (curr_key < 0)
        curr_key = 3;

      if (curr_key > 3)
        curr_key = 0;

      if (data.x == 10 || data.x == 11)
        other_options_menu(curr_key);

      if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        Serial.println("Generate new key for Password Projection");
        cont_to_next = true;
      }

      if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        Serial.println("Clear EEPROM");
        cont_to_next = true;
      }

      if (curr_key == 2 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        Serial.println("Delete Midbar.db");
        cont_to_next = true;
      }

      if (curr_key == 3 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        Serial.println("Factory Reset");
        cont_to_next = true;
      }

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
        cont_to_next = true;
    }
  }
  call_main_menu();
}

void setup() {
  mySerial.begin(9600);
  oled.begin();
  Serial.begin(115200);
  call_main_menu();
}

void loop() {
  enc0.tick();
  if (enc0.left())
    curr_key--;
  if (enc0.right())
    curr_key++;

  if (curr_key < 0)
    curr_key = 6;

  if (curr_key > 6)
    curr_key = 0;

  if (enc0.turn()) {
    main_menu(curr_key);
  }

  delayMicroseconds(400);
  bus.tick();

  if (bus.gotData()) {
    myStruct data;
    bus.readData(data);
    if (data.x == 10)
      curr_key++;
    if (data.x == 11)
      curr_key--;

    if (curr_key < 0)
      curr_key = 6;

    if (curr_key > 6)
      curr_key = 0;

    if (data.x == 10 || data.x == 11)
      main_menu(curr_key);

    if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97))
      data_in_flash();

    if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97))
      data_on_eeprom();

    if (curr_key == 2 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97))
      encryption_algorithms();

    if (curr_key == 3 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97))
      hash_functions();

    if (curr_key == 4 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97))
      sqlite3_menu();

    if (curr_key == 5 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97))
      password_projection_menu();

    if (curr_key == 6 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97))
      other_options();
  }
  delayMicroseconds(400);
}
