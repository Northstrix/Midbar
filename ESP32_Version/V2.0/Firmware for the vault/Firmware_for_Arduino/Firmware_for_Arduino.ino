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
#include <PS2Keyboard.h>
#include <SoftwareSerial.h>
#include <EncButton2.h>
EncButton2 < EB_BTN > a_button(INPUT, 10);
EncButton2 < EB_BTN > b_button(INPUT, 11);
SoftwareSerial mySerial(5, 4);
const int DataPin = 8;
const int IRQpin =  3;
#include "GBUS.h"
PS2Keyboard keyboard;
GBUS bus(&mySerial, 5, 20);

struct myStruct {
  char x;
};

void setup() {
  delay(1000);
  keyboard.begin(DataPin, IRQpin);
  //Serial.begin(115200);
  mySerial.begin(9600);
  //Serial.println("Keyboard Test:");
}

void loop() {
  if (keyboard.available()) {
    myStruct data;
    // read the next key
    char c = keyboard.read();
    //Serial.print(c);
    data.x = c;
    bus.sendData(3, data);
  }
  delayMicroseconds(400);
  a_button.tick();
  if (a_button.press()) {
    myStruct data;
    data.x = 131;
    bus.sendData(3, data);
  }
  delayMicroseconds(200);
  b_button.tick();
  if (b_button.press()) {
    myStruct data;
    data.x = 132;
    bus.sendData(3, data);
  }
  delayMicroseconds(400);
}
