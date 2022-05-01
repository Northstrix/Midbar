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
#include <PS2Keyboard.h>
#include <SoftwareSerial.h>
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
}
