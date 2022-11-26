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
https://github.com/ulwanski/sha512
https://github.com/adafruit/Adafruit_SSD1306
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/intrbiz/arduino-crypto
https://github.com/Northstrix/DES_and_3DES_Library_for_MCUs
https://github.com/GyverLibs/EncButton
*/
#include <EEPROM.h>
#define EEPROM_SIZE 4095

void setup() {
  Serial.begin(115200);
  Serial.println();
    EEPROM.begin(EEPROM_SIZE);
    for (int i = 0; i < EEPROM_SIZE; i++){
      Serial.print("[");
      Serial.print(i);
      Serial.print("]");
      if (EEPROM.read(i) < 16)
        Serial.print("0");
      Serial.println(EEPROM.read(i), HEX);
    }
    EEPROM.end();
}

void loop() {
}
