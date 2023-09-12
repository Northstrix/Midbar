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
https://github.com/adafruit/Adafruit_ILI9341
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/intrbiz/arduino-crypto
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/techpaul/PS2KeyMap
https://github.com/pothos/arduino-n64-controller-library
https://github.com/ulwanski/sha512
*/
// Wire Master Writer
// by Nicholas Zambetti <http://www.zambetti.com>

// Demonstrates use of the Wire library
// Writes data to an I2C/TWI slave device
// Refer to the "Wire Slave Receiver" example for use with this

// Created 29 March 2006

// This example code is in the public domain.

/*

 Example guide:
 https://www.amebaiot.com/en/amebad-arduino-i2c-1/
 */

#include <Wire.h>

void setup() {
    Serial.begin(115200);
    Wire.begin(); // join i2c bus (address optional for master)
}

byte x = 0;

void loop() {
    Wire.beginTransmission(13);  // transmit to device #87
    Wire.write(x);              // sends one byte
    Wire.endTransmission();     // stop transmitting

    x++;
    if (x == 256)
      x = 0;
    delay(4);
}
