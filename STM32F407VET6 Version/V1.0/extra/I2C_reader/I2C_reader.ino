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
// Wire Peripheral Receiver
// by Nicholas Zambetti <http://www.zambetti.com>

// Demonstrates use of the Wire library
// Receives data as an I2C/TWI Peripheral device
// Refer to the "Wire Master Writer" example for use with this

// Created 29 March 2006

// This example code is in the public domain.

/*

 Example guide:
 https://www.amebaiot.com/en/amebad-arduino-i2c-4/
 */

#include <Wire.h>

void setup() {  
    Wire.begin(13);                // join i2c bus with address #8
    Wire.onReceive(receiveEvent); // register event
    Serial.begin(115200);         // start serial for output
}

void loop() {
    delay(100);
}

// function that executes whenever data is received from master
// this function is registered as an event, see setup()
void receiveEvent(int howMany) {
    howMany = howMany;              // clear warning msg
    /*
    while(1 < Wire.available()) {   // loop through all but the last
        char c = Wire.read();         // receive byte as a character
        Serial.print(c);              // print the character
    }
    */
    int x = Wire.read();            // receive byte as an integer
    Serial.println(x);              // print the integer
}
