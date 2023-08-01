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
https://github.com/ddokkaebi/Blowfish
https://github.com/intrbiz/arduino-crypto
https://github.com/GyverLibs/EncButton
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/techpaul/PS2KeyMap
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

bool rec_d;
byte i2c_data;

void get_random_number(){
  rec_d = false;
  digitalWrite(3, HIGH);
  while (rec_d == false){
    delay(1);
  }
  digitalWrite(3, LOW);
  delay(4);
}

int generate_random_number(){
  get_random_number();
  randomSeed(i2c_data);
  get_random_number();
  byte random_number = i2c_data;
  random_number ^= byte(random(256));
  get_random_number();
  random_number ^= i2c_data;
  return int(random_number);
}

void setup() {	
    Wire.begin(13);                // join i2c bus with address #13
    Wire.onReceive(receiveEvent); // register event
    Serial.begin(115200);         // start serial for output
    pinMode(3, OUTPUT);
    digitalWrite(3, LOW);
}

void loop() {
    Serial.println(generate_random_number());
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
    
    int x = Wire.read();            // receive byte as an integer
    Serial.println(x);              // print the integer
    */
    i2c_data = Wire.read();
    rec_d = true;
}
