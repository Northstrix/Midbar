/*
Midbar
Distributed under the MIT License
© Copyright Maxim Bortnikov 2023
For more information please visit
https://sourceforge.net/projects/midbar/
https://github.com/Northstrix/Midbar
Required libraries:
https://github.com/zhouyangchao/AES
https://github.com/peterferrie/serpent
https://github.com/ddokkaebi/Blowfish
https://github.com/Northstrix/DES_and_3DES_Library_for_MCUs
https://github.com/ulwanski/sha512
https://github.com/Bodmer/TFT_eSPI
https://github.com/intrbiz/arduino-crypto
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/techpaul/PS2KeyMap
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/adafruit/Adafruit-ST7735-Library
https://github.com/Chris--A/Keypad
*/
#include <Wire_slave.h>
#include <USBComposite.h>

bool rec_d;
byte x;

USBHID HID;
HIDKeyboard Keyboard(HID);

void setup(){
  HID.begin(HID_KEYBOARD_MOUSE);
  while(!USBComposite);
  Keyboard.print(" "); // Needed to work properly 'cause Windows misses the first keystroke
  Wire.begin(4);                // join i2c bus with address #4
  Wire.onReceive(receiveEvent); // register event
}

void loop(){
  if (rec_d == true){
    if (x > 0){
      Keyboard.print(char(x));
      x = 0;
    }
    rec_d = false;
  }
  delay(1);
}

// function that executes whenever data is received from master
// this function is registered as an event, see setup()
// Note that it is not advicable to call Serial.print() from within an ISR
void receiveEvent(int howMany){
  while(1 < Wire.available()){ // loop through all but the last
    char c = Wire.read(); // receive byte as a character
  }
  x = Wire.read();    // receive byte as an integer
  rec_d = true;
}
