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
https://github.com/ulwanski/sha512
https://github.com/adafruit/Adafruit_ILI9341
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/intrbiz/arduino-crypto
https://github.com/GyverLibs/EncButton
*/
// Simple USB Keyboard Forwarder
//
// This example is in the public domain

#include "USBHost_t36.h"

#define SHOW_KEYBOARD_DATA

USBHost myusb;
USBHub hub1(myusb);
KeyboardController keyboard1(myusb);

USBHIDParser hid1(myusb);
USBHIDParser hid2(myusb);
USBHIDParser hid3(myusb);

uint8_t keyboard_modifiers = 0;  // try to keep a reasonable value
#ifdef KEYBOARD_INTERFACE
uint8_t keyboard_last_leds = 0;
#endif

void setup()
{
#ifdef SHOW_KEYBOARD_DATA
	while (!Serial) ; // wait for Arduino Serial Monitor
#endif
	myusb.begin();
	keyboard1.attachPress(OnPress);
}


void loop()
{
	myusb.Task();
}

void OnPress(int key)
{
	switch (key) {
	case KEYD_UP       : Serial.print("UP"); break;
	case KEYD_DOWN    : Serial.print("DN"); break;
	case KEYD_LEFT     : Serial.print("LEFT"); break;
	case KEYD_RIGHT   : Serial.print("RIGHT"); break;
	}
	Serial.println();
	Serial.println(char(key));
  Serial.println(key);
}
