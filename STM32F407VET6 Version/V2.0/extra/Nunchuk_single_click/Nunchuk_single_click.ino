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
https://github.com/dmadison/NintendoExtensionCtrl
https://github.com/ulwanski/sha512
*/
#include <NintendoExtensionCtrl.h>

Nunchuk wii_nunchuk;

bool pressed_c;
bool pressed_z;
bool held_left;
bool held_up;
bool held_right;
bool held_down;

byte threshold = 16;

void setup() {
	Serial.begin(115200);
	wii_nunchuk.begin();
  while (!wii_nunchuk.connect()) {
    Serial.println("Nunchuk not detected!");
    delay(1000);
  }
}

void loop() {
	boolean success = wii_nunchuk.update();  // Get new data from the controller

	if (!success) {  // Ruh roh
		Serial.println("Controller disconnected!");
		delay(1000);
	}
	else {
    if (wii_nunchuk.buttonC() == true){
      if (pressed_c == false){
        Serial.println("C");
      }
      pressed_c = true;
    }
    else{
      pressed_c = false;
    }

    if (wii_nunchuk.buttonZ() == true){
      if (pressed_z == false){
        Serial.println("Z");
      }
      pressed_z = true;
    }
    else{
      pressed_z = false;
    }

    byte XAxis = wii_nunchuk.joyX();
    byte YAxis = wii_nunchuk.joyY();

    if (XAxis > (255 - threshold)){
      if (held_right == false){
        Serial.println("Right");
      }
      held_right = true;
    }
    else{
      held_right = false;
    }

    if (XAxis < threshold){
      if (held_left == false){
        Serial.println("Left");
      }
      held_left = true;
    }
    else{
      held_left = false;
    }

    if (YAxis > (255 - threshold)){
      if (held_up == false){
        Serial.println("Up");
      }
      held_up = true;
    }
    else{
      held_up = false;
    }

    if (YAxis < threshold){
      if (held_down == false){
        Serial.println("Down");
      }
      held_down = true;
    }
    else{
      held_down = false;
    }
	}
}
