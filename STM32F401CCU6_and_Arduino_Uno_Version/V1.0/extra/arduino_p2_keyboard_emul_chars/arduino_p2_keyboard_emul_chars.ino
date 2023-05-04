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
https://github.com/Bodmer/TFT_eSPI
https://github.com/miguelbalboa/rfid
https://github.com/intrbiz/arduino-crypto
https://github.com/GyverLibs/EncButton
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/techpaul/PS2KeyMap
https://github.com/adafruit/SdFat
*/
#include <ps2dev.h>

PS2dev keyboard(3, 2); //clock, data

unsigned long timecount = 0;
int scancodes_idx = 0;

void setup() {
  keyboard.keyboard_init();
}

char scancodes[] = {
  PS2dev::ZERO,
  PS2dev::ONE,
  PS2dev::TWO,
  PS2dev::THREE,
  PS2dev::FOUR,
  PS2dev::FIVE,
  PS2dev::SIX,
  PS2dev::SEVEN,
  PS2dev::EIGHT,
  PS2dev::NINE,
  PS2dev::A,
  PS2dev::B,
  PS2dev::C,
  PS2dev::D,
  PS2dev::E,
  PS2dev::F,
  PS2dev::ENTER
};

void loop() {
  unsigned char leds;
  if(keyboard.keyboard_handle(&leds)) {
  }

  if (millis() - timecount > 1000) {
    keyboard.keyboard_mkbrk(scancodes[scancodes_idx++]);
    if (scancodes_idx >= sizeof(scancodes)) {
      scancodes_idx = 0;
    }
    timecount = millis();
  }
}
