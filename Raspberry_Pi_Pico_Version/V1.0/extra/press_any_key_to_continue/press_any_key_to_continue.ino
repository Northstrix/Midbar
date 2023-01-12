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
https://github.com/moononournation/Arduino_GFX
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/intrbiz/arduino-crypto
https://github.com/GyverLibs/EncButton
*/
#include <PS2KeyAdvanced.h>
#include <EncButton2.h>

/* Keyboard constants  Change to suit your Arduino
   define pins used for data and clock from keyboard */
#define DATAPIN 14
#define IRQPIN 15


uint16_t c;

EncButton2 < EB_ENC > enc0(INPUT, 12, 13);
EncButton2 < EB_BTN > encoder_button(INPUT, 9);
EncButton2 < EB_BTN > a_button(INPUT, 11);
EncButton2 < EB_BTN > b_button(INPUT, 10);

PS2KeyAdvanced keyboard;

void press_any_key_to_continue() {
  bool break_the_loop = false;
  while (break_the_loop == false) {

    a_button.tick();
    if (a_button.press())
      break_the_loop = true;
    delayMicroseconds(400);

    b_button.tick();
    if (b_button.press())
      break_the_loop = true;
    delayMicroseconds(400);

    if (keyboard.available()) {
      c = keyboard.read();
      if (c > 0 && ((c & 0xFF) != 6)) {
        if (c >> 8 == 192 && (c & PS2_BREAK)) {
          break_the_loop = true;
        }
        if (c >> 8 == 129 && (c & PS2_BREAK)) {
          break_the_loop = true;
        }
        if (c >> 8 == 128 && (c & PS2_BREAK)) {
          break_the_loop = true;
        }
      }
    }

    delayMicroseconds(400);
    encoder_button.tick();
    if (encoder_button.press()) {
      break_the_loop = true;
    }
    delayMicroseconds(400);
  }
}


void setup() {
  keyboard.begin(DATAPIN, IRQPIN);
  Serial.begin(115200);
  Serial.println("Break the loop function test:");
}

void loop() {
  Serial.println("Press any key to break the loop");
  press_any_key_to_continue();
  Serial.println("The loop is broken");
}
