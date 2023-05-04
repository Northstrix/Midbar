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
#include <PS2KeyAdvanced.h>

/* Keyboard constants  Change to suit your Arduino
   define pins used for data and clock from keyboard */
#define DATAPIN PB5
#define IRQPIN PB6
#define CHOOSE_ARD_MODE_PIN PA15

uint16_t c;
String keyboard_input;
bool finish_input;

PS2KeyAdvanced arduino;

void get_input_from_arduino() {
  keyboard_input = "";
  finish_input = false;
  while (finish_input == false) {
    if (arduino.available()) {
      // read the next key
      c = arduino.read();
      if (c > 0 && ((c & 0xFF) != 6)) {
        if (c >> 8 == 129 && (c & PS2_BREAK)) {

          if ((c & 0xFF) == 30) { // Enter
            finish_input = true;
          }
        }
        if (c >> 8 == 128 && (c & PS2_BREAK)) {

          if ((c & 0xFF) > 48 && (c & 0xFF) < 58) // Digits
            keyboard_input += (char((c & 0xFF)));

          if ((c & 0xFF) > 64 && (c & 0xFF) < 91) // Lowercase letters
            keyboard_input += (char((c & 0xFF) + 32));

        }

      }
    }
    delayMicroseconds(200);
  }
}

void setup() {
  // Configure the keyboard library
  arduino.begin(DATAPIN, IRQPIN);
  Serial.begin(115200);
  Serial.println("PS2 Advanced Key Simple Test:");
  pinMode(CHOOSE_ARD_MODE_PIN, OUTPUT);
  digitalWrite(CHOOSE_ARD_MODE_PIN, HIGH);
}

void loop() {
  /*
  get_input_from_arduino();
  Serial.println(keyboard_input);
  */
  digitalWrite(CHOOSE_ARD_MODE_PIN, LOW);
  get_input_from_arduino();
  Serial.println(keyboard_input);
  digitalWrite(CHOOSE_ARD_MODE_PIN, HIGH);
  delay(250);
}
