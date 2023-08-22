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
https://github.com/miguelbalboa/rfid
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/techpaul/PS2KeyMap
https://github.com/pothos/arduino-n64-controller-library
*/
#include <FlashMemory.h>

void setup() {
    Serial.begin(115200);
    for (int i = 0; i < 4096; i++)
      FlashMemory.buf[i] = 255;
    FlashMemory.update();
    pinMode(LED_B, OUTPUT);
}

void loop() {
  digitalWrite(LED_B, HIGH);
  delay(250);
  digitalWrite(LED_B, LOW);
  delay(250);
}
