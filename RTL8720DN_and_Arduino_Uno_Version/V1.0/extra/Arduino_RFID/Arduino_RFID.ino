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
#include <SPI.h>
#include <MFRC522.h>
#define SS_PIN 10
#define RST_PIN 9
MFRC522 mfrc522(SS_PIN, RST_PIN);

void setup() 
{
  Serial.begin(115200);
  SPI.begin();
  mfrc522.PCD_Init();
}
void loop() 
{
  delay(1);
    if ( ! mfrc522.PICC_IsNewCardPresent()) 
    {
      return;
    }
    if ( ! mfrc522.PICC_ReadCardSerial()) 
    {
      return;
    }
    for (int i = 0; i < 4; i++){
      Serial.println(mfrc522.uid.uidByte[i]);
    }
}
