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
https://github.com/intrbiz/arduino-crypto
https://github.com/GyverLibs/EncButton
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/techpaul/PS2KeyMap
https://github.com/miguelbalboa/rfid
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/adafruit/Adafruit-ST7735-Library
https://github.com/Chris--A/Keypad
*/
#include <TFT_eSPI.h> // Hardware-specific library
#include <SPI.h>
#include <MFRC522.h>

TFT_eSPI tft = TFT_eSPI();       // Invoke custom library

/*
 * RFID Reader - ESP32
 * SDA - D21
 * SCK - D18
 * MOSI - D23
 * MISO - D19
 * RST - D27
 */

#define SS_PIN  21
#define RST_PIN 25

MFRC522 rfid(SS_PIN, RST_PIN);

void setup() {
  Serial.begin(115200);
  tft.begin();
  tft.fillScreen(0x0000);
  tft.setRotation(1);
  tft.println("Tap an RFID/NFC tag on the RFID-RC522 reader");
  SPI.begin(); // init SPI bus
  rfid.PCD_Init(); // init MFRC522
}

void loop() {
  if (rfid.PICC_IsNewCardPresent()) { // new tag is available
    if (rfid.PICC_ReadCardSerial()) { // NUID has been readed
      MFRC522::PICC_Type piccType = rfid.PICC_GetType(rfid.uid.sak);
      Serial.print("RFID/NFC Tag Type: ");
      Serial.println(rfid.PICC_GetTypeName(piccType));

      // print UID in Serial Monitor in the hex format
      Serial.print("UID:");
      for (int i = 0; i < rfid.uid.size; i++) {
        Serial.print(rfid.uid.uidByte[i] < 0x10 ? " 0" : " ");
        Serial.print(rfid.uid.uidByte[i], HEX);
      }
      Serial.println();
      tft.fillScreen(0x0000);
      tft.setCursor(0,5);
      tft.setTextSize(2);
      tft.print("UID:");
      for (int i = 0; i < rfid.uid.size; i++) {
        tft.print(rfid.uid.uidByte[i] < 0x10 ? " 0" : " ");
        tft.print(rfid.uid.uidByte[i], HEX);
      }
      rfid.PICC_HaltA(); // halt PICC
      rfid.PCD_StopCrypto1(); // stop encryption on PCD
    }
  }
  delay(50);
}
