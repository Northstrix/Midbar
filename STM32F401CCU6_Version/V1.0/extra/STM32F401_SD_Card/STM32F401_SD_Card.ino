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
https://github.com/adafruit/SdFat
*/
/*
  SD card test for stm32 and SdFat library
 
  This example shows how use the utility libraries
 
        CS    = PB12;
        MOSI  = PB15;
        MISO  = PB14;
        SCK   = PB13;
 
   by Mischianti Renzo <https://www.mischianti.org>
  
   Taken from: https://www.mischianti.org/2022/10/24/how-to-use-sd-card-with-stm32-and-sdfat-library/
*/
#include <SPI.h>
//#include <SD.h>
#include "SdFat.h"
 
// #define SD_CS_PIN PA4
 
#define SD_CS_PIN PB12
static SPIClass mySPI2(PB15, PB14, PB13, SD_CS_PIN);
#define SD2_CONFIG SdSpiConfig(SD_CS_PIN, DEDICATED_SPI, SD_SCK_MHZ(18), &mySPI2)
 
SdFat SD;
 
void printDirectory(File dir, int numTabs);

void write_to_file_with_overwrite(String filename, String content) {
  if (SD.exists(filename)) {
    SD.remove(filename);
  }
  File myFile = SD.open(filename, FILE_WRITE);

  // if the file opened okay, write to it:
  if (myFile) {
    int content_len = content.length() + 1;
    char content_array[content_len];
    content.toCharArray(content_array, content_len);
    myFile.print(content_array);
    // close the file:
    myFile.close();
  } else {
  }
}

String read_file(String filename) {
  File myFile = SD.open(filename);
  if (myFile) {
    String read_cntnt;
    while (myFile.available()) {
      read_cntnt += char(myFile.read());
    }
    myFile.close();
    return read_cntnt;
  } else {
    return "-1";
  }
}

void delete_file(String filename){
  if (SD.exists(filename)) {
    SD.remove(filename);
  }
}
 
void setup() {
  // Open serial communications and wait for port to open:
  Serial.begin(115200);
  delay(5000);
 
  Serial.print("\nInitializing SD card...");
 
  // we'll use the initialization code from the utility libraries
  // since we're just testing if the card is working!
  if (!SD.begin(SD2_CONFIG)) {
  // if (!SD.begin(SD_CS_PIN)) {
    Serial.println("initialization failed. Things to check:");
    Serial.println("* is a card inserted?");
    Serial.println("* is your wiring correct?");
    Serial.println("* did you change the chipSelect pin to match your shield or module?");
    while (1);
  } else {
    Serial.println("Wiring is correct and a card is present.");
  }
  write_to_file_with_overwrite("/file", "qwerty");
  Serial.println(read_file("/mpass"));
  Serial.println(read_file("/doesnexist"));
  Serial.println(read_file("/file"));
  delete_file("/mpass");
  uint32_t cardSize = SD.card()->sectorCount();
 
  // print the type of card
  Serial.println();
  Serial.print("Card type:         ");
  switch (SD.card()->type()) {
  case SD_CARD_TYPE_SD1:
    Serial.println(F("SD1"));
    break;
  case SD_CARD_TYPE_SD2:
    Serial.println(F("SD2"));
    break;
 
  case SD_CARD_TYPE_SDHC:
    if (cardSize < 70000000) {
      Serial.println(F("SDHC"));
    } else {
      Serial.println(F("SDXC"));
    }
    break;
 
  default:
    Serial.println(F("Unknown"));
  }
 
 
//  print the type and size of the first FAT-type volume
  uint32_t volumesize;
  Serial.print("Volume type is:    FAT");
  Serial.println(int(SD.vol()->fatType()), DEC);
 
  Serial.print("Card size:  ");
  Serial.println((float) 0.000512*cardSize);
 
  Serial.print("Total bytes: ");
  Serial.println(0.000512*SD.vol()->clusterCount()*SD.sectorsPerCluster());
 
  Serial.print("Free bytes: ");
  Serial.println(0.000512*SD.vol()->freeClusterCount()*SD.sectorsPerCluster());
 
  File dir =  SD.open("/");
  printDirectory(dir, 0);
 
}
 
void loop(void) {
}
 
void printDirectory(File dir, int numTabs) {
  while (true) {
 
    File entry =  dir.openNextFile();
    if (! entry) {
      // no more files
      break;
    }
    for (uint8_t i = 0; i < numTabs; i++) {
      Serial.print('\t');
    }
    entry.printName(&Serial);
 
    if (entry.isDirectory()) {
      Serial.println("/");
      printDirectory(entry, numTabs + 1);
    } else {
      // files have sizes, directories do not
      Serial.print("\t\t");
      Serial.print(entry.size(), DEC);
      uint16_t pdate;
      uint16_t ptime;
      entry.getModifyDateTime(&pdate, &ptime);
 
      Serial.printf("\tLAST WRITE: %d-%02d-%02d %02d:%02d:%02d\n", FS_YEAR(pdate), FS_MONTH(pdate), FS_DAY(pdate), FS_HOUR(ptime), FS_MINUTE(ptime), FS_SECOND(ptime));
    }
    entry.close();
  }
}
