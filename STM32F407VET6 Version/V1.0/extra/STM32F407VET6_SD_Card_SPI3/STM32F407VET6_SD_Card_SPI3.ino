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
https://github.com/pothos/arduino-n64-controller-library
https://github.com/ulwanski/sha512
*/
/*
https://www.mischianti.org/2022/10/24/how-to-use-sd-card-with-stm32-and-sdfat-library/
http://ardupiclab.blogspot.com/2021/08/how-to-use-sd-card-of-stm32f407vet6.html
https://github.com/stm32duino/Arduino_Core_STM32/wiki/API#spi
*/
#include <SPI.h>
#include <SD.h>


#define SD_MOSI PC12
#define SD_MISO PC11
#define SD_CLK PC10
#define SD_CS_PIN PC9
SPIClass SPI_3(SD_MOSI, SD_MISO, SD_CLK);
static SPIClass mySPI3(SD_MOSI, SD_MISO, SD_CLK, SD_CS_PIN);


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
  pinMode(PD2, INPUT_PULLUP);// SDIO pin
  pinMode(PC8, INPUT_PULLUP);// SDIO pin
  pinMode(PC12, INPUT_PULLUP);// SDIO pin
  SPI.setMOSI(SD_MOSI);
  SPI.setMISO(SD_MISO);
  SPI.setSCLK(SD_CLK);

  Serial.begin(115200);
  delay(5000);
 
  Serial.print("\nInitializing SD card...");
 
  // we'll use the initialization code from the utility libraries
  // since we're just testing if the card is working!
  if (!SD.begin(SD_CS_PIN)) {
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
 
}
 
void loop(void) {
}
