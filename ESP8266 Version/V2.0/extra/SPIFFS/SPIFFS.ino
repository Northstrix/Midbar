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
https://github.com/dmadison/NintendoExtensionCtrl
https://github.com/adafruit/Adafruit-ST7735-Library
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/intrbiz/arduino-crypto
https://github.com/marvinroger/ESP8266TrueRandom
*/
#include "FS.h"

String read_file(fs::FS &fs, String path){
  File file = fs.open(path, "r");
  if(!file || file.isDirectory()){
    return "-1";
  }
  String fileContent;
  while(file.available()){
    fileContent+=String((char)file.read());
  }
  file.close();
  return fileContent;
}

void write_to_file_with_overwrite(fs::FS &fs, String path, String content){
  File file = fs.open(path, "w");
  if(!file){
    return;
  }
  file.print(content);
  file.close();
}

void delete_file(fs::FS &fs, String path){
  fs.remove(path);
}

void setup() {
  Serial.begin(115200);
   while (!Serial) {
    ; // wait for serial port to connect.
  }
  if(!SPIFFS.begin()){
    Serial.println("An Error has occurred while mounting SPIFFS");
    return;
  }
  Serial.println();
  write_to_file_with_overwrite(SPIFFS, "test", "That should work");
  Serial.println(read_file(SPIFFS, "test"));
  delete_file(SPIFFS, "test");
  Serial.println(read_file(SPIFFS, "test"));
}
 
void loop() {

}
