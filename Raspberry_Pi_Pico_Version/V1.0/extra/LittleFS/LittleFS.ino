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
/*
 *  Raspberry Pi Pico (or generic rp2040)
 *  LittleFS write, read and seek file
 *  by Mischianti Renzo <https://www.mischianti.org>
 *
 *  https://www.mischianti.org/
 *
 *  Taken from https://www.mischianti.org/2022/09/30/raspberry-pi-pico-and-rp2040-boards-integrated-littlefs-filesystem-2/
 */
#include "Arduino.h"
#include "LittleFS.h"

void write_to_file_with_overwrite(String filename, String content){
  LittleFS.remove(filename);
  File testFile = LittleFS.open(filename, "w");
  if (testFile){
    //Serial.println("Write file content!");
    testFile.print(content);
 
    testFile.close();
  }else{
    //Serial.println("Problem on create file!");
  }
}

String read_file(String filename){
  File testFile = LittleFS.open(filename, "r");
  String file_content;
  if (testFile){
    //Serial.println("Read file content!");
    file_content = testFile.readString();
    //Serial.println(testFile.readString());
    testFile.close();
  }else{
    //Serial.println("Problem on read file!");
    file_content = "-1";
  }
  return file_content;
}
 
void setup()
{
  Serial.begin(115200);
 
  while (!Serial) {delay(100);}
 
  Serial.println(F("Inizializing FS..."));
  if (LittleFS.begin()){
    Serial.println(F("done."));
  }else{
    Serial.println(F("fail."));
  }

  LittleFS.remove("/test");
  Serial.println("No file:");
  Serial.println(read_file("/test"));
  write_to_file_with_overwrite("/test", "1234567890-=");
  Serial.println("Read file:");
  Serial.println(read_file("/test"));
 
}
 
void loop()
{
 
}
