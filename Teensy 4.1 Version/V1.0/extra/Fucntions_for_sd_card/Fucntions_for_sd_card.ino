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
https://github.com/adafruit/Adafruit_ILI9341
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/intrbiz/arduino-crypto
https://github.com/GyverLibs/EncButton
*/
/*
  SD card basic file example
 
 This example shows how to create and destroy an SD card file 	
 The circuit:
 * SD card attached to SPI bus as follows:
 ** MOSI - pin 11, pin 7 on Teensy with audio board
 ** MISO - pin 12
 ** CLK - pin 13, pin 14 on Teensy with audio board
 ** CS - pin 4, pin 10 on Teensy with audio board
 
 created   Nov 2010
 by David A. Mellis
 modified 9 Apr 2012
 by Tom Igoe
 
 This example code is in the public domain.
 	 
 */
#include <SD.h>
#include <SPI.h>

const int chipSelect = BUILTIN_SDCARD;

void write_to_file_with_overwrite(String filename, String content) {
  int filename_len = filename.length() + 1;
  char filename_array[filename_len];
  filename.toCharArray(filename_array, filename_len);
  SD.remove(filename_array);
  File testFile = SD.open(filename_array, FILE_WRITE);
  if (testFile) {
    //Serial.println("Write file content!");
    testFile.print(content);

    testFile.close();
  } else {
    //Serial.println("Problem on create file!");
  }
}

String read_file(String filename) {
  int filename_len = filename.length() + 1;
  char filename_array[filename_len];
  filename.toCharArray(filename_array, filename_len);
  File testFile = SD.open(filename_array, "r");
  String file_content;
  if (testFile) {
    //Serial.println("Read file content!");
    file_content = testFile.readString();
    //Serial.println(testFile.readString());
    testFile.close();
  } else {
    //Serial.println("Problem on read file!");
    file_content = "-1";
  }
  return file_content;
}

void delete_file(String filename){
   int filename_len = filename.length() + 1;
   char filename_array[filename_len];
   filename.toCharArray(filename_array, filename_len);
   SD.remove(filename_array);
}

void setup()
{
 //UNCOMMENT THESE TWO LINES FOR TEENSY AUDIO BOARD:
 //SPI.setMOSI(7);  // Audio shield has MOSI on pin 7
 //SPI.setSCK(14);  // Audio shield has SCK on pin 14
  
 // Open serial communications and wait for port to open:
  Serial.begin(115200);
   while (!Serial) {
    ; // wait for serial port to connect.
  }


  Serial.print("Initializing SD card...");

  if (!SD.begin(chipSelect)) {
    Serial.println("initialization failed!");
    return;
  }
  Serial.println("initialization done.");

  Serial.println("No file");
  delete_file("f");
  Serial.println(read_file("f"));
  Serial.println("Create file");
  write_to_file_with_overwrite("f", "Some content");
  Serial.println("Read file");
  Serial.println(read_file("f"));
}

void loop()
{
  // nothing happens after setup finishes.
}
