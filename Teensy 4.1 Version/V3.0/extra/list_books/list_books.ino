/*
Midbar
Distributed under the MIT License
© Copyright Maxim Bortnikov 2024
For more information please visit
https://sourceforge.net/projects/midbar/
https://github.com/Northstrix/Midbar
Required libraries:
https://github.com/zhouyangchao/AES
https://github.com/peterferrie/serpent
https://github.com/ddokkaebi/Blowfish
https://github.com/Northstrix/DES_and_3DES_Library_for_MCUs
https://github.com/ulwanski/sha512
https://github.com/adafruit/Adafruit-ST7735-Library
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/intrbiz/arduino-crypto
*/
/*
  SD card basic directory list example
 
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

// change this to match your SD shield or module;
// Teensy 2.0: pin 0
// Teensy++ 2.0: pin 20
// Wiz820+SD board: pin 4
// Teensy audio board: pin 10
// Teensy 3.5 & 3.6 & 4.1 on-board: BUILTIN_SDCARD
const int chipSelect = BUILTIN_SDCARD;

void setup()
{
  //Uncomment these lines for Teensy 3.x Audio Shield (Rev C)
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

  Serial.println();
  Serial.print("Number of books: ");
  Serial.println(file_count());
  printDirectory();
  
  read_book("/books/Enc Book");
}

void loop()
{
  // nothing happens after setup finishes.
}

void read_book(String filename) {
  int filename_len = filename.length() + 1;
  char filename_array[filename_len];
  filename.toCharArray(filename_array, filename_len);
  File chosenBook = SD.open(filename_array, "r");
  int n = 0;
  while (chosenBook.available()) {
    bool cnt = false;
    if (n != 0){
      /*
      while (1){
        if (digitalRead(16) == LOW){
          delay(270);
          if (digitalRead(16) == LOW){
            tft.fillScreen(0x3186);
            tft.setTextColor(0xce6a, 0x3186);
            tft.setCursor(0,0);
            break;
          }
        }
        if (digitalRead(5) == LOW){
          delay(270);
          if (digitalRead(5) == LOW){
            cls_b = true;
            break;
          }
        }
        delay(90);
      }
      */
    }
    //if (cls_b == true)
    //  break;
    String ct;
    for (int i = 0; i < 32; i++)
      ct += char(chosenBook.read());
    Serial.println(ct);
    delay(5);
    //int ct_len = ct.length() + 1;
    //char ct_array[ct_len];
    //ct.toCharArray(ct_array, ct_len);
    //split_for_dec_des_only(ct_array, ct_len, 0);
    n++;
  }
}

int file_count() {
  File dir = SD.open("/books");
  int file_c = 0;
   while(true) {
     File entry = dir.openNextFile();
     if (! entry) {
       //Serial.println("** no more files **");
       break;
     }
     if (entry.isDirectory()) {
     } else {
       file_c++;
     }
     entry.close();
   }
   return file_c ;
}

void printDirectory() {
  File dir = SD.open("/books");
   while(true) {
     File entry = dir.openNextFile();
     if (! entry) {
       //Serial.println("** no more files **");
       break;
     }
     if (entry.isDirectory()) {
     } else {
       Serial.println(entry.name());
     }
     entry.close();
   }
}
