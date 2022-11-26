/*
Midbar
Distributed under the MIT License
© Copyright Maxim Bortnikov 2022
For more information please visit
https://sourceforge.net/projects/midbar/
https://osdn.net/projects/midbar/
https://github.com/Northstrix/Midbar
Required libraries:
https://github.com/zhouyangchao/AES
https://github.com/peterferrie/serpent
https://github.com/ddokkaebi/Blowfish
https://github.com/ulwanski/sha512
https://github.com/adafruit/Adafruit_SSD1306
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/intrbiz/arduino-crypto
https://github.com/Northstrix/DES_and_3DES_Library_for_MCUs
https://github.com/GyverLibs/EncButton
*/
#include <SPI.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

Adafruit_SSD1306 display(128, 64, &Wire);

#include <EncButton2.h>
EncButton2<EB_ENC> enc0(INPUT, D5, D6);
EncButton2<EB_BTN> a_button(INPUT, D0);
EncButton2<EB_BTN> b_button(INPUT, D3);
int curr_key;
String encoder_input;

void setup(void){
  curr_key = 65;
  Serial.begin(115200);
  display.begin(SSD1306_SWITCHCAPVCC, 0x3C);
  display.clearDisplay();
  disp();
}

void disp(){
  display.clearDisplay();
  //display.fillRect(0, 0, 128, 16, WHITE);
  display.setTextSize(2);
  display.setTextColor(WHITE);
  display.setCursor(2,0);
  display.print("Char'");
  display.print(char(curr_key));
  display.print("' ");
  display.setCursor(104,0);
  String hexstr;
  if (curr_key < 16)
    hexstr += 0;
  hexstr +=  String(curr_key, HEX);
  hexstr.toUpperCase();
  display.print(hexstr);
  display.display();

}

void loop(){
  enc0.tick();
  if (enc0.left()){
    curr_key--;
    disp();
  }
  if (enc0.right()){
    curr_key++;
    disp();
  }
    
  if(curr_key < 32)
    curr_key = 126;
   
  if(curr_key > 126)
    curr_key = 32;

  if (enc0.turn()) {
    //Serial.println(char(curr_key));
    disp();
  }
  a_button.tick();
  if (a_button.press()){
    encoder_input += char(curr_key);
    Serial.println(encoder_input);
    disp();
  }
  b_button.tick();
  if (b_button.press()){
    if(encoder_input.length() > 0)
      encoder_input.remove(encoder_input.length() -1, 1);
    Serial.println(encoder_input);
    disp();
  }
}
