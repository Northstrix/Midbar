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
#include <Adafruit_GFX.h>
#include <Adafruit_ST7735.h>
#include "custom_hebrew_font.h"
#include <NintendoExtensionCtrl.h>
#define TFT_CS1         D3
#define TFT_RST1        D6
#define TFT_DC1         D4
Adafruit_ST7735 tft = Adafruit_ST7735(TFT_CS1, TFT_DC1, TFT_RST1);

Nunchuk wii_nunchuk;

#define letter_spacing_pxls 6
#define regular_shift_down 16
#define shift_down_for_mem 12

bool pressed_c;
bool pressed_z;
bool held_left;
bool held_up;
bool held_right;
bool held_down;
bool c_functions_as_enter = true;
uint16_t colors[4] = { // Purple, Yellow, Green, Blue
  0xb81c, 0xfde0, 0x87a0, 0x041c
};
uint16_t current_inact_clr = 0x041c;
byte threshold = 24;
byte sdown = 36;
int curr_pos = 0;

int get_offset(String text_to_print){
  int shift_right = 160;
  for (int s = 0; s < text_to_print.length(); s++){ // Traverse the string

    if (text_to_print.charAt(s) == 'b'){ // Bet
      shift_right -= sizeof(Bet)/sizeof(Bet[0]);
      shift_right -= letter_spacing_pxls;
    }

    if (text_to_print.charAt(s) == 'd'){ // Dalet
      shift_right -= sizeof(Dalet)/sizeof(Dalet[0]);
      shift_right -= letter_spacing_pxls;
    }

    if (text_to_print.charAt(s) == 'M'){ // Mem
      shift_right -= sizeof(Mem)/sizeof(Mem[0]);
      shift_right -= letter_spacing_pxls;
    }

    if (text_to_print.charAt(s) == 'r'){ // Resh
      shift_right -= sizeof(Resh)/sizeof(Resh[0]);
      shift_right -= letter_spacing_pxls;
    }

  }
  shift_right += letter_spacing_pxls;
  return shift_right / 2;
}

void print_centered_custom_hebrew_font(String text_to_print, int y, uint16_t font_colors[], int how_many_colors){
  print_custom_multi_colored_hebrew_font(text_to_print, y, get_offset(text_to_print), font_colors, how_many_colors);
}

void print_custom_multi_colored_hebrew_font(String text_to_print, int y, int offset_from_the_right, uint16_t font_colors[], int how_many_colors){
  int shift_right = 160 - offset_from_the_right;
  for (int s = 0; s < text_to_print.length(); s++){ // Traverse the string

    if (text_to_print.charAt(s) == 'b'){ // Bet
      shift_right -= sizeof(Bet)/sizeof(Bet[0]);
      for (int i = 0; i < 22; i++) {
        for (int j = 0; j < 24; j++) {
          if (Bet[i][j] == 0)
            tft.drawPixel(i + shift_right, j + y + regular_shift_down, font_colors[s % how_many_colors]);
        }
      }
      shift_right -= letter_spacing_pxls;
    }

    if (text_to_print.charAt(s) == 'd'){ // Dalet
      shift_right -= sizeof(Dalet)/sizeof(Dalet[0]);
      for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 24; j++) {
          if (Dalet[i][j] == 0)
            tft.drawPixel(i + shift_right, j + y + regular_shift_down, font_colors[s % how_many_colors]);
        }
      }
      shift_right -= letter_spacing_pxls;
    }

    if (text_to_print.charAt(s) == 'M'){ // Mem
      shift_right -= sizeof(Mem)/sizeof(Mem[0]);
      for (int i = 0; i < 18; i++) {
        for (int j = 0; j < 29; j++) {
          if (Mem[i][j] == 0)
            tft.drawPixel(i + shift_right, j + y + shift_down_for_mem, font_colors[s % how_many_colors]);
        }
      }
      shift_right -= letter_spacing_pxls;
    }

    if (text_to_print.charAt(s) == 'r'){ // Resh
      shift_right -= sizeof(Resh)/sizeof(Resh[0]);
      for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 24; j++) {
          if (Resh[i][j] == 0)
            tft.drawPixel(i + shift_right, j + y + regular_shift_down, font_colors[s % how_many_colors]);
        }
      }
      shift_right -= letter_spacing_pxls;
    }
  }
}

void disp_centered_text(String t_disp, int y){
   int16_t x1, y1;
   uint16_t w, h;
   tft.getTextBounds(t_disp, 160, 0, &x1, &y1, &w, &h);
   tft.setCursor(80 - (w / 2), y);
   tft.print(t_disp);
}

byte get_nunchuk_input() {
  /*
   * 0 - Nothing
   * 1 - Enter
   * 2 - Esc/Return
   * 3 - Right
   * 4 - Left
   * 5 - Up
   * 6 - Down
   */
  byte obtained_data = 0;
  boolean success = wii_nunchuk.update();  // Get new data from the controller

  if (!success) {
    delay(12);
  }
  else {
    if (wii_nunchuk.buttonC() == true){
      if (pressed_c == false){
        if (c_functions_as_enter == true){
          obtained_data = 1;
        }
        else{
          obtained_data = 2;
        }
      }
      pressed_c = true;
    }
    else{
      pressed_c = false;
    }

    if (wii_nunchuk.buttonZ() == true){
      if (pressed_z == false){
        if (c_functions_as_enter == true){
          obtained_data = 2;
        }
        else{
          obtained_data = 1;
        }
      }
      pressed_z = true;
    }
    else{
      pressed_z = false;
    }

    byte XAxis = wii_nunchuk.joyX();
    byte YAxis = wii_nunchuk.joyY();

    if (XAxis > (255 - threshold)){
      if (held_right == false){
        obtained_data = 3;
      }
      held_right = true;
    }
    else{
      held_right = false;
    }

    if (XAxis < threshold){
      if (held_left == false){
        obtained_data = 4;
      }
      held_left = true;
    }
    else{
      held_left = false;
    }

    if (YAxis > (255 - threshold)){
      if (held_up == false){
        obtained_data = 5;
      }
      held_up = true;
    }
    else{
      held_up = false;
    }

    if (YAxis < threshold){
      if (held_down == false){
        obtained_data = 6;
      }
      held_down = true;
    }
    else{
      held_down = false;
    }
  }
  delayMicroseconds(1200);
  return obtained_data;
}

void main_menu() {
  tft.setTextSize(1);
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("Logins", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Credit Cards", sdown + 20);
    disp_centered_text("Notes", sdown + 30);
    disp_centered_text("Phone Numbers", sdown + 40);
    disp_centered_text("Encryption Algorithms", sdown + 50);
    disp_centered_text("Hash Functions", sdown + 60);
    disp_centered_text("Factory Reset", sdown + 70);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Credit Cards", sdown + 20);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Notes", sdown + 30);
    disp_centered_text("Phone Numbers", sdown + 40);
    disp_centered_text("Encryption Algorithms", sdown + 50);
    disp_centered_text("Hash Functions", sdown + 60);
    disp_centered_text("Factory Reset", sdown + 70);
  }
  if (curr_pos == 2) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    disp_centered_text("Credit Cards", sdown + 20);
    tft.setTextColor(0xffff);
    disp_centered_text("Notes", sdown + 30);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Phone Numbers", sdown + 40);
    disp_centered_text("Encryption Algorithms", sdown + 50);
    disp_centered_text("Hash Functions", sdown + 60);
    disp_centered_text("Factory Reset", sdown + 70);
  }
  if (curr_pos == 3) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    disp_centered_text("Credit Cards", sdown + 20);
    disp_centered_text("Notes", sdown + 30);
    tft.setTextColor(0xffff);
    disp_centered_text("Phone Numbers", sdown + 40);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Encryption Algorithms", sdown + 50);
    disp_centered_text("Hash Functions", sdown + 60);
    disp_centered_text("Factory Reset", sdown + 70);
  }
  if (curr_pos == 4) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    disp_centered_text("Credit Cards", sdown + 20);
    disp_centered_text("Notes", sdown + 30);
    disp_centered_text("Phone Numbers", sdown + 40);
    tft.setTextColor(0xffff);
    disp_centered_text("Encryption Algorithms", sdown + 50);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Hash Functions", sdown + 60);
    disp_centered_text("Factory Reset", sdown + 70);
  }
  if (curr_pos == 5) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    disp_centered_text("Credit Cards", sdown + 20);
    disp_centered_text("Notes", sdown + 30);
    disp_centered_text("Phone Numbers", sdown + 40);
    disp_centered_text("Encryption Algorithms", sdown + 50);
    tft.setTextColor(0xffff);
    disp_centered_text("Hash Functions", sdown + 60);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Factory Reset", sdown + 70);
  }
  if (curr_pos == 6) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    disp_centered_text("Credit Cards", sdown + 20);
    disp_centered_text("Notes", sdown + 30);
    disp_centered_text("Phone Numbers", sdown + 40);
    disp_centered_text("Encryption Algorithms", sdown + 50);
    disp_centered_text("Hash Functions", sdown + 60);
    tft.setTextColor(0xffff);
    disp_centered_text("Factory Reset", sdown + 70);
  }
}

void call_main_menu(){
  tft.setRotation(1);
  tft.fillScreen(0x0000);
  print_centered_custom_hebrew_font("Mdbr", -8, colors, 4);
  curr_pos = 0;
  main_menu();
}

void press_any_key_to_continue() {
  bool break_the_loop = false;
  while (break_the_loop == false) {
    byte input_data = get_nunchuk_input();
    if (input_data == 1 || input_data == 2){
      break_the_loop = true;
    }
    delay(24);
  }
}

void setup() {
  tft.initR(INITR_BLACKTAB);
  tft.setRotation(1);
  tft.fillScreen(0x0000);
  wii_nunchuk.begin();
  Serial.begin(115200);
  print_centered_custom_hebrew_font("Mdbr", -8, colors, 4);
  while (!wii_nunchuk.connect()) {
    Serial.println("Nunchuk not detected!");
    tft.fillRect(0, 120, 168, 8, 0x0000);
    disp_centered_text("Connect Nunchuk", 120);
    delay(24);
  }
  delay(100);
  tft.fillRect(0, 120, 168, 8, 0x0000);
  disp_centered_text("Press Any Button", 120);
  press_any_key_to_continue();
  delay(100);
  call_main_menu();
}

void loop() {
  byte input_data = get_nunchuk_input();

  if (input_data == 1){ //Enter
    if (curr_pos == 0){
      Serial.println("Logins");
    }
    if (curr_pos == 1){
      Serial.println("Credit Cards");
    }
    if (curr_pos == 2){
      Serial.println("Notes");
    }
    if (curr_pos == 3){
      Serial.println("Phone Numbers");
    }
    if (curr_pos == 4){
      Serial.println("Encryption Algorithms");
    }
    if (curr_pos == 5){
      Serial.println("Hash Functions");
    }
    if (curr_pos == 6){
      Serial.println("Factory Reset");
    }
  }

  if (input_data == 3 || input_data == 6){
    curr_pos++;
    if (curr_pos > 6)
      curr_pos = 0;
    main_menu();
  }

  if (input_data == 4 || input_data == 5){
    curr_pos--;
    if (curr_pos < 0)
      curr_pos = 6;
     main_menu();
  }
}
