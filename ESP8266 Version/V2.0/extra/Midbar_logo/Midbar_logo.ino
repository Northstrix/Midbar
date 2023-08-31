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
#define TFT_CS1         D3
#define TFT_RST1        D6
#define TFT_DC1         D4
Adafruit_ST7735 tft = Adafruit_ST7735(TFT_CS1, TFT_DC1, TFT_RST1);

#define letter_spacing_pxls 6
#define regular_shift_down 16
#define shift_down_for_mem 12

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

void setup() {
  tft.initR(INITR_BLACKTAB);
  tft.setRotation(1);
  tft.fillScreen(0x0000);
  uint16_t colors[4] = { // Purple, Yellow, Green, Blue
    0xb81c, 0xfde0, 0x87a0, 0x041c
  };
  print_centered_custom_hebrew_font("Mdbr", 30, colors, 4);
  disp_centered_text("Press Any Button", 120);
}

void loop() {
  // put your main code here, to run repeatedly:

}
