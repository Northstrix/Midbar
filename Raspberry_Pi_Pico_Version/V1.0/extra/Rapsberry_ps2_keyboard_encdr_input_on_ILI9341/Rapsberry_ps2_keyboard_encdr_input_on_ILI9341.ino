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
/*  Simple keyboard to serial port at 115200 baud

  PS2KeyAdvanced library example

  Advanced support PS2 Keyboard to get every key code byte from a PS2 Keyboard
  for testing purposes.

  IMPORTANT WARNING

    If using a DUE or similar board with 3V3 I/O you MUST put a level translator
    like a Texas Instruments TXS0102 or FET circuit as the signals are
    Bi-directional (signals transmitted from both ends on same wire).

    Failure to do so may damage your Arduino Due or similar board.

  Test History
    September 2014 Uno and Mega 2560 September 2014 using Arduino V1.6.0
    January 2016   Uno, Mega 2560 and Due using Arduino 1.6.7 and Due Board
                    Manager V1.6.6

  This is for a LATIN style keyboard using Scan code set 2. See various
  websites on what different scan code sets use. Scan Code Set 2 is the
  default scan code set for PS2 keyboards on power up.

  Will support most keyboards even ones with multimedia keys or even 24 function keys.

  The circuit:
   * KBD Clock (PS2 pin 1) to an interrupt pin on Arduino ( this example pin 3 )
   * KBD Data (PS2 pin 5) to a data pin ( this example pin 4 )
   * +5V from Arduino to PS2 pin 4
   * GND from Arduino to PS2 pin 3

   The connector to mate with PS2 keyboard is a 6 pin Female Mini-Din connector
   PS2 Pins to signal
    1       KBD Data
    3       GND
    4       +5V
    5       KBD Clock

   Keyboard has 5V and GND connected see plenty of examples and
   photos around on Arduino site and other sites about the PS2 Connector.

 Interrupts

   Clock pin from PS2 keyboard MUST be connected to an interrupt
   pin, these vary with the different types of Arduino

  PS2KeyAdvanced requires both pins specified for begin()

    keyboard.begin( data_pin, irq_pin );

  Valid irq pins:
     Arduino Uno:  2, 3
     Arduino Due:  All pins, except 13 (LED)
     Arduino Mega: 2, 3, 18, 19, 20, 21
     Teensy 2.0:   All pins, except 13 (LED)
     Teensy 2.0:   5, 6, 7, 8
     Teensy 1.0:   0, 1, 2, 3, 4, 6, 7, 16
     Teensy++ 2.0: 0, 1, 2, 3, 18, 19, 36, 37
     Teensy++ 1.0: 0, 1, 2, 3, 18, 19, 36, 37
     Sanguino:     2, 10, 11

  Read method Returns an UNSIGNED INT containing
        Make/Break status
        Caps status
        Shift, CTRL, ALT, ALT GR, GUI keys
        Flag for function key not a displayable/printable character
        8 bit key code

  Code Ranges (bottom byte of unsigned int)
        0       invalid/error
        1-1F    Functions (Caps, Shift, ALT, Enter, DEL... )
        1A-1F   Functions with ASCII control code
                    (DEL, BS, TAB, ESC, ENTER, SPACE)
        20-61   Printable characters noting
                    0-9 = 0x30 to 0x39 as ASCII
                    A to Z = 0x41 to 0x5A as upper case ASCII type codes
                    8B Extra European key
        61-A0   Function keys and other special keys (plus F2 and F1)
                    61-78 F1 to F24
                    79-8A Multimedia
                    8B NOT included
                    8C-8E ACPI power
                    91-A0 and F2 and F1 - Special multilingual
        A8-FF   Keyboard communications commands (note F2 and F1 are special
                codes for special multi-lingual keyboards)

    By using these ranges it is possible to perform detection of any key and do
    easy translation to ASCII/UTF-8 avoiding keys that do not have a valid code.

    Top Byte is 8 bits denoting as follows with defines for bit code

        Define name bit     description
        PS2_BREAK   15      1 = Break key code
                   (MSB)    0 = Make Key code
        PS2_SHIFT   14      1 = Shift key pressed as well (either side)
                            0 = NO shift key
        PS2_CTRL    13      1 = Ctrl key pressed as well (either side)
                            0 = NO Ctrl key
        PS2_CAPS    12      1 = Caps Lock ON
                            0 = Caps lock OFF
        PS2_ALT     11      1 = Left Alt key pressed as well
                            0 = NO Left Alt key
        PS2_ALT_GR  10      1 = Right Alt (Alt GR) key pressed as well
                            0 = NO Right Alt key
        PS2_GUI      9      1 = GUI key pressed as well (either)
                            0 = NO GUI key
        PS2_FUNCTION 8      1 = FUNCTION key non-printable character (plus space, tab, enter)
                            0 = standard character key

  Error Codes
     Most functions return 0 or 0xFFFF as error, other codes to note and
     handle appropriately
        0xAA   keyboard has reset and passed power up tests
               will happen if keyboard plugged in after code start
        0xFC   Keyboard General error or power up fail

  See PS2Keyboard.h file for returned definitions of Keys

  Note defines starting
            PS2_KEY_* are the codes this library returns
            PS2_*     remaining defines for use in higher levels

  To get the key as ASCII/UTF-8 single byte character conversion requires use
  of PS2KeyMap library AS WELL.

  Written by Paul Carpenter, PC Services <sales@pcserviceselectronics.co.uk>
*/

#include <PS2KeyAdvanced.h>

#include <EncButton2.h>

/* Keyboard constants  Change to suit your Arduino
   define pins used for data and clock from keyboard */
#define DATAPIN 14
#define IRQPIN 15

#include <Arduino_GFX_Library.h>

#define GFX_BL DF_GFX_BL // default backlight pin, you may replace DF_GFX_BL to actual backlight pin

/* More dev device declaration: https://github.com/moononournation/Arduino_GFX/wiki/Dev-Device-Declaration */
#if defined(DISPLAY_DEV_KIT)
Arduino_GFX * gfx = create_default_Arduino_GFX();
#else /* !defined(DISPLAY_DEV_KIT) */

/* More data bus class: https://github.com/moononournation/Arduino_GFX/wiki/Data-Bus-Class */
Arduino_DataBus * bus = create_default_Arduino_DataBus();

/* More display class: https://github.com/moononournation/Arduino_GFX/wiki/Display-Class */
Arduino_GFX * gfx = new Arduino_ILI9341(bus, DF_GFX_RST, 0 /* rotation */ , false /* IPS */ );

#endif /* !defined(DISPLAY_DEV_KIT) */
/*******************************************************************************
 * End of Arduino_GFX setting
 ******************************************************************************/

/* more fonts at: https://github.com/moononournation/ArduinoFreeFontFile.git */

uint16_t c;
String keyboard_input;
int curr_key;
const uint16_t current_inact_clr = 0x051b;
bool finish_input;
bool act;

EncButton2 < EB_ENC > enc0(INPUT, 12, 13);
EncButton2 < EB_BTN > encoder_button(INPUT, 9);
EncButton2 < EB_BTN > a_button(INPUT, 11);
EncButton2 < EB_BTN > b_button(INPUT, 10);

PS2KeyAdvanced keyboard;

void set_stuff_for_input(String blue_inscr) {
  curr_key = 65;
  gfx -> fillScreen(0x0000);
  gfx -> setTextSize(2);
  gfx -> setTextColor(0xffff);
  gfx -> setCursor(2, 0);
  gfx -> print("Char'");
  gfx -> setCursor(74, 0);
  gfx -> print("'");
  disp();
  gfx -> setCursor(0, 24);
  gfx -> setTextSize(2);
  gfx -> setTextColor(current_inact_clr);
  gfx -> print(blue_inscr);
  gfx -> fillRect(312, 0, 8, 240, current_inact_clr);
  gfx -> setTextColor(0x07e0);
  gfx -> setCursor(216, 0);
  gfx -> print("ASCII:");
}

void check_bounds_and_change_char(){
  if (curr_key < 32)
    curr_key = 126;
  
  if (curr_key > 126)
    curr_key = 32;
  curr_key = keyboard_input.charAt(keyboard_input.length() - 1);
}

void disp() {
  //gfx->fillScreen(0x0000);
  gfx -> setTextSize(2);
  gfx -> setTextColor(0xffff);
  gfx -> fillRect(62, 0, 10, 16, 0x0000);
  gfx -> setCursor(62, 0);
  gfx -> print(char(curr_key));
  gfx -> fillRect(288, 0, 22, 14, 0x0000);
  gfx -> setCursor(288, 0);
  String hexstr;
  if (curr_key < 16)
    hexstr += 0;
  hexstr += String(curr_key, HEX);
  hexstr.toUpperCase();
  gfx -> setTextColor(0x07e0);
  gfx -> print(hexstr);
  gfx -> setTextColor(0xffff);
  gfx -> setTextSize(2);
  gfx -> setCursor(0, 48);
  gfx -> print(keyboard_input);
}

void disp_stars() {
  //gfx->fillScreen(0x0000);
  gfx -> setTextSize(2);
  gfx -> setTextColor(0xffff);
  gfx -> fillRect(62, 0, 10, 16, 0x0000);
  gfx -> setCursor(62, 0);
  gfx -> print(char(curr_key));
  gfx -> fillRect(288, 0, 22, 14, 0x0000);
  gfx -> setCursor(288, 0);
  String hexstr;
  if (curr_key < 16)
    hexstr += 0;
  hexstr += String(curr_key, HEX);
  hexstr.toUpperCase();
  gfx -> setTextColor(0x07e0);
  gfx -> print(hexstr);
  int plnt = keyboard_input.length();
  String stars = "";
  for (int i = 0; i < plnt; i++) {
    stars += "*";
  }
  gfx -> setTextColor(0xffff);
  gfx -> setTextSize(2);
  gfx -> setCursor(0, 48);
  gfx -> print(stars);
}

void encdr_and_keyb_input() {
  finish_input = false;
  while (finish_input == false) {
    enc0.tick();
    if (enc0.left()) {
      curr_key--;
      disp();
    }
    if (enc0.right()) {
      curr_key++;
      disp();
    }

    if (curr_key < 32)
      curr_key = 126;

    if (curr_key > 126)
      curr_key = 32;

    if (enc0.turn()) {
      //Serial.println(char(curr_key));
      disp();
    }
    delayMicroseconds(400);

    a_button.tick();
    if (a_button.press()) {
      keyboard_input += char(curr_key);
      //Serial.println(keyboard_input);
      disp();
    }
    delayMicroseconds(400);

    b_button.tick();
    if (b_button.press()) {
      if (keyboard_input.length() > 0)
        keyboard_input.remove(keyboard_input.length() - 1, 1);
      //Serial.println(keyboard_input);
      gfx -> fillRect(0, 48, 312, 192, 0x0000);
      //Serial.println(keyboard_input);
      disp();
    }
    delayMicroseconds(400);

    if (keyboard.available()) {
      // read the next key
      c = keyboard.read();
      if (c > 0 && ((c & 0xFF) != 6)) {
        /*
        if (c & PS2_BREAK) Serial.print("break ~ ");
        if (!(c & PS2_BREAK)) Serial.print("make  ~ ");
        Serial.print( "Value " );
        Serial.print( c, HEX );
        Serial.print( " - Status Bits " );
        Serial.print( c >> 8, HEX );
        Serial.print( "  Code " );
        Serial.println( c & 0xFF, HEX );
        if (!(c & PS2_BREAK))
          Serial.println(char(c & 0xFF));
        */

        if (c >> 8 == 192 && (c & PS2_BREAK)) {
          if ((c & 0xFF) > 64 && (c & 0xFF) < 91) // Capital letters
            keyboard_input += (char(c & 0xFF));

          if ((c & 0xFF) == 93)
            keyboard_input += ("{");

          if ((c & 0xFF) == 94)
            keyboard_input += ("}");

          if ((c & 0xFF) == 91)
            keyboard_input += (":");

          if ((c & 0xFF) == 58)
            keyboard_input += (char(34)); // "

          if ((c & 0xFF) == 92)
            keyboard_input += ("|");

          if ((c & 0xFF) == 59)
            keyboard_input += ("<");

          if ((c & 0xFF) == 61)
            keyboard_input += (">");

          if ((c & 0xFF) == 62)
            keyboard_input += ("?");

          if ((c & 0xFF) == 64)
            keyboard_input += ("~");

          if ((c & 0xFF) == 60)
            keyboard_input += ("_");

          if ((c & 0xFF) == 95)
            keyboard_input += ("+");

          if ((c & 0xFF) == 49)
            keyboard_input += ("!");

          if ((c & 0xFF) == 50)
            keyboard_input += ("@");

          if ((c & 0xFF) == 51)
            keyboard_input += ("#");

          if ((c & 0xFF) == 52)
            keyboard_input += ("$");

          if ((c & 0xFF) == 53)
            keyboard_input += ("%");

          if ((c & 0xFF) == 54)
            keyboard_input += ("^");

          if ((c & 0xFF) == 55)
            keyboard_input += ("&");

          if ((c & 0xFF) == 56)
            keyboard_input += ("*");

          if ((c & 0xFF) == 57)
            keyboard_input += ("(");

          if ((c & 0xFF) == 48)
            keyboard_input += (")");

          check_bounds_and_change_char();
          disp();

        }
        if (c >> 8 == 129 && (c & PS2_BREAK)) {

          if ((c & 0xFF) == 30) { // Enter
            //Serial.println(keyboard_input);
            finish_input = true;
          }

          if ((c & 0xFF) == 27) {
            //Serial.println(keyboard_input);
            act = false;
            finish_input = true;
          }

          if (c == 33047)
            Serial.println("UP");

          if (c == 33046)
            curr_key++;

          if (c == 33048)
            Serial.println("DOWN");

          if (c == 33045)
            curr_key--;

          if (c == 33055)
            keyboard_input += (" "); // Space

          if (c == 33052) { // Backspace
            if (keyboard_input.length() > 0)
              keyboard_input.remove(keyboard_input.length() - 1, 1);
            //Serial.println(keyboard_input);
            gfx -> fillRect(0, 48, 312, 192, 0x0000);
          }
          
          check_bounds_and_change_char();
          disp();
        }
        if (c >> 8 == 128 && (c & PS2_BREAK)) {

          if ((c & 0xFF) > 47 && (c & 0xFF) < 58) // Digits
            keyboard_input += (char((c & 0xFF)));

          if ((c & 0xFF) > 64 && (c & 0xFF) < 91) // Lowercase letters
            keyboard_input += (char((c & 0xFF) + 32));

          if ((c & 0xFF) == 93)
            keyboard_input += ("[");

          if ((c & 0xFF) == 94)
            keyboard_input += ("]");

          if ((c & 0xFF) == 91)
            keyboard_input += (";");

          if ((c & 0xFF) == 58)
            keyboard_input += ("'");

          if ((c & 0xFF) == 92)
            keyboard_input += ("\\");

          if ((c & 0xFF) == 59)
            keyboard_input += (",");

          if ((c & 0xFF) == 61)
            keyboard_input += (".");

          if ((c & 0xFF) == 62)
            keyboard_input += ("/");

          if ((c & 0xFF) == 64)
            keyboard_input += ("`");

          if ((c & 0xFF) == 60)
            keyboard_input += ("-");

          if ((c & 0xFF) == 95)
            keyboard_input += ("=");

          check_bounds_and_change_char();
          disp();
        }
      }
    }

    delayMicroseconds(400);
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      //Serial.println(keyboard_input);
      finish_input = true;
    }
    if (encoder_button.hasClicks(5)) {
      //Serial.println(keyboard_input);
      act = false;
      finish_input = true;
    }
    delayMicroseconds(400);
  }
}

void star_encdr_and_keyb_input() {
  finish_input = false;
  while (finish_input == false) {
    enc0.tick();
    if (enc0.left()) {
      curr_key--;
      disp_stars();
    }
    if (enc0.right()) {
      curr_key++;
      disp_stars();
    }

    if (curr_key < 32)
      curr_key = 126;

    if (curr_key > 126)
      curr_key = 32;

    if (enc0.turn()) {
      //Serial.println(char(curr_key));
      disp_stars();
    }
    delayMicroseconds(400);

    a_button.tick();
    if (a_button.press()) {
      keyboard_input += char(curr_key);
      //Serial.println(keyboard_input);
      disp_stars();
    }
    delayMicroseconds(400);

    b_button.tick();
    if (b_button.press()) {
      if (keyboard_input.length() > 0)
        keyboard_input.remove(keyboard_input.length() - 1, 1);
      //Serial.println(keyboard_input);
      gfx -> fillRect(0, 48, 312, 192, 0x0000);
      //Serial.println(keyboard_input);
      disp_stars();
    }
    delayMicroseconds(400);

    if (keyboard.available()) {
      // read the next key
      c = keyboard.read();
      if (c > 0 && ((c & 0xFF) != 6)) {
        /*
        if (c & PS2_BREAK) Serial.print("break ~ ");
        if (!(c & PS2_BREAK)) Serial.print("make  ~ ");
        Serial.print( "Value " );
        Serial.print( c, HEX );
        Serial.print( " - Status Bits " );
        Serial.print( c >> 8, HEX );
        Serial.print( "  Code " );
        Serial.println( c & 0xFF, HEX );
        if (!(c & PS2_BREAK))
          Serial.println(char(c & 0xFF));
        */

        if (c >> 8 == 192 && (c & PS2_BREAK)) {
          if ((c & 0xFF) > 64 && (c & 0xFF) < 91) // Capital letters
            keyboard_input += (char(c & 0xFF));

          if ((c & 0xFF) == 93)
            keyboard_input += ("{");

          if ((c & 0xFF) == 94)
            keyboard_input += ("}");

          if ((c & 0xFF) == 91)
            keyboard_input += (":");

          if ((c & 0xFF) == 58)
            keyboard_input += (char(34)); // "

          if ((c & 0xFF) == 92)
            keyboard_input += ("|");

          if ((c & 0xFF) == 59)
            keyboard_input += ("<");

          if ((c & 0xFF) == 61)
            keyboard_input += (">");

          if ((c & 0xFF) == 62)
            keyboard_input += ("?");

          if ((c & 0xFF) == 64)
            keyboard_input += ("~");

          if ((c & 0xFF) == 60)
            keyboard_input += ("_");

          if ((c & 0xFF) == 95)
            keyboard_input += ("+");

          if ((c & 0xFF) == 49)
            keyboard_input += ("!");

          if ((c & 0xFF) == 50)
            keyboard_input += ("@");

          if ((c & 0xFF) == 51)
            keyboard_input += ("#");

          if ((c & 0xFF) == 52)
            keyboard_input += ("$");

          if ((c & 0xFF) == 53)
            keyboard_input += ("%");

          if ((c & 0xFF) == 54)
            keyboard_input += ("^");

          if ((c & 0xFF) == 55)
            keyboard_input += ("&");

          if ((c & 0xFF) == 56)
            keyboard_input += ("*");

          if ((c & 0xFF) == 57)
            keyboard_input += ("(");

          if ((c & 0xFF) == 48)
            keyboard_input += (")");

          check_bounds_and_change_char();
          disp_stars();

        }
        if (c >> 8 == 129 && (c & PS2_BREAK)) {

          if ((c & 0xFF) == 30) // Enter
            finish_input = true;

          if ((c & 0xFF) == 27)
            Serial.println("Escape");

          if (c == 33047)
            Serial.println("UP");

          if (c == 33046)
            curr_key++;

          if (c == 33048)
            Serial.println("DOWN");

          if (c == 33045)
            curr_key--;

          if (c == 33055)
            keyboard_input += (" "); // Space

          if (c == 33052) { // Backspace
            if (keyboard_input.length() > 0)
              keyboard_input.remove(keyboard_input.length() - 1, 1);
            //Serial.println(keyboard_input);
            gfx -> fillRect(0, 48, 312, 192, 0x0000);
          }

          check_bounds_and_change_char();
          disp_stars();
        }
        if (c >> 8 == 128 && (c & PS2_BREAK)) {

          if ((c & 0xFF) > 47 && (c & 0xFF) < 58) // Digits
            keyboard_input += (char((c & 0xFF)));

          if ((c & 0xFF) > 64 && (c & 0xFF) < 91) // Lowercase letters
            keyboard_input += (char((c & 0xFF) + 32));

          if ((c & 0xFF) == 93)
            keyboard_input += ("[");

          if ((c & 0xFF) == 94)
            keyboard_input += ("]");

          if ((c & 0xFF) == 91)
            keyboard_input += (";");

          if ((c & 0xFF) == 58)
            keyboard_input += ("'");

          if ((c & 0xFF) == 92)
            keyboard_input += ("\\");

          if ((c & 0xFF) == 59)
            keyboard_input += (",");

          if ((c & 0xFF) == 61)
            keyboard_input += (".");

          if ((c & 0xFF) == 62)
            keyboard_input += ("/");

          if ((c & 0xFF) == 64)
            keyboard_input += ("`");

          if ((c & 0xFF) == 60)
            keyboard_input += ("-");

          if ((c & 0xFF) == 95)
            keyboard_input += ("=");

          check_bounds_and_change_char();
          disp_stars();

        }
      }
    }
    delayMicroseconds(400);
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      //Serial.println(keyboard_input);
      finish_input = true;
    }
    delayMicroseconds(400);
  }
}

void setup() {
  gfx -> begin();
  gfx -> fillScreen(BLACK);
  gfx -> setRotation(1);
  keyboard.begin(DATAPIN, IRQPIN);
  Serial.begin(115200);
  Serial.println("Input Test:");
}

void loop() {
  act = true;
  //clear_variables();
  keyboard_input = "";
  gfx -> fillScreen(0x0000);
  gfx -> setTextColor(0xffff);
  gfx -> setCursor(0, 20);
  gfx -> setTextSize(1);
  set_stuff_for_input("Enter string:");
  encdr_and_keyb_input();
  if (act == true) {
    Serial.println("Continue");
    Serial.println(keyboard_input);
    gfx -> fillScreen(0x0000);
    gfx -> setTextColor(0xffff);
    gfx -> setCursor(0, 0);
    gfx -> setTextSize(2);
    gfx -> print("Contnue with \"");
    gfx -> print(keyboard_input);
    gfx -> print("\"");
    delay(2500);
  }
  else{
    Serial.println("Cancel");
    Serial.println(keyboard_input);
    gfx -> fillScreen(0x0000);
    gfx -> setTextColor(0xffff);
    gfx -> setCursor(0, 0);
    gfx -> setTextSize(2);
    gfx -> print("Cancel (input) \"");
    gfx -> print(keyboard_input);
    gfx -> print("\"");
    delay(2500);
  }
}
