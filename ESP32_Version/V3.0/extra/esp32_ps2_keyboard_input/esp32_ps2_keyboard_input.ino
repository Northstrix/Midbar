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
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_ILI9341
https://github.com/adafruit/Adafruit_BusIO
https://github.com/GyverLibs/GyverBus
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/intrbiz/arduino-crypto
https://github.com/GyverLibs/EncButton
https://github.com/Chris--A/Keypad
https://github.com/platisd/nokia-5110-lcd-library
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

/* Keyboard constants  Change to suit your Arduino
   define pins used for data and clock from keyboard */
#define DATAPIN 14
#define IRQPIN 13

uint16_t c;
String keyboard_input;

PS2KeyAdvanced keyboard;

void setup() {
  // Configure the keyboard library
  keyboard.begin(DATAPIN, IRQPIN);
  Serial.begin(115200);
  Serial.println("PS2 Advanced Key Simple Test:");
}

void loop() {
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

      }
      if (c >> 8 == 129 && (c & PS2_BREAK)) {

        if ((c & 0xFF) == 30)
          Serial.println("Enter");

        if ((c & 0xFF) == 27)
          Serial.println("Escape");

        if (c == 33047)
          Serial.println("UP");

        if (c == 33046)
          Serial.println("RIGHT");

        if (c == 33048)
          Serial.println("DOWN");

        if (c == 33045)
          Serial.println("LEFT");
          
        if (c == 33053)
          Serial.println("TAB");

        if (c == 33055)
          keyboard_input += (" "); // Space

        if (c == 33052) { // Backspace
          if (keyboard_input.length() > 0)
            keyboard_input.remove(keyboard_input.length() - 1, 1);
        }
      }
      if (c >> 8 == 128 && (c & PS2_BREAK)) {

        if ((c & 0xFF) > 48 && (c & 0xFF) < 58) // Digits
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

      }
      Serial.println(keyboard_input);

    }
  }
}
