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
https://github.com/Bodmer/TFT_eSPI
https://github.com/miguelbalboa/rfid
https://github.com/intrbiz/arduino-crypto
https://github.com/GyverLibs/EncButton
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/techpaul/PS2KeyMap
https://github.com/adafruit/SdFat
*/
#include <PS2KeyAdvanced.h>

/* Keyboard constants  Change to suit your Arduino
   define pins used for data and clock from keyboard */
#define DATAPIN PB5
#define IRQPIN PB6
#define CHOOSE_ARD_MODE_PIN PA15

uint16_t c;
String keyboard_input;

PS2KeyAdvanced arduino;

void setup() {
  // Configure the keyboard library
  arduino.begin(DATAPIN, IRQPIN);
  Serial.begin(115200);
  Serial.println("PS2 Advanced Key Simple Test:");
  pinMode(CHOOSE_ARD_MODE_PIN, OUTPUT);
  digitalWrite(CHOOSE_ARD_MODE_PIN, HIGH);
}

void loop() {
  if (arduino.available()) {
    // read the next key
    c = arduino.read();
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
