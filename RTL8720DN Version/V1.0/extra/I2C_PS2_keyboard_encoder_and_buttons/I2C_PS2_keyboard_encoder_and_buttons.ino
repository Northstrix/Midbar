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
https://github.com/ddokkaebi/Blowfish
https://github.com/intrbiz/arduino-crypto
https://github.com/GyverLibs/EncButton
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/techpaul/PS2KeyMap
*/
/*  international keyboard mapping example to serial port

    Example keyboard on Arduino to Serial port using baud of 115,200

    PS2KeyMap extension library for PS2KeyAdvanced library, 
    Key mapping to ASCII/UTF-8 mapping and International Keyboard
    Layout Example.
 
  IMPORTANT WARNING
 
    If using a DUE or similar board with 3V3 I/O you MUST put a level translator 
    like a Texas Instruments TXS0102 or FET circuit as the signals are 
    Bi-directional (signals transmitted from both ends on same wire).
 
    Failure to do so may damage your Arduino Due or similar board.

  Test History
    September 2014 Uno and Mega 2560 September 2014 using Arduino V1.6.0
    January 2016   Uno, Mega 2560 and Due using Arduino 1.6.7 and Due Board 
                    Manager V1.6.6
    March 2020  Extend for Italian and Spanish keyboards

  PS2KeyMap uses a default US-ASCII Map but different country 
  mappings can be selected on the fly

  Map to the keyboard you want when running by typing
  
    U for US keyboard
    G for UK keyboard
    D for German keyboard
    F for French keyboard
    I for Italian keyboard
    E for Spanish keyboard

  Defaults to US on start up

  The circuit:
   * KBD Clock (PS2 pin 1) to an interrupt pin on Arduino ( this example pin 3 )
   * KBD Data (PS2 pin 5) to a data pin ( this example pin 4 )
   * +5V from Arduino to PS2 pin 1
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

   For PS2KeyAdvanced you pass this info into begin()

     keyboard.begin( DATAPIN, IRQPIN );

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

  Like the Original library and example this is under LGPL license.

  Written by Paul Carpenter, PC Services <sales@pcserviceselectronics.co.uk>
*/

#include <PS2KeyAdvanced.h>
 // Include all mappings
#include <PS2KeyMap.h>

#include <Wire.h>

#include <EncButton2.h>

EncButton2 < EB_ENC > enc0(INPUT, 11, 10);
EncButton2 < EB_BTN > encoder_button(INPUT, 9);
EncButton2 < EB_BTN > a_button(INPUT, 8);
EncButton2 < EB_BTN > b_button(INPUT, 7);

#define DATAPIN 2
#define IRQPIN 3

PS2KeyAdvanced keyboard;
PS2KeyMap keymap;

uint16_t code;
uint8_t found;

void send_data_over_i2c(byte x) {
  Wire.beginTransmission(13);
  Wire.write(x);
  Wire.endTransmission();
  delay(4);
}

void setup() {
  //Serial.begin( 115200 );
  // Start keyboard setup while outputting
  keyboard.begin(DATAPIN, IRQPIN);
  // Disable Break codes (key release) from PS2KeyAdvanced
  keyboard.setNoBreak(1);
  // and set no repeat on CTRL, ALT, SHIFT, GUI while outputting
  keyboard.setNoRepeat(1);
  keymap.selectMap((char * )
    "US");
  Wire.begin(); // join i2c bus (address optional for master)
}

void loop() {
  code = keyboard.available();
  if (code > 0) {
    code = keyboard.read();
    //Serial.print( "Value " );
    //Serial.print( code, HEX );
    if (code == 277) {
      //Serial.println("Leftwards Arrow");
      send_data_over_i2c(129);
    }
    if (code == 278) {
      //Serial.println("Rightwards Arrow");
      send_data_over_i2c(130);
    }
    if (code == 279) {
      //Serial.println("Upwards Arrow");
      send_data_over_i2c(131);
    }
    if (code == 280) {
      //Serial.println("Downwards Arrow");
      send_data_over_i2c(132);
    }
    code = keymap.remapKey(code);
    if (code > 0) {
      if ((code & 0xFF)) {
        if ((code & 0xFF) == 27) {
          //Serial.println("Esc");
        } else if ((code & 0xFF) == 13) {
          //Serial.println("Enter");
        } else if ((code & 0xFF) == 8) {
          //Serial.println("Backspace");
        } else {
          //Serial.print( " mapped " );
          //Serial.print( code, HEX );
          //Serial.print( " - Status Bits " );
          //Serial.print( code >> 8, HEX );
          //Serial.print( "  Code " );
          //Serial.print( code & 0xFF, HEX );
          //Serial.print( "  ( " );
          //Serial.write( code & 0xFF );
          //Serial.print( " )\n" );
        }
        send_data_over_i2c(code);
      }

    }
  }
  delayMicroseconds(48);
  enc0.tick();
  if (enc0.left()) {
    send_data_over_i2c(129);
  }
  if (enc0.right()) {
    send_data_over_i2c(130);
  }

  delayMicroseconds(48);

  a_button.tick();
  if (a_button.press()) {
    send_data_over_i2c(133);
  }
  delayMicroseconds(48);

  b_button.tick();
  if (b_button.press()) {
    send_data_over_i2c(8);
  }
  delayMicroseconds(48);

  encoder_button.tick();
  if (encoder_button.hasClicks(4)) {
    send_data_over_i2c(13);
  }

  if (encoder_button.hasClicks(5)) {
    send_data_over_i2c(27);
  }
  delayMicroseconds(48);
}
