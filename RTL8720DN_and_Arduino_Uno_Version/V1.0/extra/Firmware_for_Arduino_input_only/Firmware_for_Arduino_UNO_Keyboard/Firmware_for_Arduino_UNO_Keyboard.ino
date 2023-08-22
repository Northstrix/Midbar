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
https://github.com/miguelbalboa/rfid
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/techpaul/PS2KeyMap
https://github.com/pothos/arduino-n64-controller-library
*/
#include <stdint.h>
#include <avr/wdt.h>
#include <avr/interrupt.h>
#include <PS2KeyAdvanced.h>
#include <PS2KeyMap.h>

#include <Wire.h>

#include <EncButton2.h>

EncButton2 < EB_ENC > enc0(INPUT, 5, 6);
EncButton2 < EB_BTN > encoder_button(INPUT, 7);
EncButton2 < EB_BTN > a_button(INPUT, 8);
EncButton2 < EB_BTN > b_button(INPUT, 0);

#define DATAPIN 2
#define IRQPIN 3

PS2KeyAdvanced keyboard;
PS2KeyMap keymap;

uint16_t code;
uint8_t found;
byte output = 0;  //holds the binary output value
byte sample = 0;
byte current_bit = 0;
boolean waiting = false;  //bool true when ISR runs

void send_data_over_i2c(byte x) {
  Wire.beginTransmission(7);
  Wire.write(x);
  Wire.endTransmission();
  delay(4);
}

byte rotate(const byte val, int shift) {    //rotate the bits to the left to increase the randomness

    if ((shift &= sizeof(val)*8 - 1) == 0)
          return val;
    return (val << shift) | (val >> (sizeof(val)*8 - shift));
}

void wd_setup() {   //sets the WD timer in interrupt mode with shortest prescaler
    cli();
    MCUSR = 0;
      
  WDTCSR |= _BV(WDCE) | _BV(WDE);
  WDTCSR = _BV(WDIE);
  sei();
}
  
// Watchdog Timer Interrupt Service Routine
ISR(WDT_vect){
  /* only sampling the clock of cpu
    which are only last 8 bits of the time
    so ignoring the higher bits*/
  
    sample = TCNT1L;
    waiting = true;
}

void generate_random_number(){
  if (waiting) {
    output = rotate(output, 1);      
    output ^= sample;           // XOR preserves randomness
    current_bit++;
    waiting = false;            //so that the loop() runs only once and after ISR
    if (current_bit > 7){
      send_data_over_i2c(output);
      current_bit = 0;
    } 
  }
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
  wd_setup();
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
  delayMicroseconds(96);
  enc0.tick();
  if (enc0.left()) {
    send_data_over_i2c(129);
  }
  if (enc0.right()) {
    send_data_over_i2c(130);
  }

  delayMicroseconds(96);

  a_button.tick();
  if (a_button.press()) {
    send_data_over_i2c(133);
  }
  delayMicroseconds(96);

  b_button.tick();
  if (b_button.press()) {
    send_data_over_i2c(8);
  }
  delayMicroseconds(96);

  encoder_button.tick();
  if (encoder_button.hasClicks(4)) {
    send_data_over_i2c(13);
  }

  if (encoder_button.hasClicks(5)) {
    send_data_over_i2c(27);
  }
  delayMicroseconds(96);
}
