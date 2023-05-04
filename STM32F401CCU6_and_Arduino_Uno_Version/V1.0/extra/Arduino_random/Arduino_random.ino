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
//Taken from: https://www.instructables.com/Arduino-Truly-Random-Number-Generator/
#include <stdint.h>
#include <avr/wdt.h>
#include <avr/interrupt.h>

byte output = 0;  //holds the binary output value
byte sample = 0;
byte current_bit = 0;
boolean waiting = false;  //bool true when ISR runs

void setup() {
Serial.begin(115200);
wd_setup();  //setting up the watchdog timer
}

void loop(){
if (waiting) {
  output = rotate(output, 1);      
  output ^= sample;           // XOR preserves randomness
  current_bit++;
  waiting = false;            //so that the loop() runs only once and after ISR

  if (current_bit > 7){
      Serial.println(output); // printing the raw binary value
      current_bit = 0;
    }
  }
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
