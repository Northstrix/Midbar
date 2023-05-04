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
#include <stdint.h>
#include <avr/wdt.h>
#include <avr/interrupt.h>
#include <ps2dev.h>
#include <SPI.h>
#include <MFRC522.h>

#define SS_PIN 10
#define RST_PIN 9
MFRC522 mfrc522(SS_PIN, RST_PIN);

byte output = 0;  //holds the binary output value
byte sample = 0;
byte current_bit = 0;
boolean waiting = false;  //bool true when ISR runs

char key_codes[] = {
  '0',
  '1',
  '2',
  '3',
  '4',
  '5',
  '6',
  '7',
  '8',
  '9',
  'a',
  'b',
  'c',
  'd',
  'e',
  'f',
  '\n'
};

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

void print_to_ser(String stuff_to_print){
  Serial.begin(4800);
  for (int i = 0; i < stuff_to_print.length(); i++){
    if (stuff_to_print.charAt(i) == '0')
      Serial.print(key_codes[0]);
    if (stuff_to_print.charAt(i) == '1')
      Serial.print(key_codes[1]);
    if (stuff_to_print.charAt(i) == '2')
      Serial.print(key_codes[2]);
    if (stuff_to_print.charAt(i) == '3')
      Serial.print(key_codes[3]);
    if (stuff_to_print.charAt(i) == '4')
      Serial.print(key_codes[4]);
    if (stuff_to_print.charAt(i) == '5')
      Serial.print(key_codes[5]);
    if (stuff_to_print.charAt(i) == '6')
      Serial.print(key_codes[6]);
    if (stuff_to_print.charAt(i) == '7')
      Serial.print(key_codes[7]);
    if (stuff_to_print.charAt(i) == '8')
      Serial.print(key_codes[8]);
    if (stuff_to_print.charAt(i) == '9')
      Serial.print(key_codes[9]);
    if (stuff_to_print.charAt(i) == 'a')
      Serial.print(key_codes[10]);
    if (stuff_to_print.charAt(i) == 'b')
      Serial.print(key_codes[11]);
    if (stuff_to_print.charAt(i) == 'c')
      Serial.print(key_codes[12]);
    if (stuff_to_print.charAt(i) == 'd')
      Serial.print(key_codes[13]);
    if (stuff_to_print.charAt(i) == 'e')
      Serial.print(key_codes[14]);
    if (stuff_to_print.charAt(i) == 'f')
      Serial.print(key_codes[15]);
  }
  Serial.print(key_codes[16]);
  delayMicroseconds(50);
  Serial.end();
}

void setup() {
  SPI.begin();
  mfrc522.PCD_Init();
  pinMode(4, INPUT);
  wd_setup();  //setting up the watchdog timer
}

void loop() {
  if (digitalRead(4) == HIGH){
    if ( ! mfrc522.PICC_IsNewCardPresent()) 
    {
      return;
    }
    if ( ! mfrc522.PICC_ReadCardSerial()) 
    {
      return;
    }
      String read_card;
      
      //if (mfrc522.uid.uidByte[0] < 16)
        //read_card += 0;
      read_card +=  String(mfrc522.uid.uidByte[0], HEX);
      
      //if (mfrc522.uid.uidByte[1] < 16)
        //read_card += 0;
      read_card +=  String(mfrc522.uid.uidByte[1], HEX);
      
      //if (mfrc522.uid.uidByte[2] < 16)
        //read_card += 0;
      read_card +=  String(mfrc522.uid.uidByte[2], HEX);
      
      //if (mfrc522.uid.uidByte[3] < 16)
        //read_card += 0;
      read_card +=  String(mfrc522.uid.uidByte[3], HEX);

      print_to_ser(read_card);
      delay(200);
      
  }
  else{
    if (waiting) {
      output = rotate(output, 1);      
      output ^= sample;           // XOR preserves randomness
      current_bit++;
      waiting = false;            //so that the loop() runs only once and after ISR

      if (current_bit > 7){
        String rnd_n;
        if (output < 16)
          rnd_n += 0;
        rnd_n +=  String(output, HEX);
        print_to_ser(rnd_n);
        current_bit = 0;
        while (digitalRead(4) == LOW){
          
        }
      } 
    }
  }
}
