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
https://github.com/adafruit/Adafruit_ILI9341
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/intrbiz/arduino-crypto
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/techpaul/PS2KeyMap
https://github.com/pothos/arduino-n64-controller-library
https://github.com/ulwanski/sha512
*/
#include <stdint.h>
#include <avr/wdt.h>
#include <avr/interrupt.h>
#include <N64Controller.h>

#include <Wire.h>

N64Controller N64_ctrl(2);

uint16_t code;
uint8_t found;
byte output = 0;  //holds the binary output value
byte sample = 0;
byte current_bit = 0;
boolean waiting = false;  //bool true when ISR runs
byte threshold = 111;
bool pressed_a;
bool pressed_b;
bool pressed_start;
bool pressed_z;
bool pressed_up;
bool pressed_down;
bool pressed_left;
bool pressed_right;

void send_data_over_i2c(byte x) {
  Wire.beginTransmission(13);
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
      while (digitalRead(A1) == HIGH){}
    } 
  }
}

void handle_input(){
  N64_ctrl.update();
  if (N64_ctrl.A() == true){
    if (pressed_a == false){
      send_data_over_i2c(133);
    }
    pressed_a = true;
  }
  else{
    pressed_a = false;
  }
  
  if (N64_ctrl.B() == true){
    if (pressed_b == false){
      send_data_over_i2c(8);
    }
    pressed_b = true;
  }
  else{
    pressed_b = false;
  }
  
  if (N64_ctrl.Start() == true){
    if (pressed_start == false){
      send_data_over_i2c(13);
    }
    pressed_start = true;
  }
  else{
    pressed_start = false;
  }
  
  if (N64_ctrl.Z() == true){
    if (pressed_z == false){
      send_data_over_i2c(27);
    }
    pressed_z = true;
  }
  else{
    pressed_z = false;
  }
  
  if (N64_ctrl.axis_y() > threshold || N64_ctrl.C_up() == true || N64_ctrl.D_up() == true){
    if (pressed_up == false){
      send_data_over_i2c(131);
    }
    pressed_up = true;
  }
  else{
    pressed_up = false;
  }
  
  if (N64_ctrl.axis_y() < (threshold) * -1 || N64_ctrl.C_down() == true || N64_ctrl.D_down() == true){
    if (pressed_down == false){
      send_data_over_i2c(132);
    }
    pressed_down = true;
  }
  else{
    pressed_down = false;
  }
  
  if (N64_ctrl.L() == true || N64_ctrl.D_left() == true || N64_ctrl.C_left() == true || N64_ctrl.axis_x() < ((threshold) * -1)){
    if (pressed_left == false){
      send_data_over_i2c(129);
    }
    pressed_left = true;
  }
  else{
    pressed_left = false;
  }
  
  if (N64_ctrl.R() == true || N64_ctrl.D_right() == true || N64_ctrl.C_right() == true || N64_ctrl.axis_x() > threshold){
    if (pressed_right == false){
      send_data_over_i2c(130);
    }
    pressed_right = true;
  }
  else{
    pressed_right = false;
  }
  
  delayMicroseconds(256);
}

void setup() {
  //Serial.begin(115200);
  Wire.begin();
  wd_setup();
  bool pressed_a = false;
  bool pressed_b = false;
  bool pressed_start = false;
  bool pressed_z = false;
  bool pressed_up = false;
  bool pressed_down = false;
  bool pressed_left = false;
  bool pressed_right = false;
  pinMode(A1, INPUT);
}

void loop() {
  if (digitalRead(A1) == LOW){ // Handle Input
    handle_input();
  }
  else{ // RNG
    generate_random_number();
  }
}
