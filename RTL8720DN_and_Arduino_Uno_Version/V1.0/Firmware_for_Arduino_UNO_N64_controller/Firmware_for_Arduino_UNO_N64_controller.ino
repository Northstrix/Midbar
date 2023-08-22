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
#include <N64Controller.h>

#include <Wire.h>

#include <EncButton2.h>

#include <SPI.h>
#include <MFRC522.h>
#define SS_PIN 10
#define RST_PIN 9
MFRC522 mfrc522(SS_PIN, RST_PIN);

EncButton2 < EB_ENC > enc0(INPUT, 5, 6);
EncButton2 < EB_BTN > encoder_button(INPUT, 7);
EncButton2 < EB_BTN > a_button(INPUT, 8);
EncButton2 < EB_BTN > b_button(INPUT, 4);

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

void print_to_i2c(String stuff_to_print){
  for (int i = 0; i < stuff_to_print.length(); i++){
    if (stuff_to_print.charAt(i) == '0')
      send_data_over_i2c(key_codes[0]);
    if (stuff_to_print.charAt(i) == '1')
      send_data_over_i2c(key_codes[1]);
    if (stuff_to_print.charAt(i) == '2')
      send_data_over_i2c(key_codes[2]);
    if (stuff_to_print.charAt(i) == '3')
      send_data_over_i2c(key_codes[3]);
    if (stuff_to_print.charAt(i) == '4')
      send_data_over_i2c(key_codes[4]);
    if (stuff_to_print.charAt(i) == '5')
      send_data_over_i2c(key_codes[5]);
    if (stuff_to_print.charAt(i) == '6')
      send_data_over_i2c(key_codes[6]);
    if (stuff_to_print.charAt(i) == '7')
      send_data_over_i2c(key_codes[7]);
    if (stuff_to_print.charAt(i) == '8')
      send_data_over_i2c(key_codes[8]);
    if (stuff_to_print.charAt(i) == '9')
      send_data_over_i2c(key_codes[9]);
    if (stuff_to_print.charAt(i) == 'a')
      send_data_over_i2c(key_codes[10]);
    if (stuff_to_print.charAt(i) == 'b')
      send_data_over_i2c(key_codes[11]);
    if (stuff_to_print.charAt(i) == 'c')
      send_data_over_i2c(key_codes[12]);
    if (stuff_to_print.charAt(i) == 'd')
      send_data_over_i2c(key_codes[13]);
    if (stuff_to_print.charAt(i) == 'e')
      send_data_over_i2c(key_codes[14]);
    if (stuff_to_print.charAt(i) == 'f')
      send_data_over_i2c(key_codes[15]);
    delay(24);
  }
  send_data_over_i2c(13);
}

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

void read_rfid_card(){
  bool break_rfid_loop = false;
  while (break_rfid_loop == false && digitalRead(A1) == LOW && digitalRead(A2) == HIGH) {
    delay(1);
    if ( ! mfrc522.PICC_IsNewCardPresent()) 
    {
      return;
    }
    if ( ! mfrc522.PICC_ReadCardSerial()) 
    {
      return;
    }
      String read_card;
      
      if (mfrc522.uid.uidByte[0] < 16)
        read_card += 0;
      read_card +=  String(mfrc522.uid.uidByte[0], HEX);
      
      if (mfrc522.uid.uidByte[1] < 16)
        read_card += 0;
      read_card +=  String(mfrc522.uid.uidByte[1], HEX);
      
      if (mfrc522.uid.uidByte[2] < 16)
        read_card += 0;
      read_card +=  String(mfrc522.uid.uidByte[2], HEX);
      
      if (mfrc522.uid.uidByte[3] < 16)
        read_card += 0;
      read_card +=  String(mfrc522.uid.uidByte[3], HEX);
      
      mfrc522.PICC_HaltA();
      mfrc522.PCD_StopCrypto1();
      
      print_to_i2c(read_card);
      break_rfid_loop = true;
      delay(60);
  }
}

void handle_input(){
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
  delayMicroseconds(256);
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
  Serial.begin(115200);
  SPI.begin();
  mfrc522.PCD_Init();
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
  pinMode(A2, INPUT);
}

void loop() {
  if (digitalRead(A1) == LOW && digitalRead(A2) == LOW){ // Handle Input
    handle_input();
  }
  if (digitalRead(A1) == HIGH && digitalRead(A2) == LOW){ // RNG
    generate_random_number();
  }
  if (digitalRead(A1) == LOW && digitalRead(A2) == HIGH){ // RFID Reader
    read_rfid_card();
  }
}
