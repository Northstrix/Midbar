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
#include <N64Controller.h>

N64Controller N64_ctrl(4);

byte threshold = 111;

bool pressed_a;
bool pressed_b;
bool pressed_start;
bool pressed_z;
bool pressed_up;
bool pressed_down;
bool pressed_left;
bool pressed_right;

void setup() {
  N64_ctrl.begin(); // Initialisation
  Serial.begin(115200);
  bool pressed_a = false;
  bool pressed_b = false;
  bool pressed_start = false;
  bool pressed_z = false;
  bool pressed_up = false;
  bool pressed_down = false;
  bool pressed_left = false;
  bool pressed_right = false;
}

void loop() {
  N64_ctrl.update();
  if (N64_ctrl.A() == true){
    if (pressed_a == false){
      Serial.println("A");
    }
    pressed_a = true;
  }
  else{
    pressed_a = false;
  }
  
  if (N64_ctrl.B() == true){
    if (pressed_b == false){
      Serial.println("B");
    }
    pressed_b = true;
  }
  else{
    pressed_b = false;
  }
  
  if (N64_ctrl.Start() == true){
    if (pressed_start == false){
      Serial.println("Start");
    }
    pressed_start = true;
  }
  else{
    pressed_start = false;
  }
  
  if (N64_ctrl.Z() == true){
    if (pressed_z == false){
      Serial.println("Z");
    }
    pressed_z = true;
  }
  else{
    pressed_z = false;
  }
  
  if (N64_ctrl.axis_y() > threshold || N64_ctrl.C_up() == true || N64_ctrl.D_up() == true){
    if (pressed_up == false){
      Serial.println("Up");
    }
    pressed_up = true;
  }
  else{
    pressed_up = false;
  }
  
  if (N64_ctrl.axis_y() < (threshold) * -1 || N64_ctrl.C_down() == true || N64_ctrl.D_down() == true){
    if (pressed_down == false){
      Serial.println("Down");
    }
    pressed_down = true;
  }
  else{
    pressed_down = false;
  }
  
  if (N64_ctrl.L() == true || N64_ctrl.D_left() == true || N64_ctrl.C_left() == true || N64_ctrl.axis_x() < ((threshold) * -1)){
    if (pressed_left == false){
      Serial.println("Left");
    }
    pressed_left = true;
  }
  else{
    pressed_left = false;
  }
  
  if (N64_ctrl.R() == true || N64_ctrl.D_right() == true || N64_ctrl.C_right() == true || N64_ctrl.axis_x() > threshold){
    if (pressed_right == false){
      Serial.println("Right");
    }
    pressed_right = true;
  }
  else{
    pressed_right = false;
  }
  
  delayMicroseconds(256);
}
