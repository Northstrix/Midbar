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

N64Controller N64_ctrl (4);

void setup() {
    N64_ctrl.begin(); // Initialisation
    Serial.begin(115200);
}

void loop() {
    delay(24);
    N64_ctrl.update(); // read key state
    if (N64_ctrl.A() == true){
      Serial.println("A");
    }
    if (N64_ctrl.B() == true){
      Serial.println("B");
    }
    if (N64_ctrl.Start() == true){
      Serial.println("Start");
    }
    if (N64_ctrl.Z() == true){
      Serial.println("Z");
    }
    if (N64_ctrl.axis_x() > 96){
      Serial.println("Stick Right");
    }
    if (N64_ctrl.axis_x() < -96){
      Serial.println("Stick Left");
    }
    if (N64_ctrl.axis_y() > 96){
      Serial.println("Stick Up");
    }
    if (N64_ctrl.axis_y() < -96){
      Serial.println("Stick Down");
    }
    if (N64_ctrl.C_right() == true){
      Serial.println("C Right");
    }
    if (N64_ctrl.C_left() == true){
      Serial.println("C Left");
    }
    if (N64_ctrl.C_up() == true){
      Serial.println("C Up");
    }
    if (N64_ctrl.C_down() == true){
      Serial.println("C Down");
    }
    if (N64_ctrl.D_right() == true){
      Serial.println("D Right");
    }
    if (N64_ctrl.D_left() == true){
      Serial.println("D Left");
    }
    if (N64_ctrl.D_up() == true){
      Serial.println("D Up");
    }
    if (N64_ctrl.D_down() == true){
      Serial.println("D Down");
    }
    if (N64_ctrl.L() == true){
      Serial.println("L");
    }
    if (N64_ctrl.R() == true){
      Serial.println("R");
    }
    //N64_ctrl.print_N64_status();
    delay(24);
}
