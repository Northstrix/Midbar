/*
Project Midbar
Distributed under the MIT License
© Copyright Maxim Bortnikov 2022
For more information please visit
https://github.com/Northstrix/Midbar
Required libraries:
https://github.com/zhouyangchao/AES
https://github.com/peterferrie/serpent
https://github.com/ulwanski/sha512
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_ILI9341
https://github.com/GyverLibs/GyverBus
https://github.com/PaulStoffregen/PS2Keyboard
https://github.com/siara-cc/esp32_arduino_sqlite3_lib
*/
String gen_rand_ID(int n_itr){
  String rec_ID;
  for (int i = 0; i<n_itr; i++){
    rec_ID += char(32 + esp_random()%95);
  }
  return rec_ID;
}

void setup()
{
Serial.begin(115200);
}
 
void loop()
{
Serial.println(gen_rand_ID(34));
Serial.println(gen_rand_ID(36));
Serial.println(gen_rand_ID(40));
delay(24);
}
