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
#include <ESP8266WiFi.h>
#include <espnow.h>
#include "sha512.h"
#include "aes.h"
#include "serpent.h"
#include <Adafruit_GFX.h>
#include <Adafruit_ST7735.h>
#include <FS.h>
#define TFT_CS         D2
#define TFT_RST        D3
#define TFT_DC         D4
Adafruit_ST7735 tft = Adafruit_ST7735(TFT_CS, TFT_DC, TFT_RST);
typedef struct struct_message {
  char l_srp[16];
  char r_srp[16];
  bool n;
} struct_message;

// Create a struct_message called myData
struct_message myData;
String plt;
byte tmp_st[8];
int tmp_s[8];
int m = 2; // AES-256

char *keys[] = {"efde9ba9bcf66ee02458cf22acbe0fc59efc82dd7c8f347e08f53eff8c6c686c"}; // Serpent's key
uint8_t projection_key[32] = {
0xad,0xbd,0xdc,0xbb,
0xe1,0xae,0x64,0x29,
0x5e,0xd6,0x01,0xef,
0xa2,0x14,0xe1,0xef,
0x4b,0xdd,0xfe,0x99,
0x08,0xf4,0xa9,0xa0,
0x96,0xe6,0xdc,0x7e,
0x9c,0xff,0x55,0x80
};

void incr_projection_key(){
  if(projection_key[0] == 255){
    projection_key[0] = 0;
    if(projection_key[1] == 255){
      projection_key[1] = 0;
      if(projection_key[2] == 255){
        projection_key[2] = 0;
        if(projection_key[3] == 255){
          projection_key[3] = 0;

  if(projection_key[4] == 255){
    projection_key[4] = 0;
    if(projection_key[5] == 255){
      projection_key[5] = 0;
      if(projection_key[6] == 255){
        projection_key[6] = 0;
        if(projection_key[7] == 255){
          projection_key[7] = 0;
          
  if(projection_key[8] == 255){
    projection_key[8] = 0;
    if(projection_key[9] == 255){
      projection_key[9] = 0;
      if(projection_key[10] == 255){
        projection_key[10] = 0;
        if(projection_key[11] == 255){
          projection_key[11] = 0;

  if(projection_key[12] == 255){
    projection_key[12] = 0;
    if(projection_key[13] == 255){
      projection_key[13] = 0;
      if(projection_key[14] == 255){
        projection_key[14] = 0;
        if(projection_key[15] == 255){
          projection_key[15] = 0;
        }
        else{
          projection_key[15]++;
        }
        }
      else{
        projection_key[14]++;
      }
    }
    else{
      projection_key[13]++;
    }
  }
  else{
    projection_key[12]++;
  }
          
        }
        else{
          projection_key[11]++;
        }
        }
      else{
        projection_key[10]++;
      }
    }
    else{
      projection_key[9]++;
    }
  }
  else{
    projection_key[8]++;
  }
          
        }
        else{
          projection_key[7]++;
        }
        }
      else{
        projection_key[6]++;
      }
    }
    else{
      projection_key[5]++;
    }
  }
  else{
    projection_key[4]++;
  }
          
        }
        else{
          projection_key[3]++;
        }
        }
      else{
        projection_key[2]++;
      }
    }
    else{
      projection_key[1]++;
    }
  }
  else{
    projection_key[0]++;
  }
}

int getNum(char ch)
{
    int num=0;
    if(ch>='0' && ch<='9')
    {
        num=ch-0x30;
    }
    else
    {
        switch(ch)
        {
            case 'A': case 'a': num=10; break;
            case 'B': case 'b': num=11; break;
            case 'C': case 'c': num=12; break;
            case 'D': case 'd': num=13; break;
            case 'E': case 'e': num=14; break;
            case 'F': case 'f': num=15; break;
            default: num=0;
        }
    }
    return num;
}

void print(const char *msg, const uint8_t *buf)
{
  Serial.printf("%s", msg);
  int i;
  for(i = 0; i < 16; ++i)
    Serial.printf("%02x ", buf[i]);
  Serial.printf("\n");
}

// Callback function that will be executed when data is received
void OnDataRecv(uint8_t * mac, uint8_t *incomingData, uint8_t len) {
  memcpy(&myData, incomingData, sizeof(myData));
  if (myData.n == false){
    plt = "";
  }
  delayMicroseconds(24);
  decr_Serpent(myData.l_srp, false);
  decr_Serpent(myData.r_srp, true);
  incr_projection_key();
}

void decr_Serpent(char res[], bool pass){
      uint8_t ct1[32], pt1[32], key[64];
      int plen, clen, i, j;
      serpent_key skey;
      serpent_blk ct2;
      uint32_t *p;
  
  for (i=0; i<sizeof(keys)/sizeof(char*); i++) {
    hex2bin (key, keys[i]);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");

    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      //Serial.printf ("%08X ", p[j]);
    }

    for(int i = 0; i <16; i++)
      ct2.b[i] = res[i];
    /*
    Serial.printf ("\n\n");
    for(int i = 0; i<16; i++){
    Serial.printf("%x", ct2.b[i]);
    Serial.printf(" ");
    */
    }
    //Serial.printf("\n");
    serpent_encrypt (ct2.b, &skey, SERPENT_DECRYPT);
    /*
    for (int i=0; i<16; i++) {
      Serial.print(int(ct2.b[i]));
      Serial.print(" ");
    }
    Serial.println();
    */
    if (pass == false){
      for (int i = 0; i<8; i++){
        tmp_s[i] = ct2.b[i];
      }
    }
    if (pass == true){
      int t_dec[16];
      for (int i = 0; i<8; i++){
        t_dec[i] = tmp_s[i];
      }
      for (int i = 0; i<8; i++){
        t_dec[i+8] = ct2.b[i];
      }
      decr_AES(t_dec);
    }
}

void decr_AES(int res[]){
      uint8_t ret_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
      uint8_t cipher_text[16] = {0};
      for(int i = 0; i<16; i++){
        int c = int(res[i]);
        cipher_text[i] = c;
      }
      uint32_t projection_key_bit[3] = {128, 192, 256};
      int i = 0;
      aes_context ctx;
      aes_set_key(&ctx, projection_key, projection_key_bit[m]);
      aes_decrypt_block(&ctx, ret_text, cipher_text);
      for (i = 0; i < 8; ++i) {
        //Serial.print(char(ret_text[i]));
        //Serial.println(ret_text[i]);
        if (ret_text[i] != 0){
          plt += char(ret_text[i]);
        }
      }
      Serial.print("Received text:");
      Serial.println(plt);
}

size_t hex2bin (void *bin, char hex[]) {
  size_t len, i;
  int x;
  uint8_t *p=(uint8_t*)bin;
  
  len = strlen (hex);
  
  if ((len & 1) != 0) {
    return 0; 
  }
  
  for (i=0; i<len; i++) {
    if (isxdigit((int)hex[i]) == 0) {
      return 0; 
    }
  }
  
  for (i=0; i<len / 2; i++) {
    sscanf (&hex[i * 2], "%2x", &x);
    p[i] = (uint8_t)x;
  } 
  return len / 2;
}
 
void setup() {
  // Initialize Serial Monitor
  Serial.begin(115200);
  Serial.println("\nProject Midbar");
  tft.initR(INITR_BLACKTAB);
  tft.setRotation(1);
  // Set device as a Wi-Fi Station
  WiFi.mode(WIFI_STA);

  // Init ESP-NOW
  if (esp_now_init() != 0) {
    Serial.println("Error initializing ESP-NOW");
    return;
  }
  tft.fillScreen(0x2145);
  tft.setTextColor(0xdefb, 0x2145);
  tft.setTextSize(1);
  tft.setCursor(0,2);
  tft.print("Project Midbar");
  esp_now_set_self_role(ESP_NOW_ROLE_SLAVE);
  esp_now_register_recv_cb(OnDataRecv);
}

void loop() {
  if (plt != ""){
    tft.fillScreen(0x2145);
    tft.fillScreen(0x2145);
    tft.fillScreen(0x2145); // Needed for the additional delay
    tft.setTextColor(0xdefb, 0x2145);
    tft.setCursor(0,2);
    tft.print("Received text:");
    tft.setCursor(0,16);
    tft.print(plt);
    plt = "";
  }
}
