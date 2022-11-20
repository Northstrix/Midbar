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
#include <Adafruit_GFX.h>                                                   // include Adafruit graphics library
#include <Adafruit_ILI9341.h>                                               // include Adafruit ILI9341 TFT library
#define TFT_CS    15                                                        // TFT CS  pin is connected to ESP32 pin D15
#define TFT_RST   4                                                         // TFT RST pin is connected to ESP32 pin D4
#define TFT_DC    2                                                         // TFT DC  pin is connected to ESP32 pin D2
                                                                            // SCK (CLK) ---> ESP32 pin D18
                                                                            // MOSI(DIN) ---> ESP32 pin D23
#include <esp_now.h>
#include <WiFi.h>
#include <SoftwareSerial.h>
#include "SPIFFS.h"
#include <sys/random.h>
#include "sha512.h"
#include "aes.h"
#include "serpent.h"
#include "GBUS.h"
Adafruit_ILI9341 tft = Adafruit_ILI9341(TFT_CS, TFT_DC, TFT_RST);
SoftwareSerial mySerial(34, 35); // RX, TX
GBUS bus(&mySerial, 3, 25);
int cur_pos;
char ch;
int pr_key;
struct myStruct {
  char x;
};
char *keys[]=
{"4f18b6b1ffd81f9755b0815db942c415834a9bae3bbc838a2d6b33d2f87598fd"};// Serpent's key

uint8_t key[32] = {
   0xd1,0xf0,0x68,0x5b,
   0x33,0xa0,0xb1,0x73,
   0xb6,0x25,0x54,0xf9,
   0xdd,0x2c,0xd3,0x1d,
   0xc1,0x93,0xb3,0x14,
   0x16,0x76,0x28,0x59,
   0x04,0x85,0xd4,0x24,
   0x9d,0xe0,0x2a,0x74
};

uint8_t second_key[32] = {
   0xfb,0x87,0x9c,0x11,
   0x16,0x97,0xbb,0x14,
   0x3c,0x1e,0x30,0xdb,
   0x67,0xab,0xb8,0x9b,
   0x23,0x5e,0x15,0x9a,
   0xd2,0xdd,0x7c,0x96,
   0x41,0xc9,0x25,0xd3,
   0xd0,0xe1,0x75,0xe3
};

uint8_t projection_key[32] = {
   0xef,0xe7,0x3e,0x31,
   0x61,0x71,0x6c,0xca,
   0x16,0xe8,0xfb,0x24,
   0xd4,0x57,0x7d,0x9a,
   0x74,0x60,0x76,0xaf,
   0x1c,0x42,0x82,0x6d,
   0xf4,0xc3,0x5b,0x51,
   0x69,0x8e,0x24,0x2d
};

uint8_t broadcastAddress[] = {0xEC, 0x94, 0xCB, 0x67, 0x3A, 0x4C};
int count;
byte tmp_st[8];
char temp_st_for_pp[16];
int m;
int n;
String dec_st;
String keyb_inp;
uint8_t back_key[32];
uint8_t back_s_key[32];

typedef struct struct_message {
  char l_srp[16];
  char r_srp[16];
  bool n;
} struct_message;

struct_message myData;

esp_now_peer_info_t peerInfo;

void OnDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
  Serial.print("\r\nLast Packet Send Status:\t");
  Serial.println(status == ESP_NOW_SEND_SUCCESS ? "Delivery Success" : "Delivery Fail");
}

void back_k(){
  for(int i = 0; i<32; i++){
    back_key[i] = key[i];
  }
}

void rest_k(){
  for(int i = 0; i<32; i++){
    key[i] = back_key[i];
  }
}

void back_s_k(){
  for(int i = 0; i<32; i++){
    back_s_key[i] = second_key[i];
  }
}

void rest_s_k(){
  for(int i = 0; i<32; i++){
    second_key[i] = back_s_key[i];
  }
}

void incr_key(){
  if(key[0] == 255){
    key[0] = 0;
    if(key[1] == 255){
      key[1] = 0;
      if(key[2] == 255){
        key[2] = 0;
        if(key[3] == 255){
          key[3] = 0;

  if(key[4] == 255){
    key[4] = 0;
    if(key[5] == 255){
      key[5] = 0;
      if(key[6] == 255){
        key[6] = 0;
        if(key[7] == 255){
          key[7] = 0;
          
  if(key[8] == 255){
    key[8] = 0;
    if(key[9] == 255){
      key[9] = 0;
      if(key[10] == 255){
        key[10] = 0;
        if(key[11] == 255){
          key[11] = 0;

  if(key[12] == 255){
    key[12] = 0;
    if(key[13] == 255){
      key[13] = 0;
      if(key[14] == 255){
        key[14] = 0;
        if(key[15] == 255){
          key[15] = 0;
        }
        else{
          key[15]++;
        }
        }
      else{
        key[14]++;
      }
    }
    else{
      key[13]++;
    }
  }
  else{
    key[12]++;
  }
          
        }
        else{
          key[11]++;
        }
        }
      else{
        key[10]++;
      }
    }
    else{
      key[9]++;
    }
  }
  else{
    key[8]++;
  }
          
        }
        else{
          key[7]++;
        }
        }
      else{
        key[6]++;
      }
    }
    else{
      key[5]++;
    }
  }
  else{
    key[4]++;
  }
          
        }
        else{
          key[3]++;
        }
        }
      else{
        key[2]++;
      }
    }
    else{
      key[1]++;
    }
  }
  else{
    key[0]++;
  }
}

void incr_second_key(){
  if(second_key[0] == 255){
    second_key[0] = 0;
    if(second_key[1] == 255){
      second_key[1] = 0;
      if(second_key[2] == 255){
        second_key[2] = 0;
        if(second_key[3] == 255){
          second_key[3] = 0;

  if(second_key[4] == 255){
    second_key[4] = 0;
    if(second_key[5] == 255){
      second_key[5] = 0;
      if(second_key[6] == 255){
        second_key[6] = 0;
        if(second_key[7] == 255){
          second_key[7] = 0;
          
  if(second_key[8] == 255){
    second_key[8] = 0;
    if(second_key[9] == 255){
      second_key[9] = 0;
      if(second_key[10] == 255){
        second_key[10] = 0;
        if(second_key[11] == 255){
          second_key[11] = 0;

  if(second_key[12] == 255){
    second_key[12] = 0;
    if(second_key[13] == 255){
      second_key[13] = 0;
      if(second_key[14] == 255){
        second_key[14] = 0;
        if(second_key[15] == 255){
          second_key[15] = 0;
        }
        else{
          second_key[15]++;
        }
        }
      else{
        second_key[14]++;
      }
    }
    else{
      second_key[13]++;
    }
  }
  else{
    second_key[12]++;
  }
          
        }
        else{
          second_key[11]++;
        }
        }
      else{
        second_key[10]++;
      }
    }
    else{
      second_key[9]++;
    }
  }
  else{
    second_key[8]++;
  }
          
        }
        else{
          second_key[7]++;
        }
        }
      else{
        second_key[6]++;
      }
    }
    else{
      second_key[5]++;
    }
  }
  else{
    second_key[4]++;
  }
          
        }
        else{
          second_key[3]++;
        }
        }
      else{
        second_key[2]++;
      }
    }
    else{
      second_key[1]++;
    }
  }
  else{
    second_key[0]++;
  }
}

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

int gen_r_num(){
  int rn = esp_random()%256;
  return rn;
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

char getChar(int num){
  char ch;
    if(num>=0 && num<=9)
    {
        ch = char(num+48);
    }
    else
    {
        switch(num)
        {
            case 10: ch='a'; break;
            case 11: ch='b'; break;
            case 12: ch='c'; break;
            case 13: ch='d'; break;
            case 14: ch='e'; break;
            case 15: ch='f'; break;
        }
    }
    return ch;
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

void split_by_eight(char plntxt[], int k, int str_len, bool add_aes){
  char plt_data[] = {0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 8; i++){
      if(i+k > str_len - 1)
      break;
      plt_data[i] = plntxt[i+k];
  }
  char t_encr[16];
  for(int i = 0; i<8; i++){
      t_encr[i] = plt_data[i];
  }
  for(int i = 8; i<16; i++){
      t_encr[i] = gen_r_num();
  }
  encr_AES(t_encr, add_aes);
}

void encr_AES(char t_enc[], bool add_aes){
  uint8_t text[16];
  for(int i = 0; i<16; i++){
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t key_bit[3] = {128, 192, 256};
  aes_context ctx;
  aes_set_key(&ctx, key, key_bit[m]);
  aes_encrypt_block(&ctx, cipher_text, text);
  /*
  for (int i = 0; i < 16; ++i) {
    Serial.printf("%02x", cipher_text[i]);
  }
  */
  char L_half[16];
  for(int i = 0; i<8; i++){
    L_half[i] = cipher_text[i];
  }
  char R_half[16];
  for(int i = 0; i<8; i++){
    R_half[i] = cipher_text[i+8];
  }
  for(int i = 8; i<16; i++){
    L_half[i] = gen_r_num();
    R_half[i] = gen_r_num();
  }
  serp_enc(L_half, add_aes);
  serp_enc(R_half, add_aes);
}

void serp_enc(char res[], bool add_aes){
  int tmp_s[16];
  for(int i = 0; i < 16; i++){
      tmp_s[i] = res[i];
  }
  /*
   for (int i = 0; i < 16; i++){
     Serial.print(res[i]);
  }
  Serial.println();
  */
  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, b, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t *p;
  
  for (b=0; b<sizeof(keys)/sizeof(char*); b++) {
    hex2bin (key, keys[b]);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");
    /*
    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      Serial.printf ("%08X ", p[j]);
    }
    */
    for(int i = 0; i < 16; i++){
        ct2.b[i] = tmp_s[i];
    }
  serpent_encrypt (ct2.b, &skey, SERPENT_ENCRYPT);
  if(add_aes == false){
    for (int i=0; i<16; i++) {
      if(ct2.b[i]<16)
        Serial.print("0");
      Serial.print(ct2.b[i],HEX);
    }
  }
  if(add_aes == true)
  encr_sec_AES(ct2.b);
  }
}

void encr_sec_AES(byte t_enc[]){
  uint8_t text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for(int i = 0; i<16; i++){
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t second_key_bit[3] = {128, 192, 256};
  int i = 0;
  aes_context ctx;
  aes_set_key(&ctx, second_key, second_key_bit[m]);
  aes_encrypt_block(&ctx, cipher_text, text);
  for (i = 0; i < 16; ++i) {
    Serial.printf("%02x", cipher_text[i]);
  }
}

void split_dec(char ct[], int ct_len, int p, bool ch, bool add_r){
  int br = false;
  byte res[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 32; i+=2){
    if(i+p > ct_len - 1){
      br = true;
      break;
    }
    if (i == 0){
    if(ct[i+p] != 0 && ct[i+p+1] != 0)
    res[i] = 16*getNum(ct[i+p])+getNum(ct[i+p+1]);
    if(ct[i+p] != 0 && ct[i+p+1] == 0)
    res[i] = 16*getNum(ct[i+p]);
    if(ct[i+p] == 0 && ct[i+p+1] != 0)
    res[i] = getNum(ct[i+p+1]);
    if(ct[i+p] == 0 && ct[i+p+1] == 0)
    res[i] = 0;
    }
    else{
    if(ct[i+p] != 0 && ct[i+p+1] != 0)
    res[i/2] = 16*getNum(ct[i+p])+getNum(ct[i+p+1]);
    if(ct[i+p] != 0 && ct[i+p+1] == 0)
    res[i/2] = 16*getNum(ct[i+p]);
    if(ct[i+p] == 0 && ct[i+p+1] != 0)
    res[i/2] = getNum(ct[i+p+1]);
    if(ct[i+p] == 0 && ct[i+p+1] == 0)
    res[i/2] = 0;
    }
  }
    if(br == false){
      if(add_r == true){
      uint8_t ret_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
      uint8_t cipher_text[16] = {0};
      for(int i = 0; i<16; i++){
        int c = int(res[i]);
        cipher_text[i] = c;
      }
      uint32_t second_key_bit[3] = {128, 192, 256};
      int i = 0;
      aes_context ctx;
      aes_set_key(&ctx, second_key, second_key_bit[m]);
      aes_decrypt_block(&ctx, ret_text, cipher_text);
      for (i = 0; i < 16; ++i) {
        res[i] = (char)ret_text[i];
      }
      }
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
    if (ch == false){
    for (int i=0; i<8; i++) {
      tmp_st[i] = char(ct2.b[i]);
    }
    }
    if (ch == true){
      decr_AES(ct2.b);
    }
  }
}

void decr_AES(byte sh[]){
  uint8_t ret_text[16];
  for(int i = 0; i<8; i++){
    ret_text[i] = tmp_st[i];
  }
  for(int i = 0; i<8; i++){
    ret_text[i+8] = sh[i];
  }
      uint8_t cipher_text[16] = {0};
      for(int i = 0; i<16; i++){
        int c = int(ret_text[i]);
        cipher_text[i] = c;
      }
      uint32_t key_bit[3] = {128, 192, 256};
      int i = 0;
      aes_context ctx;
      aes_set_key(&ctx, key, key_bit[m]);
      aes_decrypt_block(&ctx, ret_text, cipher_text);
      for (i = 0; i < 8; ++i) {
        dec_st += (char(ret_text[i]));
      }
}

void proj_pass(){
      int str_len = keyb_inp.length() + 1;
      char char_array[str_len];
      keyb_inp.toCharArray(char_array, str_len);
      int p = 0;
      while( str_len > p+1){
        split_by_eight_for_pass_proj(char_array, p, str_len);
        p+=8;
      }
    keyb_inp = "";
    show_main_menu();
    return;
}

void split_by_eight_for_pass_proj(char plntxt[], int k, int str_len){
  char res[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 8; i++){
      if(i+k > str_len - 1)
      break;
      res[i] = plntxt[i+k];
  }
  for (int i = 8; i < 16; i++){
      res[i] = gen_r_num();
  }
  /*
   for (int i = 0; i < 8; i++){
     Serial.print(res[i]);
  }
  Serial.println();
  */
  encr_AES_for_pp(res);
}

void encr_AES_for_pp(char t_enc[]){
  uint8_t text[16];
  for(int i = 0; i<16; i++){
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t key_bit[3] = {128, 192, 256};
  aes_context ctx;
  aes_set_key(&ctx, projection_key, key_bit[m]);
  aes_encrypt_block(&ctx, cipher_text, text);
  /*
  for (int i = 0; i < 16; ++i) {
    Serial.printf("%02x", cipher_text[i]);
  }
  */
  char L_half[16];
  for(int i = 0; i<8; i++){
    L_half[i] = cipher_text[i];
  }
  char R_half[16];
  for(int i = 0; i<8; i++){
    R_half[i] = cipher_text[i+8];
  }
  for(int i = 8; i<16; i++){
    L_half[i] = gen_r_num();
    R_half[i] = gen_r_num();
  }
  serp_for_pp(L_half, false);
  serp_for_pp(R_half, true);
}

void serp_for_pp(char res[], bool snd){
  int tmp_s[16];
  for(int i = 0; i < 16; i++){
      tmp_s[i] = res[i];
  }
  /*
   for (int i = 0; i < 16; i++){
     Serial.print(res[i]);
  }
  Serial.println();
  */
  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, b, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t *p;
  
  for (b=0; b<sizeof(keys)/sizeof(char*); b++) {
    hex2bin (key, keys[b]);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");
    /*
    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      Serial.printf ("%08X ", p[j]);
    }
    */
    for(int i = 0; i < 16; i++){
        ct2.b[i] = tmp_s[i];
    }
  serpent_encrypt (ct2.b, &skey, SERPENT_ENCRYPT);
    for (int i=0; i<16; i++) {
      if(ct2.b[i]<16)
        Serial.print("0");
      Serial.print(ct2.b[i],HEX);
    }
    if (snd == false){
     for(int i = 0; i <16; i++){
      temp_st_for_pp[i] = ct2.b[i];
     }
    }
    if (snd == true){
     for(int i = 0; i <16; i++){
      myData.l_srp[i] = temp_st_for_pp[i];
      myData.r_srp[i] = ct2.b[i];
     }
     myData.n = n;
     esp_now_send(broadcastAddress, (uint8_t *) &myData, sizeof(myData));
     incr_projection_key();
     n = true;
     delayMicroseconds(240);
    }
  }
}

void disp_cur_pos(){
  clear_right_side();
  tft.setTextColor(0xe73c, 0x12ea);
  tft.setTextSize(2);
  char indc = char(175);
  if (cur_pos == 0){
    tft.setCursor(9,20);
    tft.print(indc);
    tft.setCursor(9,40);
    tft.print(" ");
    tft.setCursor(9,60);
    tft.print(" ");
    tft.setCursor(9,80);
    tft.print(" ");
    tft.setCursor(9,100);
    tft.print(" ");
    tft.setCursor(9,120);
    tft.print(" ");
    tft.setCursor(9,140);
    tft.print(" ");
    tft.setCursor(9,160);
    tft.print(" ");
    tft.setCursor(9,180);
    disp_login_cred_card_note_phone_menu();
  }
  if (cur_pos == 1){
    tft.setCursor(9,20);
    tft.print(" ");
    tft.setCursor(9,40);
    tft.print(indc);
    tft.setCursor(9,60);
    tft.print(" ");
    tft.setCursor(9,80);
    tft.print(" ");
    tft.setCursor(9,100);
    tft.print(" ");
    tft.setCursor(9,120);
    tft.print(" ");
    tft.setCursor(9,140);
    tft.print(" ");
    tft.setCursor(9,160);
    tft.print(" ");
    tft.setCursor(9,180);
    disp_login_cred_card_note_phone_menu();
  }
  if (cur_pos == 2){
    tft.setCursor(9,20);
    tft.print(" ");
    tft.setCursor(9,40);
    tft.print(" ");
    tft.setCursor(9,60);
    tft.print(indc);
    tft.setCursor(9,80);
    tft.print(" ");
    tft.setCursor(9,100);
    tft.print(" ");
    tft.setCursor(9,120);
    tft.print(" ");
    tft.setCursor(9,140);
    tft.print(" ");
    tft.setCursor(9,160);
    tft.print(" ");
    tft.setCursor(9,180);
    disp_login_cred_card_note_phone_menu();
  }
  if (cur_pos == 3){
    tft.setCursor(9,20);
    tft.print(" ");
    tft.setCursor(9,40);
    tft.print(" ");
    tft.setCursor(9,60);
    tft.print(" ");
    tft.setCursor(9,80);
    tft.print(indc);
    tft.setCursor(9,100);
    tft.print(" ");
    tft.setCursor(9,120);
    tft.print(" ");
    tft.setCursor(9,140);
    tft.print(" ");
    tft.setCursor(9,160);
    tft.print(" ");
    tft.setCursor(9,180);
    disp_login_cred_card_note_phone_menu();
  }
  if (cur_pos == 4){
    tft.setCursor(9,20);
    tft.print(" ");
    tft.setCursor(9,40);
    tft.print(" ");
    tft.setCursor(9,60);
    tft.print(" ");
    tft.setCursor(9,80);
    tft.print(" ");
    tft.setCursor(9,100);
    tft.print(indc);
    tft.setCursor(9,120);
    tft.print(" ");
    tft.setCursor(9,140);
    tft.print(" ");
    tft.setCursor(9,160);
    tft.print(" ");
    tft.setCursor(9,180);
    disp_encr_menu();
  }
  if (cur_pos == 5){
    tft.setCursor(9,20);
    tft.print(" ");
    tft.setCursor(9,40);
    tft.print(" ");
    tft.setCursor(9,60);
    tft.print(" ");
    tft.setCursor(9,80);
    tft.print(" ");
    tft.setCursor(9,100);
    tft.print(" ");
    tft.setCursor(9,120);
    tft.print(indc);
    tft.setCursor(9,140);
    tft.print(" ");
    tft.setCursor(9,160);
    tft.print(" ");
    tft.setCursor(9,180);
    disp_sqlite_menu();
  }
  if (cur_pos == 6){
    tft.setCursor(9,20);
    tft.print(" ");
    tft.setCursor(9,40);
    tft.print(" ");
    tft.setCursor(9,60);
    tft.print(" ");
    tft.setCursor(9,80);
    tft.print(" ");
    tft.setCursor(9,100);
    tft.print(" ");
    tft.setCursor(9,120);
    tft.print(" ");
    tft.setCursor(9,140);
    tft.print(indc);
    tft.setCursor(9,160);
    tft.print(" ");
    tft.setCursor(9,180);
    disp_hash_menu();
  }
  if (cur_pos == 7){
    tft.setCursor(9,20);
    tft.print(" ");
    tft.setCursor(9,40);
    tft.print(" ");
    tft.setCursor(9,60);
    tft.print(" ");
    tft.setCursor(9,80);
    tft.print(" ");
    tft.setCursor(9,100);
    tft.print(" ");
    tft.setCursor(9,120);
    tft.print(" ");
    tft.setCursor(9,140);
    tft.print(" ");
    tft.setCursor(9,160);
    tft.print(indc);
    tft.setCursor(9,180);
    disp_fs_menu();
  }
}

void show_main_menu(){
   tft.fillScreen(0x12ea);
   clear_right_side();
   tft.setTextColor(0xe73c, 0x12ea);
   tft.setTextSize(2);
   tft.setCursor(26,20);
   tft.print("Login");
   tft.setCursor(26,40);
   tft.print("Credit Card");
   tft.setCursor(26,60);
   tft.print("Note");
   tft.setCursor(26,80);
   tft.print("Phone number");
   tft.setCursor(26,100);
   tft.print("Encryption");
   tft.setCursor(26,120);
   tft.print("SQLite3");
   tft.setCursor(26,140);
   tft.print("SHA-512");
   tft.setCursor(26,160);
   tft.print("File");
   show_state();
}

void show_state(){
   tft.fillRect(0, 210, 320, 240, 0xe73c);
   tft.setTextColor(0x3186, 0xe73c);
   tft.setTextSize(2);
   tft.setCursor(18,218);
   tft.print("SPIFFS:OK AES:256 Key:"); 
}

void last_pressed_key(){
   tft.setCursor(280,218);
   tft.print("7F");
}

void clear_right_side(){
   tft.fillRect(188, 0, 320, 210, 0x3186);
}

void disp_login_cred_card_note_phone_menu(){
   tft.setTextColor(0xe73c, 0x3186);
   tft.setTextSize(2);
   tft.setCursor(196, 20);
   tft.print("1.Add");
   tft.setCursor(196, 40);
   tft.print("2.Modify"); 
   tft.setCursor(196, 60);
   tft.print("3.Remove"); 
   tft.setCursor(196, 80);
   tft.print("4.View"); 
   tft.setCursor(196, 100);
   tft.print("5.Show all");
   tft.setCursor(196, 120);
   tft.print("6.Send"); 
}

void disp_encr_menu(){
   tft.setTextColor(0xe73c, 0x3186);
   tft.setTextSize(1);
   tft.setCursor(196, 20);
   tft.print("1.Encrypt input from");
   tft.setCursor(196, 30);
   tft.print("keyboard with AES +"); 
   tft.setCursor(196, 40);
   tft.print("Serpent + AES in"); 
   tft.setCursor(196, 50);
   tft.print("counter mode."); 
   tft.setCursor(196, 65);
   tft.print("2.Encrypt input from");
   tft.setCursor(196, 75);
   tft.print("the Serial Monitor"); 
   tft.setCursor(196, 85);
   tft.print("with AES + Serpent +"); 
   tft.setCursor(196, 95);
   tft.print("AES in counter mode.");
   tft.setCursor(196, 110);
   tft.print("3.Decrypt with AES +"); 
   tft.setCursor(196, 120);
   tft.print("Serpent + AES in"); 
   tft.setCursor(196, 130);
   tft.print("counter mode.");
   tft.setCursor(196, 145);
}

void disp_sqlite_menu(){
   tft.setTextColor(0xe73c, 0x3186);
   tft.setTextSize(1);
   tft.setCursor(196, 20);
   tft.print("1.Execute SQL");
   tft.setCursor(196, 30);
   tft.print("statement from the"); 
   tft.setCursor(196, 40);
   tft.print("Serial Monitor."); 
   tft.setCursor(196, 55);
   tft.print("2.Execute SQL");
   tft.setCursor(196, 65);
   tft.print("statement from"); 
   tft.setCursor(196, 75);
   tft.print("keyboard."); 
}

void disp_hash_menu(){
   tft.setTextColor(0xe73c, 0x3186);
   tft.setTextSize(1);
   tft.setCursor(196, 20);
   tft.print("1.Take the input");
   tft.setCursor(196, 30);
   tft.print("from keyboard and"); 
   tft.setCursor(196, 40);
   tft.print("hash it using");
   tft.setCursor(196, 50);
   tft.print("SHA-512."); 
   tft.setCursor(196, 65);
   tft.print("2.Take the input");
   tft.setCursor(196, 75);
   tft.print("from the Serial"); 
   tft.setCursor(196, 85);
   tft.print("Monitor and hash it");
   tft.setCursor(196, 95);
   tft.print("using SHA-512."); 
}

void disp_fs_menu(){
   tft.setTextColor(0xe73c, 0x3186);
   tft.setTextSize(2);
   tft.setCursor(196, 20);
   tft.print("1.Create");
   tft.setCursor(196, 40);
   tft.print("2.Remove"); 
   tft.setCursor(196, 60);
   tft.print("3.View"); 
   tft.setCursor(196, 80);
   tft.print("4.List all"); 
}

void enc_text(){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter the text to encrypt:");
  tft.setTextColor(0xe73c, 0x3186);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  tft.fillRect(0, 210, 320, 240, 0xe73c);
  tft.setTextColor(0x3186, 0xe73c);
  tft.setTextSize(2);
  tft.setCursor(18,218);
  tft.print("Length:");
  int inpl = keyb_inp.length();
  tft.setCursor(100,218);
  tft.print("    ");
  tft.setCursor(100,218);
  tft.print(inpl);
  while (pr_key != 27){
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      pr_key = int(ch);
      if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11){
        keyb_inp += ch;
      }
      else if (ch == 127) {
        tft.fillScreen(0x3186);
        if(keyb_inp.length() > 0)
          keyb_inp.remove(keyb_inp.length() -1, 1);
        tft.fillScreen(0x3186);
        tft.setTextColor(0xe73c, 0x3186);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter the text to encrypt:");
      }
  tft.setTextColor(0xe73c, 0x3186);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  tft.fillRect(0, 210, 320, 240, 0xe73c);
  tft.setTextColor(0x3186, 0xe73c);
  tft.setTextSize(2);
  tft.setCursor(18,218);
  tft.print("Length:");
  int inpl = keyb_inp.length();
  tft.setCursor(100,218);
  tft.print("    ");
  tft.setCursor(100,218);
  tft.print(inpl);
  if (pr_key == 13){
    int str_len = keyb_inp.length() + 1;
    char keyb_inp_arr[str_len];
    keyb_inp.toCharArray(keyb_inp_arr, str_len);
    Serial.println("Ciphertext:");
    int p = 0;
    while(str_len > p+1){
      incr_key();
      incr_second_key();
      split_by_eight(keyb_inp_arr, p, str_len, true);
      p+=8;
    }
    rest_k();
    rest_s_k();
    Serial.println("");
    keyb_inp = "";
    show_main_menu();
    disp_encr_menu();
    return;
  }
  if (pr_key == 27){
     keyb_inp = "";
     show_main_menu();
     return;
  }
  }
 }
}

void dec_text(){
 while (pr_key != 27){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.print("Paste the ciphertext into");
  tft.setCursor(0,25);
  tft.print("the Serial Monitor.");
  dec_st = "";
  String ct;
  Serial.println("Paste the ciphertext here:");
  while (!Serial.available()) {
    bus.tick();
   if (bus.gotData()) {
    myStruct data;
    bus.readData(data);
    // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
    ch = data.x;
    pr_key = int(ch);
    if (pr_key == 27){
      keyb_inp = "";
      dec_st = "";
      show_main_menu();
      return;
    }
   }  
  }
  ct = Serial.readString();
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  count = 0;
  bool ch = false;
  while(ct_len > ext){
  if(count%2 == 1 && count !=0)
    ch = true;
  else{
    ch = false;
      incr_key();
      incr_second_key();
  }
  split_dec(ct_array, ct_len, 0+ext, ch, true);
  ext+=32;
  count++;
  }
  rest_k();
  rest_s_k();
  Serial.println("Plaintext:");
  Serial.println(dec_st);
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Plaintext:");
  tft.setCursor(0,25);
  tft.println(dec_st);
  tft.setCursor(0,200);
  tft.print("Press any key to return to");
  tft.setCursor(0,220);
  tft.print("the main menu.");
  keyb_inp = "";
  dec_st = "";
  while (!bus.gotData()){
    bus.tick();
  }
  show_main_menu();
  return;
 }
}

void hash_str(){
  tft.fillScreen(0x49a9);
  tft.setTextColor(0xe73c, 0x49a9);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter the string to hash:");
  tft.fillRect(0, 210, 320, 240, 0xe73c);
  tft.setTextColor(0x3186, 0xe73c);
  tft.setTextSize(2);
  tft.setCursor(18,218);
  tft.print("Length:");
  while (pr_key != 27){
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      pr_key = int(ch);
      if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11){
        keyb_inp += ch;
      }
      else if (ch == 127) {
        if(keyb_inp.length() > 0)
          keyb_inp.remove(keyb_inp.length() -1, 1);
        tft.fillScreen(0x49a9);
        tft.setTextColor(0xe73c, 0x49a9);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter the string to hash:");
        tft.fillRect(0, 210, 320, 240, 0xe73c);
        tft.setTextColor(0x49a9, 0xe73c);
        tft.setTextSize(2);
        tft.setCursor(18,218);
        tft.print("Length:");
      }
  int inpl = keyb_inp.length();
  tft.setTextColor(0x49a9, 0xe73c);
  tft.setCursor(100,218);
  tft.print("    ");
  tft.setCursor(100,218);
  tft.print(inpl);
  tft.setTextColor(0xf75b, 0x49a9);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
    int str_len = keyb_inp.length() + 1;
    char keyb_inp_arr[str_len];
    keyb_inp.toCharArray(keyb_inp_arr, str_len);
    std::string str = "";
    if(str_len > 1){
      for(int i = 0; i<str_len-1; i++){
        str += keyb_inp_arr[i];
      }
    }
    String h = sha512( str ).c_str();
    //Serial.println(h);
    tft.fillScreen(0x49a9);
    tft.setTextColor(0xe73c, 0x49a9);
    tft.setCursor(0,5);
    tft.println("Resulted hash:");
    tft.setTextColor(0xf75b, 0x49a9);
    tft.setCursor(0,25);
    tft.println(h);
    tft.setTextColor(0xe73c, 0x49a9);
    tft.setCursor(0,200);
    tft.print("Press any key to return to");
    tft.setCursor(0,220);
    tft.print("the main menu.");
    keyb_inp = "";
    while (!bus.gotData()){
      bus.tick();
    }
    show_main_menu();
    return;
  }
  if (pr_key == 27){
     keyb_inp = "";
     show_main_menu();
     return;
  }
  }
 }
}

void hash_str_from_ser(){
 while (pr_key != 27){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(2);
  tft.setCursor(5,5);
  tft.println("Paste the text you want to");
  tft.setCursor(5,25);
  tft.println("hash into the Serial");
  tft.setCursor(5,45);
  tft.println("Monitor.");
  tft.setCursor(5,220);
  tft.print("Press Esc to cancel.");
  Serial.println("Paste the text that you want to hash here:");
  String input;
  while (!Serial.available()) {
        bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      pr_key = int(ch);
     if (pr_key == 27){
      keyb_inp = "";
      show_main_menu();
      return;
    }
    }
  }
  input = Serial.readString();
  Serial.println("Input:" + input);
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  std::string str = "";
  if(str_len > 1){
    for(int i = 0; i<str_len-1; i++){
      str += input_arr[i];
    }
  }
  String h = sha512( str ).c_str();
  Serial.println("Hash:" + h);
  Serial.println("");
  show_main_menu();
  return;
 }
}

void enc_text_from_ser(){
 while (pr_key != 27){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(2);
  tft.setCursor(5,5);
  tft.println("Paste the text to encrypt");
  tft.setCursor(5,25);
  tft.println("into the Serial Monitor.");
  tft.setCursor(5,220);
  tft.print("Press Esc to cancel.");
  Serial.println("Paste the text to encrypt:");
  String inp_str;
  while (!Serial.available()) {
        bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      pr_key = int(ch);
     if (pr_key == 27){
      keyb_inp = "";
      show_main_menu();
      return;
    }
    }
  }
  inp_str = Serial.readString();
  int str_len = inp_str.length() + 1;
  char char_array[str_len];
  inp_str.toCharArray(char_array, str_len);
  Serial.println("Ciphertext:");
  int p = 0;
  while(str_len > p+1){
    incr_key();
    incr_second_key();
    split_by_eight(char_array, p, str_len, true);
    p+=8;
  }
  rest_k();
  rest_s_k();
  Serial.println("");
  show_main_menu();
  return;
 }
}

void proj_text_from_Serial(){
 while (pr_key != 27){
  tft.fillScreen(0x2145);
  tft.setTextColor(0xdefb, 0x2145);
  tft.setCursor(0,0);
  tft.println("Enter the text you want to send into the Serial Monitor:");
  Serial.println("Enter the text to send:");
  String inp_str;
  while (!Serial.available()) {}
  inp_str = Serial.readString();
  int str_len = inp_str.length() + 1;
  char char_array[str_len];
  inp_str.toCharArray(char_array, str_len);
  Serial.println("Ciphertext:");
  int p = 0;
  while(str_len > p+1){
    incr_key();
    incr_second_key();
    split_by_eight_for_pass_proj(char_array, p, str_len);
    p+=8;
  }
  rest_k();
  rest_s_k();
  show_main_menu();
  return;
 }
}

void Unlock_device(){
  tft.fillScreen(0x059a);
  tft.fillRect(10, 120, 300, 20, 0xe73c);
  tft.setTextColor(0xe73c, 0x059a);
  tft.setTextSize(4);
  tft.setCursor(89,40);
  tft.print("MIDBAR");
  tft.setTextColor(0x2126, 0xe73c);  
  tft.setTextSize(1);
  tft.setCursor(15,127);
  tft.print("Enter the Master Password...");
  tft.fillRect(0, 210, 320, 240, 0xe73c);
  tft.setTextColor(0x3186, 0xe73c);
  tft.setTextSize(2);
  tft.setCursor(18,218);
  tft.print("Password Length:0 chars");
  while (pr_key != 27){
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      pr_key = int(ch);
      if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11){
        keyb_inp += ch;
      }
      else if (ch == 127) {
        tft.fillRect(10, 120, 300, 20, 0xe73c);
        tft.setTextColor(0x2126, 0xe73c);
        tft.setTextSize(2);
        tft.setCursor(210,218);
        tft.print("         ");
        if(keyb_inp.length() > 0)
          keyb_inp.remove(keyb_inp.length() -1, 1);
      }
  int inpl = keyb_inp.length();
  if(inpl == 0){
      tft.fillRect(10, 120, 300, 20, 0xe73c);
      tft.setTextColor(0x2126, 0xe73c);  
      tft.setTextSize(1);
      tft.setCursor(15,127);
      tft.print("Enter the Master Password...");
      tft.setTextSize(2);
      tft.setCursor(18,218);
      tft.print("Password Length:0 chars");
  }
  else{
    String pass = "";
      for(int i = 0; i < inpl; i++){
        if (i < 49)
          pass += "*";
      }
      tft.fillRect(10, 120, 300, 20, 0xe73c);
      tft.setTextColor(0x2126, 0xe73c);  
      tft.setTextSize(1);
      tft.setCursor(15,127);
      tft.print(pass);
      tft.setTextSize(2);
      tft.setCursor(210,218);
      tft.printf("%d chars",inpl); 
  }

  if (pr_key == 13){
      int str_len = keyb_inp.length() + 1;
      char input_arr[str_len];
      keyb_inp.toCharArray(input_arr, str_len);
      std::string str = "";
      if(str_len > 1){
        for(int i = 0; i<str_len-1; i++){
          str += input_arr[i];
        }
      }
      String h = sha512( str ).c_str();
      int h_len = h.length() + 1;
      char h_array[h_len];
      h.toCharArray(h_array, h_len);
      byte res[16] = {0};
      for (int i = 0; i < 32; i+=2){
      if (i == 0){
      if(h_array[i] != 0 && h_array[i+1] != 0)
      res[i] = 16*getNum(h_array[i])+getNum(h_array[i+1]);
      if(h_array[i] != 0 && h_array[i+1] == 0)
      res[i] = 16*getNum(h_array[i]);
      if(h_array[i] == 0 && h_array[i+1] != 0)
      res[i] = getNum(h_array[i+1]);
      if(h_array[i] == 0 && h_array[i+1] == 0)
      res[i] = 0;
      }
      else{
      if(h_array[i] != 0 && h_array[i+1] != 0)
      res[i/2] = 16*getNum(h_array[i])+getNum(h_array[i+1]);
      if(h_array[i] != 0 && h_array[i+1] == 0)
      res[i/2] = 16*getNum(h_array[i]);
      if(h_array[i] == 0 && h_array[i+1] != 0)
      res[i/2] = getNum(h_array[i+1]);
      if(h_array[i] == 0 && h_array[i+1] == 0)
      res[i/2] = 0;
      }
     }
     uint8_t ct1[32], pt1[32], key[64];
     int plen, clen, i, j;
     serpent_key skey;
     serpent_blk ct2;
     uint32_t *p;
     for (i=0; i<sizeof(keys)/sizeof(char*); i++) {
      hex2bin (key, keys[i]);
      memset (&skey, 0, sizeof (skey));
      p=(uint32_t*)&skey.x[0][0];
      serpent_setkey (&skey, key);
      for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
        if ((j % 8)==0) putchar('\n');
      }
      for(int i = 0; i <16; i++)
        ct2.b[i] = res[i];
      }
      for(int i = 0; i<576; i++)
        serpent_encrypt (ct2.b, &skey, SERPENT_DECRYPT);
      key[0] = ct2.b[0];
      key[1] = ct2.b[1];
      key[3] = ct2.b[2];
      key[4] = ct2.b[3];
      key[6] = ct2.b[4];
      key[7] = ct2.b[5];
      key[8] = ct2.b[12];
      second_key[0] = ct2.b[6];
      second_key[1] = ct2.b[7];
      second_key[3] = ct2.b[8];
      second_key[4] = ct2.b[9];
      second_key[6] = ct2.b[10];
      second_key[7] = ct2.b[11];
      second_key[8] = ct2.b[13];
    tft.setTextSize(2);
    tft.fillScreen(0x059a);
    tft.setTextColor(0xe73c, 0x059a);
    tft.setCursor(0,10);
    tft.println("      Device unlocked");
    tft.setCursor(0,30);
    tft.println("       successfully!");
    tft.setCursor(5,100);
    tft.print("Verification number is ");
    tft.print(ct2.b[14]);
    tft.setCursor(5,200);
    tft.print("Press any key to get to");
    tft.setCursor(5,220);
    tft.print("the main menu.");
    keyb_inp = "";
    while (!bus.gotData()){
      bus.tick();
    }
    show_main_menu();
    return;
  }
  if (pr_key == 27){
     keyb_inp = "";
     show_main_menu();
     return;
  }
  }
 }
}

void setup() {
  Serial.begin(115200);
  mySerial.begin(9600);
  Serial.println("Project Midbar");
  tft.begin();
  tft.setRotation(1);
  m = 2;
  Unlock_device();
  if (!SPIFFS.begin(true)) {
    Serial.println("An Error has occurred while mounting SPIFFS");
    return;
  }
  // Set device as a Wi-Fi Station
  WiFi.mode(WIFI_STA);

  // Init ESP-NOW
  if (esp_now_init() != ESP_OK) {
    Serial.println("Error initializing ESP-NOW");
    return;
  }

  // Once ESPNow is successfully Init, we will register for Send CB to
  // get the status of Trasnmitted packet
  esp_now_register_send_cb(OnDataSent);
  
  // Register peer
  memcpy(peerInfo.peer_addr, broadcastAddress, 6);
  peerInfo.channel = 0;  
  peerInfo.encrypt = false;
  
  // Add peer        
  if (esp_now_add_peer(&peerInfo) != ESP_OK){
    Serial.println("Failed to add peer");
    return;
  }
  show_main_menu();
  cur_pos = 0;
  disp_cur_pos();
  disp_login_cred_card_note_phone_menu();
}

void loop() {
  back_k();
  back_s_k();
  n = false;
  bus.tick();
  if (bus.gotData()) {
    myStruct data;
    bus.readData(data);
    // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
    ch = data.x;
    //Serial.println(ch);
    //Serial.println(int(ch));
    pr_key = int(ch);
    if (pr_key == 10)
      cur_pos++;
      
    if (pr_key == 11)
      cur_pos--;
      
    if (cur_pos < 0)
      cur_pos = 7;
      
    if (cur_pos > 7)
      cur_pos = 0;
      
    if (cur_pos == 0){
      clear_right_side();
    }
    
    if (cur_pos == 1){
      clear_right_side();
    }
    
    if (cur_pos == 2){
      clear_right_side();
    }
    
    if (cur_pos == 3){
      clear_right_side();
    }

    if (cur_pos == 4){
      clear_right_side();
    }
    
    if (cur_pos == 5){
      clear_right_side();
    }
    
    if (cur_pos == 6){
      clear_right_side();
    }
    
    if (cur_pos == 7){
      clear_right_side();
    }

    if (cur_pos == 4 && pr_key == 49) // Encryption.1
      enc_text();
    if (cur_pos == 4 && pr_key == 50) // Encryption.2
      enc_text_from_ser();
    if (cur_pos == 4 && pr_key == 51) // Encryption.3
      dec_text();
      
    if (cur_pos == 6 && pr_key == 49) // SHA512.1
      hash_str();
    if (cur_pos == 6 && pr_key == 50) // SHA512.1
      hash_str_from_ser();
    
    disp_cur_pos();
  }
}
