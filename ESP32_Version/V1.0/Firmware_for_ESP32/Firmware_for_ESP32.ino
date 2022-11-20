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
#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <SPI.h>
#include <FS.h>
#include "SPIFFS.h"
#include <sys/random.h>
#include "sha512.h"
#include "aes.h"
#include "serpent.h"
#include "GBUS.h"
Adafruit_ILI9341 tft = Adafruit_ILI9341(TFT_CS, TFT_DC, TFT_RST);
SoftwareSerial mySerial(34, 35); // RX, TX
GBUS bus(&mySerial, 3, 25);
bool spf_ok;
bool peer_ok;
int cur_pos;
char ch;
int pr_key;
int num_of_IDs;
struct myStruct {
  char x;
};

uint8_t broadcastAddress[] = {0x5C, 0xCF, 0x7F, 0xFD, 0x85, 0x1D}; // Receiver's MAC address

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
uint8_t key[32] = {
0x15,0xdc,0x0b,0x0f,
0xcf,0xfb,0xc7,0x7c,
0x1f,0x8d,0x9c,0x07,
0xda,0xdd,0x66,0xac,
0x6c,0xd1,0x6f,0xcf,
0xbc,0xe1,0xab,0xfc,
0x68,0xac,0x9e,0x26,
0x6b,0x89,0x3c,0xc7
};
uint8_t second_key[32] = {
0xa2,0xb6,0xb8,0xea,
0x3b,0x1b,0x9e,0xdf,
0x66,0x08,0x9d,0xce,
0x69,0xbe,0xb3,0xc6,
0x76,0xea,0xcc,0xe7,
0x03,0xbe,0xba,0xe0,
0x8b,0xc0,0x0b,0x6a,
0xc5,0x4d,0x2d,0xb9
};

int count;
byte tmp_st[8];
char temp_st_for_pp[16];
int m;
int n;
String dec_st;
String keyb_inp;
uint8_t back_key[32];
uint8_t back_s_key[32];
String rec_ID;

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

int clb_m;
const char* data = "Callback function called";
static int callback(void *data, int argc, char **argv, char **azColName) {
   int i;
   if (clb_m == 0) //Print in serial
    Serial.printf("%s: ", (const char*)data);
   if (clb_m == 1){ //Print in serial
    tft.printf("%s:\n", (const char*)data);
   }
   for (i = 0; i<argc; i++){
       if (clb_m == 0){ //Print in serial
        Serial.printf("\n%s = %s", azColName[i], argv[i] ? argv[i] : "Empty");
        Serial.printf("\n\n");
       }
       if (clb_m == 1){ //Print in tft
        tft.printf("\n%s = %s\n", azColName[i], argv[i] ? argv[i] : "Empty");
        Serial.printf("\n\n");
       }
       if (clb_m == 2){ //Decrypt
        int ct_len = strlen(argv[i]) + 1;
        char ct_array[ct_len];
        snprintf(ct_array, ct_len, "%s", argv[i]);
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
       }
       if (clb_m == 3){ //Extract IDs
        int ct_len = strlen(argv[i]) + 1;
        char ct_array[ct_len];
        snprintf(ct_array, ct_len, "%s", argv[i]);
        for (int i = 0; i<ct_len; i++){
          dec_st += ct_array[i];
        }
        dec_st += "\n";
        num_of_IDs++;
       }
   }
   return 0;
}

void gen_rand_ID(int n_itr){
  for (int i = 0; i<n_itr; i++){
    int r_numb3r = esp_random()%95;
    if (r_numb3r != 7)
      rec_ID += char(32 + r_numb3r);
    else
      rec_ID += char(33 + r_numb3r + esp_random()%30);
  }
}

int db_open(const char *filename, sqlite3 **db) {
   int rc = sqlite3_open(filename, db);
   if (rc) {
       if (clb_m == 0) //Print in serial
        Serial.printf("Can't open database: %s\n", sqlite3_errmsg(*db));
       if (clb_m == 1) //Print in tft
        tft.printf("Can't open database: %s\n", sqlite3_errmsg(*db));
       return rc;
   } else {
       if (clb_m == 0) //Print in serial
        Serial.printf("Opened database successfully\n");
       if (clb_m == 1) //Print in tft
        tft.printf("Opened database successfully\n");
   }
   return rc;
}

char *zErrMsg = 0;
int db_exec(sqlite3 *db, const char *sql) {
   int rc = sqlite3_exec(db, sql, callback, (void*)data, &zErrMsg);
   if (rc != SQLITE_OK) {
       if (clb_m == 0) //Print in serial
        Serial.printf("SQL error: %s\n", zErrMsg);
       if (clb_m == 1) //Print in tft
        tft.printf("SQL error: %s\n", zErrMsg);
       sqlite3_free(zErrMsg);
   } else {
       if (clb_m == 0) //Print in serial
        Serial.printf("Operation done successfully\n");
       if (clb_m == 1) //Print in serial
        tft.printf("Operation done successfully\n");
   }
   return rc;
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

void split_by_eight(char plntxt[], int k, int str_len, bool add_aes, bool out_f){
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
  encr_AES(t_encr, add_aes, out_f);
}

void encr_AES(char t_enc[], bool add_aes, bool out_f){
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
  serp_enc(L_half, add_aes, out_f);
  serp_enc(R_half, add_aes, out_f);
}

void serp_enc(char res[], bool add_aes, bool out_f){
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
  encr_sec_AES(ct2.b, out_f);
  }
}

void encr_sec_AES(byte t_enc[], bool out_f){
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
    if (out_f == false)
      Serial.printf("%02x", cipher_text[i]);
    if (out_f == true){
      if (cipher_text[i] < 16)
        dec_st += 0;
      dec_st +=  String(cipher_text[i], HEX);
    }
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
   String spiffs_rec_state = "SPIFFS:";
   if (spf_ok == true){
    spiffs_rec_state += "OK";
   }
   else{
    spiffs_rec_state += "Err";
   }
   spiffs_rec_state += " ESP-NOW:";
   if (peer_ok == true){
    spiffs_rec_state += "OK";
   }
   else{
    spiffs_rec_state += "Err";
   }
   
   tft.print(spiffs_rec_state);
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
   tft.print("2.Edit"); 
   tft.setCursor(196, 60);
   tft.print("3.Remove"); 
   tft.setCursor(196, 80);
   tft.print("4.View"); 
   tft.setCursor(196, 100);
   tft.print("5.Show all");
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
   tft.print("statement from");
   tft.setCursor(196, 40);
   tft.print("keyboard.");
   tft.setCursor(196, 55);
   tft.print("2.Execute SQL");
   tft.setCursor(196, 65);
   tft.print("statement from the"); 
   tft.setCursor(196, 75);
   tft.print("Serial Monitor."); 
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
      split_by_eight(keyb_inp_arr, p, str_len, true, false);
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
  tft.setCursor(5,5);
  tft.print("Paste the ciphertext into");
  tft.setCursor(5,25);
  tft.print("the Serial Monitor.");
  tft.setCursor(5,220);
  tft.print("Press Esc to cancel.");
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

void exeq_sql_keyb(){
  tft.fillScreen(0x11c4);
  tft.setTextColor(0xe73c, 0x11c4);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter the SQL statement to");
  tft.setCursor(0,25);
  tft.println("execute:");
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
        tft.fillScreen(0x11c4);
        tft.setTextColor(0xe73c, 0x11c4);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter the SQL statement to");
        tft.setCursor(0,25);
        tft.println("execute:");
        tft.fillRect(0, 210, 320, 240, 0xe73c);
        tft.setTextColor(0x11c4, 0xe73c);
        tft.setTextSize(2);
        tft.setCursor(18,218);
        tft.print("Length:");
      }
  int inpl = keyb_inp.length();
  tft.setTextColor(0x11c4, 0xe73c);
  tft.setCursor(100,218);
  tft.print("    ");
  tft.setCursor(100,218);
  tft.print(inpl);
  tft.setTextColor(0xf75b, 0x11c4);
  tft.setCursor(0,45);
  tft.println(keyb_inp);
  if (pr_key == 13){
    clb_m = 1;
    tft.fillScreen(0x3186);
    tft.setTextColor(0xe73c, 0x3186);
    tft.setTextSize(1);
    tft.setCursor(0,0);
    exeq_sql_statement_from_string(keyb_inp);
    tft.setTextSize(2);
    tft.setCursor(0,200);
    tft.print("                                                                                                    ");
    tft.setCursor(5,200);
    tft.print("Press any key to return to");
    tft.setCursor(5,220);
    tft.print("the main menu.            ");
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

void exeq_sql_from_ser(){
  clb_m = 0;
 while (pr_key != 27){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(2);
  tft.setCursor(5,5);
  tft.println("Paste the SQL statement to");
  tft.setCursor(5,25);
  tft.println("execute into the Serial");
  tft.setCursor(5,45);
  tft.println("Monitor.");
  tft.setCursor(5,220);
  tft.print("Press Esc to cancel.");
  Serial.println("Paste the SQL statement to execute here:");
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
  exeq_sql_statement_from_string(Serial.readString());
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
    split_by_eight(char_array, p, str_len, true, false);
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

void send_text_from_keyb(){
  keyb_inp = "";
  tft.fillScreen(0x11c4);
  tft.setTextColor(0xe73c, 0x11c4);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter the text to send");
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
        tft.fillScreen(0x11c4);
        tft.setTextColor(0xe73c, 0x11c4);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter the text to send");
        tft.fillRect(0, 210, 320, 240, 0xe73c);
        tft.setTextColor(0x11c4, 0xe73c);
        tft.setTextSize(2);
        tft.setCursor(18,218);
        tft.print("Length:");
      }
  int inpl = keyb_inp.length();
  tft.setTextColor(0x11c4, 0xe73c);
  tft.setCursor(100,218);
  tft.print("    ");
  tft.setCursor(100,218);
  tft.print(inpl);
  tft.setTextColor(0xf75b, 0x11c4);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
     proj_pass();
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

void Create_file(){
  clb_m = 0;
 while (pr_key != 27){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(2);
  tft.setCursor(5,5);
  tft.println("Enter the name of the file");
  tft.setCursor(5,25);
  tft.println("and the content of the");
  tft.setCursor(5,45);
  tft.println("file into the Serial");
  tft.setCursor(5,65);
  tft.println("Monitor.");
  tft.setCursor(5,220);
  tft.print("Press Esc to cancel.");
  Serial.println("Enter the name of the new file");
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
  String nm = Serial.readString();
  Serial.println("Enter the content of the new file.");
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
  write_f("/" + nm, Serial.readString());
  show_main_menu();
  return;
 }
}

void read_f(String name){
  File file = SPIFFS.open(name);
  if(!file){
    Serial.println("Failed to open file for reading");
    return;
  }
  Serial.println("File Content:");
  while(file.available()){
    Serial.write(file.read());
  }
  file.close();
}

void write_f(String name, String cont){
  File file = SPIFFS.open(name, FILE_WRITE);
 
  if (!file) {
    Serial.println("There was an error opening the file for writing");
    return;
  }
  if (file.print(cont)) {
    Serial.println("File was written");
  } else {
    Serial.println("File write failed");
  }
 
  file.close();
}

void Remove_file(){
  clb_m = 0;
 while (pr_key != 27){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(2);
  tft.setCursor(5,5);
  tft.println("Enter the name of the file");
  tft.setCursor(5,25);
  tft.println("to remove into the Serial");
  tft.setCursor(5,45);
  tft.println("Monitor.");
  tft.setCursor(5,220);
  tft.print("Press Esc to cancel.");
  Serial.println("Enter the name of the file to remove");
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
  SPIFFS.remove("/" + Serial.readString());;
  show_main_menu();
  return;
 }
}

void View_file(){
  clb_m = 0;
 while (pr_key != 27){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(2);
  tft.setCursor(5,5);
  tft.println("Enter the name of the file");
  tft.setCursor(5,25);
  tft.println("to view into the Serial");
  tft.setCursor(5,45);
  tft.println("Monitor.");
  tft.setCursor(5,220);
  tft.print("Press Esc to cancel.");
  Serial.println("Enter the name of the file to view");
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
  read_f("/" + Serial.readString());
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

void exeq_sql_statement(char sql_statmnt[]){
   sqlite3 *db1;
   int rc;
   if (db_open("/spiffs/midbar.db", &db1))
       return;

   rc = db_exec(db1, sql_statmnt);
   if (rc != SQLITE_OK) {
       sqlite3_close(db1);
       return;
   }

   sqlite3_close(db1);
}

void create_login_table(){
   exeq_sql_statement("CREATE TABLE if not exists Logins (ID CHARACTER(36), Title TEXT, Username TEXT, Password TEXT, Website Text);");
}

void create_credit_card_table(){
   exeq_sql_statement("CREATE TABLE if not exists Credit_cards (ID CHARACTER(40), Title TEXT, Cardholder TEXT, Card_Number TEXT, Expiration_date Text, CVN Text, PIN Text, ZIP_code Text);");
}

void create_notes_table(){
   exeq_sql_statement("CREATE TABLE if not exists Notes (ID CHARACTER(34), Title TEXT, Content TEXT);");
}

void create_numbers_table(){
   exeq_sql_statement("CREATE TABLE if not exists Phone_numbers (ID CHARACTER(38), Title TEXT, Phone_number TEXT);");
}

void exeq_sql_statement_from_string(String squery){
   int squery_len = squery.length() + 1;
   char squery_array[squery_len];
   squery.toCharArray(squery_array, squery_len);
   exeq_sql_statement(squery_array);
   return;
}

void Add_login(){
  rec_ID = "";
  gen_rand_ID(36);
  Insert_title_into_the_logins();
}

void Insert_title_into_the_logins(){
  keyb_inp = "";
  tft.fillScreen(0x2145);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter the title:");
  tft.fillRect(0, 210, 320, 240, 0xe73c);
  tft.setTextColor(0x2145, 0xe73c);
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
        tft.fillScreen(0x2145);
        tft.setTextColor(0xe73c, 0x2145);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter the title:");
        tft.fillRect(0, 210, 320, 240, 0xe73c);
        tft.setTextColor(0x2145, 0xe73c);
        tft.setTextSize(2);
        tft.setCursor(18,218);
        tft.print("Length:");
      }
  int inpl = keyb_inp.length();
  tft.setTextColor(0x2145, 0xe73c);
  tft.setCursor(100,218);
  tft.print("    ");
  tft.setCursor(100,218);
  tft.print(inpl);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
    clb_m = 1;
    tft.fillScreen(0x3186);
    tft.setTextColor(0xe73c, 0x3186);
    tft.setTextSize(1);
    tft.setCursor(0,0);
    int str_len = keyb_inp.length() + 1;
    char keyb_inp_arr[str_len];
    keyb_inp.toCharArray(keyb_inp_arr, str_len);
    int p = 0;
    while(str_len > p+1){
      incr_key();
      incr_second_key();
      split_by_eight(keyb_inp_arr, p, str_len, true, true);
      p+=8;
    }
    rest_k();
    rest_s_k();
    //Serial.println(dec_st);
    exeq_sql_statement_from_string("INSERT INTO Logins (ID, Title) VALUES( '" + rec_ID + "','" + dec_st + "');");
    dec_st = "";
    show_main_menu();
    Insert_username_into_logins();
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

void Insert_username_into_logins(){
  keyb_inp = "";
  tft.fillScreen(0x2145);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter the username:");
  tft.fillRect(0, 210, 320, 240, 0xe73c);
  tft.setTextColor(0x2145, 0xe73c);
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
        tft.fillScreen(0x2145);
        tft.setTextColor(0xe73c, 0x2145);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter the username:");
        tft.fillRect(0, 210, 320, 240, 0xe73c);
        tft.setTextColor(0x2145, 0xe73c);
        tft.setTextSize(2);
        tft.setCursor(18,218);
        tft.print("Length:");
      }
  int inpl = keyb_inp.length();
  tft.setTextColor(0x2145, 0xe73c);
  tft.setCursor(100,218);
  tft.print("    ");
  tft.setCursor(100,218);
  tft.print(inpl);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
    clb_m = 1;
    tft.fillScreen(0x3186);
    tft.setTextColor(0xe73c, 0x3186);
    tft.setTextSize(1);
    tft.setCursor(0,0);
    int str_len = keyb_inp.length() + 1;
    char keyb_inp_arr[str_len];
    keyb_inp.toCharArray(keyb_inp_arr, str_len);
    int p = 0;
    while(str_len > p+1){
      incr_key();
      incr_second_key();
      split_by_eight(keyb_inp_arr, p, str_len, true, true);
      p+=8;
    }
    rest_k();
    rest_s_k();
    //Serial.println(dec_st);
    exeq_sql_statement_from_string("UPDATE Logins set Username = '" + dec_st + "' where ID = '" + rec_ID + "';");
    dec_st = "";
    show_main_menu();
    Insert_password_into_logins();
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

void Insert_password_into_logins(){
  keyb_inp = "";
  tft.fillScreen(0x2145);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter the password:");
  tft.fillRect(0, 210, 320, 240, 0xe73c);
  tft.setTextColor(0x2145, 0xe73c);
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
        tft.fillScreen(0x2145);
        tft.setTextColor(0xe73c, 0x2145);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter the password:");
        tft.fillRect(0, 210, 320, 240, 0xe73c);
        tft.setTextColor(0x2145, 0xe73c);
        tft.setTextSize(2);
        tft.setCursor(18,218);
        tft.print("Length:");
      }
  int inpl = keyb_inp.length();
  tft.setTextColor(0x2145, 0xe73c);
  tft.setCursor(100,218);
  tft.print("    ");
  tft.setCursor(100,218);
  tft.print(inpl);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
    clb_m = 1;
    tft.fillScreen(0x3186);
    tft.setTextColor(0xe73c, 0x3186);
    tft.setTextSize(1);
    tft.setCursor(0,0);
    int str_len = keyb_inp.length() + 1;
    char keyb_inp_arr[str_len];
    keyb_inp.toCharArray(keyb_inp_arr, str_len);
    int p = 0;
    while(str_len > p+1){
      incr_key();
      incr_second_key();
      split_by_eight(keyb_inp_arr, p, str_len, true, true);
      p+=8;
    }
    rest_k();
    rest_s_k();
    //Serial.println(dec_st);
    exeq_sql_statement_from_string("UPDATE Logins set Password = '" + dec_st + "' where ID = '" + rec_ID + "';");
    dec_st = "";
    show_main_menu();
    Insert_website_into_logins();
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

void Insert_website_into_logins(){
  keyb_inp = "";
  tft.fillScreen(0x2145);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter the website:");
  tft.fillRect(0, 210, 320, 240, 0xe73c);
  tft.setTextColor(0x2145, 0xe73c);
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
        tft.fillScreen(0x2145);
        tft.setTextColor(0xe73c, 0x2145);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter the website:");
        tft.fillRect(0, 210, 320, 240, 0xe73c);
        tft.setTextColor(0x2145, 0xe73c);
        tft.setTextSize(2);
        tft.setCursor(18,218);
        tft.print("Length:");
      }
  int inpl = keyb_inp.length();
  tft.setTextColor(0x2145, 0xe73c);
  tft.setCursor(100,218);
  tft.print("    ");
  tft.setCursor(100,218);
  tft.print(inpl);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
    clb_m = 1;
    tft.fillScreen(0x3186);
    tft.setTextColor(0xe73c, 0x3186);
    tft.setTextSize(1);
    tft.setCursor(0,0);
    int str_len = keyb_inp.length() + 1;
    char keyb_inp_arr[str_len];
    keyb_inp.toCharArray(keyb_inp_arr, str_len);
    int p = 0;
    while(str_len > p+1){
      incr_key();
      incr_second_key();
      split_by_eight(keyb_inp_arr, p, str_len, true, true);
      p+=8;
    }
    rest_k();
    rest_s_k();
    //Serial.println(dec_st);
    exeq_sql_statement_from_string("UPDATE Logins set Website = '" + dec_st + "' where ID = '" + rec_ID + "';");
    tft.setTextSize(2);
    tft.setCursor(0,200);
    tft.print("                                                                                                    ");
    tft.setCursor(5,200);
    tft.print("Press any key to return to");
    tft.setCursor(5,220);
    tft.print("the main menu.            ");
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

void Add_credit_card(){
  rec_ID = "";
  gen_rand_ID(40);
  Insert_title_into_the_credit_card();
}

void Insert_title_into_the_credit_card(){
  keyb_inp = "";
  tft.fillScreen(0x2145);
  tft.setTextColor(0x051c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter the title:");
  tft.fillRect(0, 210, 320, 240, 0xe73c);
  tft.setTextColor(0x2145, 0xe73c);
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
        tft.fillScreen(0x2145);
        tft.setTextColor(0x051c, 0x2145);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter the title:");
        tft.fillRect(0, 210, 320, 240, 0xe73c);
        tft.setTextColor(0x2145, 0xe73c);
        tft.setTextSize(2);
        tft.setCursor(18,218);
        tft.print("Length:");
      }
  int inpl = keyb_inp.length();
  tft.setTextColor(0x2145, 0xe73c);
  tft.setCursor(100,218);
  tft.print("    ");
  tft.setCursor(100,218);
  tft.print(inpl);
  tft.setTextColor(0x051c, 0x2145);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
    clb_m = 1;
    tft.fillScreen(0x3186);
    tft.setTextColor(0xe73c, 0x3186);
    tft.setTextSize(1);
    tft.setCursor(0,0);
    int str_len = keyb_inp.length() + 1;
    char keyb_inp_arr[str_len];
    keyb_inp.toCharArray(keyb_inp_arr, str_len);
    int p = 0;
    while(str_len > p+1){
      incr_key();
      incr_second_key();
      split_by_eight(keyb_inp_arr, p, str_len, true, true);
      p+=8;
    }
    rest_k();
    rest_s_k();
    //Serial.println(dec_st);
    exeq_sql_statement_from_string("INSERT INTO Credit_cards (ID, Title) VALUES( '" + rec_ID + "','" + dec_st + "');");
    dec_st = "";
    show_main_menu();
    Insert_cardholder_into_the_credit_card();
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

void Insert_cardholder_into_the_credit_card(){
  keyb_inp = "";
  tft.fillScreen(0x2145);
  tft.setTextColor(0x051c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter the cardholder name:");
  tft.fillRect(0, 210, 320, 240, 0xe73c);
  tft.setTextColor(0x2145, 0xe73c);
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
        tft.fillScreen(0x2145);
        tft.setTextColor(0x051c, 0x2145);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter the cardholder name:");
        tft.fillRect(0, 210, 320, 240, 0xe73c);
        tft.setTextColor(0x2145, 0xe73c);
        tft.setTextSize(2);
        tft.setCursor(18,218);
        tft.print("Length:");
      }
  int inpl = keyb_inp.length();
  tft.setTextColor(0x2145, 0xe73c);
  tft.setCursor(100,218);
  tft.print("    ");
  tft.setCursor(100,218);
  tft.print(inpl);
  tft.setTextColor(0x051c, 0x2145);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
    clb_m = 1;
    tft.fillScreen(0x3186);
    tft.setTextColor(0xe73c, 0x3186);
    tft.setTextSize(1);
    tft.setCursor(0,0);
    int str_len = keyb_inp.length() + 1;
    char keyb_inp_arr[str_len];
    keyb_inp.toCharArray(keyb_inp_arr, str_len);
    int p = 0;
    while(str_len > p+1){
      incr_key();
      incr_second_key();
      split_by_eight(keyb_inp_arr, p, str_len, true, true);
      p+=8;
    }
    rest_k();
    rest_s_k();
    //Serial.println(dec_st);
    exeq_sql_statement_from_string("UPDATE Credit_cards set Cardholder = '" + dec_st + "' where ID = '" + rec_ID + "';");
    dec_st = "";
    show_main_menu();
    Insert_card_number_into_the_credit_card();
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

void Insert_card_number_into_the_credit_card(){
  keyb_inp = "";
  tft.fillScreen(0x2145);
  tft.setTextColor(0x051c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter the card number:");
  tft.fillRect(0, 210, 320, 240, 0xe73c);
  tft.setTextColor(0x2145, 0xe73c);
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
        tft.fillScreen(0x2145);
        tft.setTextColor(0x051c, 0x2145);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter the card number:");
        tft.fillRect(0, 210, 320, 240, 0xe73c);
        tft.setTextColor(0x2145, 0xe73c);
        tft.setTextSize(2);
        tft.setCursor(18,218);
        tft.print("Length:");
      }
  int inpl = keyb_inp.length();
  tft.setTextColor(0x2145, 0xe73c);
  tft.setCursor(100,218);
  tft.print("    ");
  tft.setCursor(100,218);
  tft.print(inpl);
  tft.setTextColor(0x051c, 0x2145);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
    clb_m = 1;
    tft.fillScreen(0x3186);
    tft.setTextColor(0xe73c, 0x3186);
    tft.setTextSize(1);
    tft.setCursor(0,0);
    int str_len = keyb_inp.length() + 1;
    char keyb_inp_arr[str_len];
    keyb_inp.toCharArray(keyb_inp_arr, str_len);
    int p = 0;
    while(str_len > p+1){
      incr_key();
      incr_second_key();
      split_by_eight(keyb_inp_arr, p, str_len, true, true);
      p+=8;
    }
    rest_k();
    rest_s_k();
    //Serial.println(dec_st);
    exeq_sql_statement_from_string("UPDATE Credit_cards set Card_Number = '" + dec_st + "' where ID = '" + rec_ID + "';");
    dec_st = "";
    show_main_menu();
    Insert_expiration_date_into_the_credit_card();
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

void Insert_expiration_date_into_the_credit_card(){
  keyb_inp = "";
  tft.fillScreen(0x2145);
  tft.setTextColor(0x051c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter the expiration date:");
  tft.fillRect(0, 210, 320, 240, 0xe73c);
  tft.setTextColor(0x2145, 0xe73c);
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
        tft.fillScreen(0x2145);
        tft.setTextColor(0x051c, 0x2145);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter the expiration date:");
        tft.fillRect(0, 210, 320, 240, 0xe73c);
        tft.setTextColor(0x2145, 0xe73c);
        tft.setTextSize(2);
        tft.setCursor(18,218);
        tft.print("Length:");
      }
  int inpl = keyb_inp.length();
  tft.setTextColor(0x2145, 0xe73c);
  tft.setCursor(100,218);
  tft.print("    ");
  tft.setCursor(100,218);
  tft.print(inpl);
  tft.setTextColor(0x051c, 0x2145);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
    clb_m = 1;
    tft.fillScreen(0x3186);
    tft.setTextColor(0xe73c, 0x3186);
    tft.setTextSize(1);
    tft.setCursor(0,0);
    int str_len = keyb_inp.length() + 1;
    char keyb_inp_arr[str_len];
    keyb_inp.toCharArray(keyb_inp_arr, str_len);
    int p = 0;
    while(str_len > p+1){
      incr_key();
      incr_second_key();
      split_by_eight(keyb_inp_arr, p, str_len, true, true);
      p+=8;
    }
    rest_k();
    rest_s_k();
    //Serial.println(dec_st);
    exeq_sql_statement_from_string("UPDATE Credit_cards set Expiration_date = '" + dec_st + "' where ID = '" + rec_ID + "';");
    dec_st = "";
    show_main_menu();
    Insert_CVN_into_the_credit_card();
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

void Insert_CVN_into_the_credit_card(){
  keyb_inp = "";
  tft.fillScreen(0x2145);
  tft.setTextColor(0x051c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter the CVN:");
  tft.fillRect(0, 210, 320, 240, 0xe73c);
  tft.setTextColor(0x2145, 0xe73c);
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
        tft.fillScreen(0x2145);
        tft.setTextColor(0x051c, 0x2145);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter the CVN:");
        tft.fillRect(0, 210, 320, 240, 0xe73c);
        tft.setTextColor(0x2145, 0xe73c);
        tft.setTextSize(2);
        tft.setCursor(18,218);
        tft.print("Length:");
      }
  int inpl = keyb_inp.length();
  tft.setTextColor(0x2145, 0xe73c);
  tft.setCursor(100,218);
  tft.print("    ");
  tft.setCursor(100,218);
  tft.print(inpl);
  tft.setTextColor(0x051c, 0x2145);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
    clb_m = 1;
    tft.fillScreen(0x3186);
    tft.setTextColor(0xe73c, 0x3186);
    tft.setTextSize(1);
    tft.setCursor(0,0);
    int str_len = keyb_inp.length() + 1;
    char keyb_inp_arr[str_len];
    keyb_inp.toCharArray(keyb_inp_arr, str_len);
    int p = 0;
    while(str_len > p+1){
      incr_key();
      incr_second_key();
      split_by_eight(keyb_inp_arr, p, str_len, true, true);
      p+=8;
    }
    rest_k();
    rest_s_k();
    //Serial.println(dec_st);
    exeq_sql_statement_from_string("UPDATE Credit_cards set CVN = '" + dec_st + "' where ID = '" + rec_ID + "';");
    dec_st = "";
    show_main_menu();
    Insert_PIN_into_the_credit_card();
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

void Insert_PIN_into_the_credit_card(){
  keyb_inp = "";
  tft.fillScreen(0x2145);
  tft.setTextColor(0x051c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter the PIN:");
  tft.fillRect(0, 210, 320, 240, 0xe73c);
  tft.setTextColor(0x2145, 0xe73c);
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
        tft.fillScreen(0x2145);
        tft.setTextColor(0x051c, 0x2145);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter the PIN:");
        tft.fillRect(0, 210, 320, 240, 0xe73c);
        tft.setTextColor(0x2145, 0xe73c);
        tft.setTextSize(2);
        tft.setCursor(18,218);
        tft.print("Length:");
      }
  int inpl = keyb_inp.length();
  tft.setTextColor(0x2145, 0xe73c);
  tft.setCursor(100,218);
  tft.print("    ");
  tft.setCursor(100,218);
  tft.print(inpl);
  tft.setTextColor(0x051c, 0x2145);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
    clb_m = 1;
    tft.fillScreen(0x3186);
    tft.setTextColor(0xe73c, 0x3186);
    tft.setTextSize(1);
    tft.setCursor(0,0);
    int str_len = keyb_inp.length() + 1;
    char keyb_inp_arr[str_len];
    keyb_inp.toCharArray(keyb_inp_arr, str_len);
    int p = 0;
    while(str_len > p+1){
      incr_key();
      incr_second_key();
      split_by_eight(keyb_inp_arr, p, str_len, true, true);
      p+=8;
    }
    rest_k();
    rest_s_k();
    //Serial.println(dec_st);
    exeq_sql_statement_from_string("UPDATE Credit_cards set PIN = '" + dec_st + "' where ID = '" + rec_ID + "';");
    dec_st = "";
    show_main_menu();
    Insert_ZIP_code_into_the_credit_card();
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

void Insert_ZIP_code_into_the_credit_card(){
  keyb_inp = "";
  tft.fillScreen(0x2145);
  tft.setTextColor(0x051c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter the ZIP code:");
  tft.fillRect(0, 210, 320, 240, 0xe73c);
  tft.setTextColor(0x2145, 0xe73c);
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
        tft.fillScreen(0x2145);
        tft.setTextColor(0x051c, 0x2145);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter the ZIP code:");
        tft.fillRect(0, 210, 320, 240, 0xe73c);
        tft.setTextColor(0x2145, 0xe73c);
        tft.setTextSize(2);
        tft.setCursor(18,218);
        tft.print("Length:");
      }
  int inpl = keyb_inp.length();
  tft.setTextColor(0x2145, 0xe73c);
  tft.setCursor(100,218);
  tft.print("    ");
  tft.setCursor(100,218);
  tft.print(inpl);
  tft.setTextColor(0x051c, 0x2145);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
    clb_m = 1;
    tft.fillScreen(0x3186);
    tft.setTextColor(0xe73c, 0x3186);
    tft.setTextSize(1);
    tft.setCursor(0,0);
    int str_len = keyb_inp.length() + 1;
    char keyb_inp_arr[str_len];
    keyb_inp.toCharArray(keyb_inp_arr, str_len);
    int p = 0;
    while(str_len > p+1){
      incr_key();
      incr_second_key();
      split_by_eight(keyb_inp_arr, p, str_len, true, true);
      p+=8;
    }
    rest_k();
    rest_s_k();
    //Serial.println(dec_st);
    exeq_sql_statement_from_string("UPDATE Credit_cards set ZIP_code = '" + dec_st + "' where ID = '" + rec_ID + "';");
    dec_st = "";
    tft.setTextSize(2);
    tft.setCursor(0,200);
    tft.print("                                                                                                    ");
    tft.setCursor(5,200);
    tft.print("Press any key to return to");
    tft.setCursor(5,220);
    tft.print("the main menu.            ");
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

void Add_note(){
  rec_ID = "";
  gen_rand_ID(34);
  Insert_title_into_the_notes();
}

void Insert_title_into_the_notes(){
  keyb_inp = "";
  tft.fillScreen(0x4a49);
  tft.setTextColor(0x8606, 0x4a49);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter the title:");
  tft.fillRect(0, 210, 320, 240, 0xe73c);
  tft.setTextColor(0x4a49, 0xe73c);
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
        tft.fillScreen(0x4a49);
        tft.setTextColor(0x8606, 0x4a49);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter the title:");
        tft.fillRect(0, 210, 320, 240, 0xe73c);
        tft.setTextColor(0x4a49, 0xe73c);
        tft.setTextSize(2);
        tft.setCursor(18,218);
        tft.print("Length:");
      }
  int inpl = keyb_inp.length();
  tft.setTextColor(0x4a49, 0xe73c);
  tft.setCursor(100,218);
  tft.print("    ");
  tft.setCursor(100,218);
  tft.print(inpl);
  tft.setTextColor(0x8606, 0x4a49);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
    clb_m = 1;
    tft.fillScreen(0x3186);
    tft.setTextColor(0xe73c, 0x3186);
    tft.setTextSize(1);
    tft.setCursor(0,0);
    int str_len = keyb_inp.length() + 1;
    char keyb_inp_arr[str_len];
    keyb_inp.toCharArray(keyb_inp_arr, str_len);
    int p = 0;
    while(str_len > p+1){
      incr_key();
      incr_second_key();
      split_by_eight(keyb_inp_arr, p, str_len, true, true);
      p+=8;
    }
    rest_k();
    rest_s_k();
    //Serial.println(dec_st);
    exeq_sql_statement_from_string("INSERT INTO Notes (ID, Title) VALUES( '" + rec_ID + "','" + dec_st + "');");
    dec_st = "";
    show_main_menu();
    Insert_content_into_the_notes();
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

void Insert_content_into_the_notes(){
  keyb_inp = "";
  tft.fillScreen(0x4a49);
  tft.setTextColor(0x8606, 0x4a49);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter the note:");
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
        tft.fillScreen(0x4a49);
        tft.setTextColor(0x8606, 0x4a49);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter the note:");
        tft.fillRect(0, 210, 320, 240, 0xe73c);
        tft.setTextColor(0x4a49, 0xe73c);
        tft.setTextSize(2);
        tft.setCursor(18,218);
        tft.print("Length:");
      }
  int inpl = keyb_inp.length();
  tft.setTextColor(0x4a49, 0xe73c);
  tft.setCursor(100,218);
  tft.print("    ");
  tft.setCursor(100,218);
  tft.print(inpl);
  tft.setTextColor(0x8606, 0x4a49);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
    clb_m = 1;
    tft.fillScreen(0x3186);
    tft.setTextColor(0xe73c, 0x3186);
    tft.setTextSize(1);
    tft.setCursor(0,0);
    int str_len = keyb_inp.length() + 1;
    char keyb_inp_arr[str_len];
    keyb_inp.toCharArray(keyb_inp_arr, str_len);
    int p = 0;
    while(str_len > p+1){
      incr_key();
      incr_second_key();
      split_by_eight(keyb_inp_arr, p, str_len, true, true);
      p+=8;
    }
    rest_k();
    rest_s_k();
    //Serial.println(dec_st);
    exeq_sql_statement_from_string("UPDATE Notes set Content = '" + dec_st + "' where ID = '" + rec_ID + "';");
    dec_st = "";
    tft.setTextSize(2);
    tft.setCursor(0,200);
    tft.print("                                                                                                    ");
    tft.setCursor(5,200);
    tft.print("Press any key to return to");
    tft.setCursor(5,220);
    tft.print("the main menu.            ");
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

void Add_phone_number(){
  rec_ID = "";
  gen_rand_ID(38);
  Insert_title_into_the_phone_number();
}

void Insert_title_into_the_phone_number(){
  keyb_inp = "";
  tft.fillScreen(0xf501);
  tft.setTextColor(0x3a08, 0xf501);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter the title:");
  tft.fillRect(0, 210, 320, 240, 0xe73c);
  tft.setTextColor(0xf501, 0xe73c);
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
        tft.fillScreen(0xf501);
        tft.setTextColor(0x3a08, 0xf501);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter the title:");
        tft.fillRect(0, 210, 320, 240, 0xe73c);
        tft.setTextColor(0xf501, 0xe73c);
        tft.setTextSize(2);
        tft.setCursor(18,218);
        tft.print("Length:");
      }
  int inpl = keyb_inp.length();
  tft.setTextColor(0xf501, 0xe73c);
  tft.setCursor(100,218);
  tft.print("    ");
  tft.setCursor(100,218);
  tft.print(inpl);
  tft.setTextColor(0x3a08, 0xf501);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
    clb_m = 1;
    tft.fillScreen(0x3186);
    tft.setTextColor(0xe73c, 0x3186);
    tft.setTextSize(1);
    tft.setCursor(0,0);
    int str_len = keyb_inp.length() + 1;
    char keyb_inp_arr[str_len];
    keyb_inp.toCharArray(keyb_inp_arr, str_len);
    int p = 0;
    while(str_len > p+1){
      incr_key();
      incr_second_key();
      split_by_eight(keyb_inp_arr, p, str_len, true, true);
      p+=8;
    }
    rest_k();
    rest_s_k();
    //Serial.println(dec_st);
    exeq_sql_statement_from_string("INSERT INTO Phone_numbers (ID, Title) VALUES( '" + rec_ID + "','" + dec_st + "');");
    dec_st = "";
    show_main_menu();
    Insert_Phone_number_into_the_phone_number();
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

void Insert_Phone_number_into_the_phone_number(){
  keyb_inp = "";
  tft.fillScreen(0xf501);
  tft.setTextColor(0x3a08, 0xf501);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter the phone number:");
  tft.fillRect(0, 210, 320, 240, 0xe73c);
  tft.setTextColor(0xf501, 0xe73c);
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
        tft.fillScreen(0xf501);
        tft.setTextColor(0x3a08, 0xf501);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter the phone number:");
        tft.fillRect(0, 210, 320, 240, 0xe73c);
        tft.setTextColor(0xf501, 0xe73c);
        tft.setTextSize(2);
        tft.setCursor(18,218);
        tft.print("Length:");
      }
  int inpl = keyb_inp.length();
  tft.setTextColor(0xf501, 0xe73c);
  tft.setCursor(100,218);
  tft.print("    ");
  tft.setCursor(100,218);
  tft.print(inpl);
  tft.setTextColor(0x3a08, 0xf501);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
    clb_m = 1;
    tft.fillScreen(0x3186);
    tft.setTextColor(0xe73c, 0x3186);
    tft.setTextSize(1);
    tft.setCursor(0,0);
    int str_len = keyb_inp.length() + 1;
    char keyb_inp_arr[str_len];
    keyb_inp.toCharArray(keyb_inp_arr, str_len);
    int p = 0;
    while(str_len > p+1){
      incr_key();
      incr_second_key();
      split_by_eight(keyb_inp_arr, p, str_len, true, true);
      p+=8;
    }
    rest_k();
    rest_s_k();
    //Serial.println(dec_st);
    exeq_sql_statement_from_string("UPDATE Phone_numbers set Phone_number = '" + dec_st + "' where ID = '" + rec_ID + "';");
    dec_st = "";
    tft.setTextSize(2);
    tft.setCursor(0,200);
    tft.print("                                                                                                    ");
    tft.setCursor(5,200);
    tft.print("Press any key to return to");
    tft.setCursor(5,220);
    tft.print("the main menu.            ");
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

void Show_all_logins(){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,2);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Logins");
  if (num_of_IDs != 0){
    String IDs[num_of_IDs];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i< dec_st.length()-1; i++){
      if (dec_st.charAt(i) != '\n')
        IDs[c_id] += dec_st.charAt(i);
      else{
        c_id++;
      }
    }
    for (int i = 0; i<num_of_IDs; i++){
      if(IDs[i].length() > 0)
        IDs[i].remove(IDs[i].length() -1, 1);
    }
    dec_st = "";
    for (int i = 0; i < num_of_IDs; i++){
      Serial.print(IDs[i]);
    }
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + IDs[i] + "'");
      tft.print("Title:");
      tft.println(dec_st);
      dec_st = "";
      exeq_sql_statement_from_string("SELECT Username FROM Logins WHERE ID = '" + IDs[i] + "'");
      tft.print("Username:");
      tft.println(dec_st);
      tft.println("-----------------------------------------------------");
      dec_st = "";
    }
    /*
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + IDs[i] + "'");
      Serial.print("Title:");
      Serial.println(dec_st);
      dec_st = "";
      exeq_sql_statement_from_string("SELECT Username FROM Logins WHERE ID = '" + IDs[i] + "'");
      Serial.print("Username:");
      Serial.println(dec_st);
      dec_st = "";
      exeq_sql_statement_from_string("SELECT Password FROM Logins WHERE ID = '" + IDs[i] + "'");
      Serial.print("Password:");
      Serial.println(dec_st);
      dec_st = "";
      exeq_sql_statement_from_string("SELECT Website FROM Logins WHERE ID = '" + IDs[i] + "'");
      Serial.print("Website:");
      Serial.println(dec_st);
      dec_st = "";
    }
    */
  }
  else{
    tft.print("Empty");
  }
  tft.setTextSize(1);
  tft.setCursor(0,224);
  tft.print("                                                                                                    ");
  tft.print("                                                                                                    ");
  tft.setCursor(5,228);
  tft.print("Press any key to return to the main menu");
  keyb_inp = "";
  while (!bus.gotData()){
    bus.tick();
  }
  show_main_menu();
  return;
}

void Show_all_credit_cards(){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,2);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Credit_cards");
  if (num_of_IDs != 0){
    String IDs[num_of_IDs];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i< dec_st.length()-1; i++){
      if (dec_st.charAt(i) != '\n')
        IDs[c_id] += dec_st.charAt(i);
      else{
        c_id++;
      }
    }
    for (int i = 0; i<num_of_IDs; i++){
      if(IDs[i].length() > 0)
        IDs[i].remove(IDs[i].length() -1, 1);
    }
    dec_st = "";
    for (int i = 0; i < num_of_IDs; i++){
      Serial.print(IDs[i]);
    }
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Credit_cards WHERE ID = '" + IDs[i] + "'");
      tft.print("Title:");
      tft.println(dec_st);
      dec_st = "";
      exeq_sql_statement_from_string("SELECT Card_Number FROM Credit_cards WHERE ID = '" + IDs[i] + "'");
      tft.print("Card number:");
      tft.println(dec_st);
      tft.println("-----------------------------------------------------");
      dec_st = "";
    }
    clb_m = 0;
    /*
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Credit_cards WHERE ID = '" + IDs[i] + "'");
      Serial.print("Title:");
      Serial.println(dec_st);
      dec_st = "";
      exeq_sql_statement_from_string("SELECT Cardholder FROM Credit_cards WHERE ID = '" + IDs[i] + "'");
      Serial.print("Cardholder name:");
      Serial.println(dec_st);
      dec_st = "";
      exeq_sql_statement_from_string("SELECT Card_Number FROM Credit_cards WHERE ID = '" + IDs[i] + "'");
      Serial.print("Card number:");
      Serial.println(dec_st);
      dec_st = "";
      exeq_sql_statement_from_string("SELECT Expiration_date FROM Credit_cards WHERE ID = '" + IDs[i] + "'");
      Serial.print("Expiration date:");
      Serial.println(dec_st);
      dec_st = "";
      exeq_sql_statement_from_string("SELECT CVN FROM Credit_cards WHERE ID = '" + IDs[i] + "'");
      Serial.print("CVN:");
      Serial.println(dec_st);
      dec_st = "";
      exeq_sql_statement_from_string("SELECT PIN FROM Credit_cards WHERE ID = '" + IDs[i] + "'");
      Serial.print("PIN:");
      Serial.println(dec_st);
      dec_st = "";
      exeq_sql_statement_from_string("SELECT ZIP_code FROM Credit_cards WHERE ID = '" + IDs[i] + "'");
      Serial.print("ZIP code:");
      Serial.println(dec_st);
      dec_st = "";
    }
    */
  }
  else{
    tft.print("Empty");
  }
  tft.setTextSize(1);
  tft.setCursor(0,224);
  tft.print("                                                                                                    ");
  tft.print("                                                                                                    ");
  tft.setCursor(5,228);
  tft.print("Press any key to return to the main menu");
  keyb_inp = "";
  while (!bus.gotData()){
    bus.tick();
  }
  show_main_menu();
  return;
}

void Show_all_notes(){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,2);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Notes");
  if (num_of_IDs != 0){
    String IDs[num_of_IDs];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i< dec_st.length()-1; i++){
      if (dec_st.charAt(i) != '\n')
        IDs[c_id] += dec_st.charAt(i);
      else{
        c_id++;
      }
    }
    for (int i = 0; i<num_of_IDs; i++){
      if(IDs[i].length() > 0)
        IDs[i].remove(IDs[i].length() -1, 1);
    }
    dec_st = "";
    for (int i = 0; i < num_of_IDs; i++){
      Serial.print(IDs[i]);
    }
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Notes WHERE ID = '" + IDs[i] + "'");
      tft.print("Title:");
      tft.println(dec_st);
      dec_st = "";
      tft.println("-----------------------------------------------------");
      dec_st = "";
    }
    clb_m = 0;
  }
  else{
    tft.print("Empty");
  }
  tft.setTextSize(1);
  tft.setCursor(0,224);
  tft.print("                                                                                                    ");
  tft.print("                                                                                                    ");
  tft.setCursor(5,228);
  tft.print("Press any key to return to the main menu");
  keyb_inp = "";
  while (!bus.gotData()){
    bus.tick();
  }
  show_main_menu();
  return;
}

void Show_all_phone_numbers(){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,2);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Phone_numbers");
  if (num_of_IDs != 0){
    String IDs[num_of_IDs];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i< dec_st.length()-1; i++){
      if (dec_st.charAt(i) != '\n')
        IDs[c_id] += dec_st.charAt(i);
      else{
        c_id++;
      }
    }
    for (int i = 0; i<num_of_IDs; i++){
      if(IDs[i].length() > 0)
        IDs[i].remove(IDs[i].length() -1, 1);
    }
    dec_st = "";
    for (int i = 0; i < num_of_IDs; i++){
      Serial.print(IDs[i]);
    }
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Phone_numbers WHERE ID = '" + IDs[i] + "'");
      tft.print("Title:");
      tft.println(dec_st);
      dec_st = "";
      exeq_sql_statement_from_string("SELECT Phone_number FROM Phone_numbers WHERE ID = '" + IDs[i] + "'");
      tft.print("Phone number:");
      tft.println(dec_st);
      tft.println("-----------------------------------------------------");
      dec_st = "";
    }
    clb_m = 0;
  }
  else{
    tft.print("Empty");
  }
  tft.setTextSize(1);
  tft.setCursor(0,224);
  tft.print("                                                                                                    ");
  tft.print("                                                                                                    ");
  tft.setCursor(5,228);
  tft.print("Press any key to return to the main menu");
  keyb_inp = "";
  while (!bus.gotData()){
    bus.tick();
  }
  show_main_menu();
  return;
}

void Remove_login(){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,2);
  tft.print("Select the record to remove and press Enter");
  tft.setCursor(0,12);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Logins");
  if (num_of_IDs != 0){
    String IDs[num_of_IDs][2];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i< dec_st.length()-1; i++){
      if (dec_st.charAt(i) != '\n')
        IDs[c_id][0] += dec_st.charAt(i);
      else{
        c_id++;
      }
    }
    for (int i = 0; i<num_of_IDs; i++){
      if(IDs[i][0].length() > 0)
        IDs[i][0].remove(IDs[i][0].length() -1, 1);
    }
    dec_st = "";
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + IDs[i][0] + "'");
      IDs[i][1] = dec_st;
      dec_st = "";
    }
    clb_m = 0;
    Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++){
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      tft.print("[");
      tft.print(i);
      tft.print("] ");
      tft.println(IDs[i][1]);
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
    }
    tft.fillRect(0, 210, 320, 240, 0xe73c);
    tft.setTextColor(0x3186, 0xe73c);
    tft.setTextSize(2);
    tft.setCursor(18,218);
    tft.print("Input:");
    tft.setCursor(155,218);
    tft.print("Esc to cancel.");
    while (pr_key != 27){
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        pr_key = int(ch);
        if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11 && keyb_inp.length() < 4){
          keyb_inp += ch;
        }
        else if (ch == 127) {
          if(keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() -1, 1);
          tft.fillRect(0, 210, 320, 240, 0xe73c);
          tft.setTextColor(0x3186, 0xe73c);
          tft.setTextSize(2);
          tft.setCursor(18,218);
          tft.print("Input:");
          tft.setCursor(155,218);
          tft.print("Esc to cancel");
        }
    int inpl = keyb_inp.length();
    tft.setTextColor(0x3186, 0xe73c);
    tft.setCursor(90,218);
    tft.print("    ");
    tft.setCursor(90,218);
    tft.print(keyb_inp);
    if (pr_key == 13){
      clb_m = 1;
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0,0);
      exeq_sql_statement_from_string("DELETE FROM Logins WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
      tft.setTextSize(2);
      tft.setCursor(0,200);
      tft.print("                                                                                                    ");
      tft.setCursor(5,200);
      tft.print("Press any key to return to");
      tft.setCursor(5,220);
      tft.print("the main menu.            ");
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
  else{
    tft.print("Empty");
    tft.setTextSize(1);
    tft.setCursor(0,224);
    tft.print("                                                                                                    ");
    tft.print("                                                                                                    ");
    tft.setCursor(5,228);
    tft.print("Press any key to return to the main menu");
    keyb_inp = "";
    while (!bus.gotData()){
      bus.tick();
    }
    show_main_menu();
    return;
  }
}

void View_login(){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,2);
  tft.print("Select the record to view and press Enter");
  tft.setCursor(0,12);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Logins");
  if (num_of_IDs != 0){
    String IDs[num_of_IDs][2];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i< dec_st.length()-1; i++){
      if (dec_st.charAt(i) != '\n')
        IDs[c_id][0] += dec_st.charAt(i);
      else{
        c_id++;
      }
    }
    for (int i = 0; i<num_of_IDs; i++){
      if(IDs[i][0].length() > 0)
        IDs[i][0].remove(IDs[i][0].length() -1, 1);
    }
    dec_st = "";
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + IDs[i][0] + "'");
      IDs[i][1] = dec_st;
      dec_st = "";
    }
    clb_m = 0;
    Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++){
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      tft.print("[");
      tft.print(i);
      tft.print("] ");
      tft.println(IDs[i][1]);
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
    }
    tft.fillRect(0, 210, 320, 240, 0xe73c);
    tft.setTextColor(0x3186, 0xe73c);
    tft.setTextSize(2);
    tft.setCursor(18,218);
    tft.print("Input:");
    tft.setCursor(155,218);
    tft.print("Esc to cancel.");
    while (pr_key != 27){
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        pr_key = int(ch);
        if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11 && keyb_inp.length() < 4){
          keyb_inp += ch;
        }
        else if (ch == 127) {
          if(keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() -1, 1);
          tft.fillRect(0, 210, 320, 240, 0xe73c);
          tft.setTextColor(0x3186, 0xe73c);
          tft.setTextSize(2);
          tft.setCursor(18,218);
          tft.print("Input:");
          tft.setCursor(155,218);
          tft.print("Esc to cancel");
        }
    int inpl = keyb_inp.length();
    tft.setTextColor(0x3186, 0xe73c);
    tft.setCursor(90,218);
    tft.print("    ");
    tft.setCursor(90,218);
    tft.print(keyb_inp);
    if (pr_key == 13){
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0,2);
      clb_m = 2;
      exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
      tft.print("Title:");
      tft.println(dec_st);
      dec_st = "";
      exeq_sql_statement_from_string("SELECT Username FROM Logins WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
      tft.print("Username:");
      tft.println(dec_st);
      dec_st = "";
      exeq_sql_statement_from_string("SELECT Password FROM Logins WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
      tft.print("Password:");
      tft.println(dec_st);
      dec_st = "";
      exeq_sql_statement_from_string("SELECT Website FROM Logins WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
      tft.print("Website:");
      tft.println(dec_st);
      tft.println("-----------------------------------------------------");
      dec_st = "";
      tft.setTextSize(2);
      tft.setCursor(0,200);
      tft.print("                                                                                                    ");
      tft.setCursor(5,200);
      tft.print("Press any key to return to");
      tft.setCursor(5,220);
      tft.print("the main menu.            ");
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
  else{
    tft.print("Empty");
    tft.setTextSize(1);
    tft.setCursor(0,224);
    tft.print("                                                                                                    ");
    tft.print("                                                                                                    ");
    tft.setCursor(5,228);
    tft.print("Press any key to return to the main menu");
    keyb_inp = "";
    while (!bus.gotData()){
      bus.tick();
    }
    show_main_menu();
    return;
  }
}

void Remove_credit_card(){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,2);
  tft.print("Select the record to remove and press Enter");
  tft.setCursor(0,12);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Credit_cards");
  if (num_of_IDs != 0){
    String IDs[num_of_IDs][2];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i< dec_st.length()-1; i++){
      if (dec_st.charAt(i) != '\n')
        IDs[c_id][0] += dec_st.charAt(i);
      else{
        c_id++;
      }
    }
    for (int i = 0; i<num_of_IDs; i++){
      if(IDs[i][0].length() > 0)
        IDs[i][0].remove(IDs[i][0].length() -1, 1);
    }
    dec_st = "";
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Credit_cards WHERE ID = '" + IDs[i][0] + "'");
      IDs[i][1] = dec_st;
      dec_st = "";
    }
    clb_m = 0;
    Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++){
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      tft.print("[");
      tft.print(i);
      tft.print("] ");
      tft.println(IDs[i][1]);
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
    }
    tft.fillRect(0, 210, 320, 240, 0xe73c);
    tft.setTextColor(0x3186, 0xe73c);
    tft.setTextSize(2);
    tft.setCursor(18,218);
    tft.print("Input:");
    tft.setCursor(155,218);
    tft.print("Esc to cancel.");
    while (pr_key != 27){
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        pr_key = int(ch);
        if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11 && keyb_inp.length() < 4){
          keyb_inp += ch;
        }
        else if (ch == 127) {
          if(keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() -1, 1);
          tft.fillRect(0, 210, 320, 240, 0xe73c);
          tft.setTextColor(0x3186, 0xe73c);
          tft.setTextSize(2);
          tft.setCursor(18,218);
          tft.print("Input:");
          tft.setCursor(155,218);
          tft.print("Esc to cancel");
        }
    int inpl = keyb_inp.length();
    tft.setTextColor(0x3186, 0xe73c);
    tft.setCursor(90,218);
    tft.print("    ");
    tft.setCursor(90,218);
    tft.print(keyb_inp);
    if (pr_key == 13){
      clb_m = 1;
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0,0);
      exeq_sql_statement_from_string("DELETE FROM Credit_cards WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
      tft.setTextSize(2);
      tft.setCursor(0,200);
      tft.print("                                                                                                    ");
      tft.setCursor(5,200);
      tft.print("Press any key to return to");
      tft.setCursor(5,220);
      tft.print("the main menu.            ");
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
  else{
    tft.print("Empty");
    tft.setTextSize(1);
    tft.setCursor(0,224);
    tft.print("                                                                                                    ");
    tft.print("                                                                                                    ");
    tft.setCursor(5,228);
    tft.print("Press any key to return to the main menu");
    keyb_inp = "";
    while (!bus.gotData()){
      bus.tick();
    }
    show_main_menu();
    return;
  }
}

void View_credit_card(){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,2);
  tft.print("Select the record to view and press Enter");
  tft.setCursor(0,12);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Credit_cards");
  if (num_of_IDs != 0){
    String IDs[num_of_IDs][2];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i< dec_st.length()-1; i++){
      if (dec_st.charAt(i) != '\n')
        IDs[c_id][0] += dec_st.charAt(i);
      else{
        c_id++;
      }
    }
    for (int i = 0; i<num_of_IDs; i++){
      if(IDs[i][0].length() > 0)
        IDs[i][0].remove(IDs[i][0].length() -1, 1);
    }
    dec_st = "";
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Credit_cards WHERE ID = '" + IDs[i][0] + "'");
      IDs[i][1] = dec_st;
      dec_st = "";
    }
    clb_m = 0;
    Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++){
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      tft.print("[");
      tft.print(i);
      tft.print("] ");
      tft.println(IDs[i][1]);
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
    }
    tft.fillRect(0, 210, 320, 240, 0xe73c);
    tft.setTextColor(0x3186, 0xe73c);
    tft.setTextSize(2);
    tft.setCursor(18,218);
    tft.print("Input:");
    tft.setCursor(155,218);
    tft.print("Esc to cancel.");
    while (pr_key != 27){
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        pr_key = int(ch);
        if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11 && keyb_inp.length() < 4){
          keyb_inp += ch;
        }
        else if (ch == 127) {
          if(keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() -1, 1);
          tft.fillRect(0, 210, 320, 240, 0xe73c);
          tft.setTextColor(0x3186, 0xe73c);
          tft.setTextSize(2);
          tft.setCursor(18,218);
          tft.print("Input:");
          tft.setCursor(155,218);
          tft.print("Esc to cancel");
        }
    int inpl = keyb_inp.length();
    tft.setTextColor(0x3186, 0xe73c);
    tft.setCursor(90,218);
    tft.print("    ");
    tft.setCursor(90,218);
    tft.print(keyb_inp);
    if (pr_key == 13){
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0,2);
      clb_m = 2;
      exeq_sql_statement_from_string("SELECT Title FROM Credit_cards WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
      tft.print("Title:");
      tft.println(dec_st);
      dec_st = "";
      exeq_sql_statement_from_string("SELECT Cardholder FROM Credit_cards WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
      tft.print("Cardholder name:");
      tft.println(dec_st);
      dec_st = "";
      exeq_sql_statement_from_string("SELECT Card_Number FROM Credit_cards WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
      tft.print("Card number:");
      tft.println(dec_st);
      dec_st = "";
      exeq_sql_statement_from_string("SELECT Expiration_date FROM Credit_cards WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
      tft.print("Expiration date:");
      tft.println(dec_st);
      dec_st = "";
      exeq_sql_statement_from_string("SELECT CVN FROM Credit_cards WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
      tft.print("CVN:");
      tft.println(dec_st);
      dec_st = "";
      exeq_sql_statement_from_string("SELECT PIN FROM Credit_cards WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
      tft.print("PIN:");
      tft.println(dec_st);
      dec_st = "";
      exeq_sql_statement_from_string("SELECT ZIP_code FROM Credit_cards WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
      tft.print("ZIP code:");
      tft.println(dec_st);
      tft.println("-----------------------------------------------------");
      tft.setTextSize(2);
      tft.setCursor(0,200);
      tft.print("                                                                                                    ");
      tft.setCursor(5,200);
      tft.print("Press any key to return to");
      tft.setCursor(5,220);
      tft.print("the main menu.            ");
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
  else{
    tft.print("Empty");
    tft.setTextSize(1);
    tft.setCursor(0,224);
    tft.print("                                                                                                    ");
    tft.print("                                                                                                    ");
    tft.setCursor(5,228);
    tft.print("Press any key to return to the main menu");
    keyb_inp = "";
    while (!bus.gotData()){
      bus.tick();
    }
    show_main_menu();
    return;
  }
}

void View_note(){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,2);
  tft.print("Select the record to view and press Enter");
  tft.setCursor(0,12);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Notes");
  if (num_of_IDs != 0){
    String IDs[num_of_IDs][2];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i< dec_st.length()-1; i++){
      if (dec_st.charAt(i) != '\n')
        IDs[c_id][0] += dec_st.charAt(i);
      else{
        c_id++;
      }
    }
    for (int i = 0; i<num_of_IDs; i++){
      if(IDs[i][0].length() > 0)
        IDs[i][0].remove(IDs[i][0].length() -1, 1);
    }
    dec_st = "";
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Notes WHERE ID = '" + IDs[i][0] + "'");
      IDs[i][1] = dec_st;
      dec_st = "";
    }
    clb_m = 0;
    Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++){
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      tft.print("[");
      tft.print(i);
      tft.print("] ");
      tft.println(IDs[i][1]);
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
    }
    tft.fillRect(0, 210, 320, 240, 0xe73c);
    tft.setTextColor(0x3186, 0xe73c);
    tft.setTextSize(2);
    tft.setCursor(18,218);
    tft.print("Input:");
    tft.setCursor(155,218);
    tft.print("Esc to cancel.");
    while (pr_key != 27){
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        pr_key = int(ch);
        if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11 && keyb_inp.length() < 4){
          keyb_inp += ch;
        }
        else if (ch == 127) {
          if(keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() -1, 1);
          tft.fillRect(0, 210, 320, 240, 0xe73c);
          tft.setTextColor(0x3186, 0xe73c);
          tft.setTextSize(2);
          tft.setCursor(18,218);
          tft.print("Input:");
          tft.setCursor(155,218);
          tft.print("Esc to cancel");
        }
    int inpl = keyb_inp.length();
    tft.setTextColor(0x3186, 0xe73c);
    tft.setCursor(90,218);
    tft.print("    ");
    tft.setCursor(90,218);
    tft.print(keyb_inp);
    if (pr_key == 13){
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0,2);
      clb_m = 2;
      dec_st = "";
      exeq_sql_statement_from_string("SELECT Title FROM Notes WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
      tft.print("Title:");
      tft.println(dec_st);
      dec_st = "";
      exeq_sql_statement_from_string("SELECT Content FROM Notes WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
      tft.print("Note:");
      tft.println(dec_st);
      dec_st = "";
      tft.println("-----------------------------------------------------");
      tft.setTextSize(2);
      tft.setCursor(0,200);
      tft.print("                                                                                                    ");
      tft.setCursor(5,200);
      tft.print("Press any key to return to");
      tft.setCursor(5,220);
      tft.print("the main menu.            ");
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
  else{
    tft.print("Empty");
    tft.setTextSize(1);
    tft.setCursor(0,224);
    tft.print("                                                                                                    ");
    tft.print("                                                                                                    ");
    tft.setCursor(5,228);
    tft.print("Press any key to return to the main menu");
    keyb_inp = "";
    while (!bus.gotData()){
      bus.tick();
    }
    show_main_menu();
    return;
  }
}

void Remove_note(){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,2);
  tft.print("Select the record to remove and press Enter");
  tft.setCursor(0,12);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Notes");
  if (num_of_IDs != 0){
    String IDs[num_of_IDs][2];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i< dec_st.length()-1; i++){
      if (dec_st.charAt(i) != '\n')
        IDs[c_id][0] += dec_st.charAt(i);
      else{
        c_id++;
      }
    }
    for (int i = 0; i<num_of_IDs; i++){
      if(IDs[i][0].length() > 0)
        IDs[i][0].remove(IDs[i][0].length() -1, 1);
    }
    dec_st = "";
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Notes WHERE ID = '" + IDs[i][0] + "'");
      IDs[i][1] = dec_st;
      dec_st = "";
    }
    clb_m = 0;
    Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++){
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      tft.print("[");
      tft.print(i);
      tft.print("] ");
      tft.println(IDs[i][1]);
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
    }
    tft.fillRect(0, 210, 320, 240, 0xe73c);
    tft.setTextColor(0x3186, 0xe73c);
    tft.setTextSize(2);
    tft.setCursor(18,218);
    tft.print("Input:");
    tft.setCursor(155,218);
    tft.print("Esc to cancel.");
    while (pr_key != 27){
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        pr_key = int(ch);
        if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11 && keyb_inp.length() < 4){
          keyb_inp += ch;
        }
        else if (ch == 127) {
          if(keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() -1, 1);
          tft.fillRect(0, 210, 320, 240, 0xe73c);
          tft.setTextColor(0x3186, 0xe73c);
          tft.setTextSize(2);
          tft.setCursor(18,218);
          tft.print("Input:");
          tft.setCursor(155,218);
          tft.print("Esc to cancel");
        }
    int inpl = keyb_inp.length();
    tft.setTextColor(0x3186, 0xe73c);
    tft.setCursor(90,218);
    tft.print("    ");
    tft.setCursor(90,218);
    tft.print(keyb_inp);
    if (pr_key == 13){
      clb_m = 1;
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0,0);
      exeq_sql_statement_from_string("DELETE FROM Notes WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
      tft.setTextSize(2);
      tft.setCursor(0,200);
      tft.print("                                                                                                    ");
      tft.setCursor(5,200);
      tft.print("Press any key to return to");
      tft.setCursor(5,220);
      tft.print("the main menu.            ");
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
  else{
    tft.print("Empty");
    tft.setTextSize(1);
    tft.setCursor(0,224);
    tft.print("                                                                                                    ");
    tft.print("                                                                                                    ");
    tft.setCursor(5,228);
    tft.print("Press any key to return to the main menu");
    keyb_inp = "";
    while (!bus.gotData()){
      bus.tick();
    }
    show_main_menu();
    return;
  }
}

void View_phone_number(){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,2);
  tft.print("Select the record to view and press Enter");
  tft.setCursor(0,12);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Phone_numbers");
  if (num_of_IDs != 0){
    String IDs[num_of_IDs][2];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i< dec_st.length()-1; i++){
      if (dec_st.charAt(i) != '\n')
        IDs[c_id][0] += dec_st.charAt(i);
      else{
        c_id++;
      }
    }
    for (int i = 0; i<num_of_IDs; i++){
      if(IDs[i][0].length() > 0)
        IDs[i][0].remove(IDs[i][0].length() -1, 1);
    }
    dec_st = "";
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Phone_numbers WHERE ID = '" + IDs[i][0] + "'");
      IDs[i][1] = dec_st;
      dec_st = "";
    }
    clb_m = 0;
    Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++){
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      tft.print("[");
      tft.print(i);
      tft.print("] ");
      tft.println(IDs[i][1]);
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
    }
    tft.fillRect(0, 210, 320, 240, 0xe73c);
    tft.setTextColor(0x3186, 0xe73c);
    tft.setTextSize(2);
    tft.setCursor(18,218);
    tft.print("Input:");
    tft.setCursor(155,218);
    tft.print("Esc to cancel.");
    while (pr_key != 27){
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        pr_key = int(ch);
        if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11 && keyb_inp.length() < 4){
          keyb_inp += ch;
        }
        else if (ch == 127) {
          if(keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() -1, 1);
          tft.fillRect(0, 210, 320, 240, 0xe73c);
          tft.setTextColor(0x3186, 0xe73c);
          tft.setTextSize(2);
          tft.setCursor(18,218);
          tft.print("Input:");
          tft.setCursor(155,218);
          tft.print("Esc to cancel");
        }
    int inpl = keyb_inp.length();
    tft.setTextColor(0x3186, 0xe73c);
    tft.setCursor(90,218);
    tft.print("    ");
    tft.setCursor(90,218);
    tft.print(keyb_inp);
    if (pr_key == 13){
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0,2);
      clb_m = 2;
      dec_st = "";
      exeq_sql_statement_from_string("SELECT Title FROM Phone_numbers WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
      tft.print("Title:");
      tft.println(dec_st);
      dec_st = "";
      exeq_sql_statement_from_string("SELECT Phone_number FROM Phone_numbers WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
      tft.print("Note:");
      tft.println(dec_st);
      dec_st = "";
      tft.println("-----------------------------------------------------");
      tft.setTextSize(2);
      tft.setCursor(0,200);
      tft.print("                                                                                                    ");
      tft.setCursor(5,200);
      tft.print("Press any key to return to");
      tft.setCursor(5,220);
      tft.print("the main menu.            ");
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
  else{
    tft.print("Empty");
    tft.setTextSize(1);
    tft.setCursor(0,224);
    tft.print("                                                                                                    ");
    tft.print("                                                                                                    ");
    tft.setCursor(5,228);
    tft.print("Press any key to return to the main menu");
    keyb_inp = "";
    while (!bus.gotData()){
      bus.tick();
    }
    show_main_menu();
    return;
  }
}

void Remove_phone_number(){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,2);
  tft.print("Select the record to remove and press Enter");
  tft.setCursor(0,12);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Phone_numbers");
  if (num_of_IDs != 0){
    String IDs[num_of_IDs][2];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i< dec_st.length()-1; i++){
      if (dec_st.charAt(i) != '\n')
        IDs[c_id][0] += dec_st.charAt(i);
      else{
        c_id++;
      }
    }
    for (int i = 0; i<num_of_IDs; i++){
      if(IDs[i][0].length() > 0)
        IDs[i][0].remove(IDs[i][0].length() -1, 1);
    }
    dec_st = "";
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Phone_numbers WHERE ID = '" + IDs[i][0] + "'");
      IDs[i][1] = dec_st;
      dec_st = "";
    }
    clb_m = 0;
    Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++){
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      tft.print("[");
      tft.print(i);
      tft.print("] ");
      tft.println(IDs[i][1]);
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
    }
    tft.fillRect(0, 210, 320, 240, 0xe73c);
    tft.setTextColor(0x3186, 0xe73c);
    tft.setTextSize(2);
    tft.setCursor(18,218);
    tft.print("Input:");
    tft.setCursor(155,218);
    tft.print("Esc to cancel.");
    while (pr_key != 27){
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        pr_key = int(ch);
        if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11 && keyb_inp.length() < 4){
          keyb_inp += ch;
        }
        else if (ch == 127) {
          if(keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() -1, 1);
          tft.fillRect(0, 210, 320, 240, 0xe73c);
          tft.setTextColor(0x3186, 0xe73c);
          tft.setTextSize(2);
          tft.setCursor(18,218);
          tft.print("Input:");
          tft.setCursor(155,218);
          tft.print("Esc to cancel");
        }
    int inpl = keyb_inp.length();
    tft.setTextColor(0x3186, 0xe73c);
    tft.setCursor(90,218);
    tft.print("    ");
    tft.setCursor(90,218);
    tft.print(keyb_inp);
    if (pr_key == 13){
      clb_m = 1;
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0,0);
      exeq_sql_statement_from_string("DELETE FROM Phone_numbers WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
      tft.setTextSize(2);
      tft.setCursor(0,200);
      tft.print("                                                                                                    ");
      tft.setCursor(5,200);
      tft.print("Press any key to return to");
      tft.setCursor(5,220);
      tft.print("the main menu.            ");
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
  else{
    tft.print("Empty");
    tft.setTextSize(1);
    tft.setCursor(0,224);
    tft.print("                                                                                                    ");
    tft.print("                                                                                                    ");
    tft.setCursor(5,228);
    tft.print("Press any key to return to the main menu");
    keyb_inp = "";
    while (!bus.gotData()){
      bus.tick();
    }
    show_main_menu();
    return;
  }
}

void Edit_login(){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,2);
  tft.print("Select the record to edit and press Enter");
  tft.setCursor(0,12);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Logins");
  if (num_of_IDs != 0){
    String IDs[num_of_IDs][2];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i< dec_st.length()-1; i++){
      if (dec_st.charAt(i) != '\n')
        IDs[c_id][0] += dec_st.charAt(i);
      else{
        c_id++;
      }
    }
    for (int i = 0; i<num_of_IDs; i++){
      if(IDs[i][0].length() > 0)
        IDs[i][0].remove(IDs[i][0].length() -1, 1);
    }
    dec_st = "";
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + IDs[i][0] + "'");
      IDs[i][1] = dec_st;
      dec_st = "";
    }
    clb_m = 0;
    Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++){
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      tft.print("[");
      tft.print(i);
      tft.print("] ");
      tft.println(IDs[i][1]);
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
    }
    tft.fillRect(0, 210, 320, 240, 0xe73c);
    tft.setTextColor(0x3186, 0xe73c);
    tft.setTextSize(2);
    tft.setCursor(18,218);
    tft.print("Input:");
    tft.setCursor(155,218);
    tft.print("Esc to cancel.");
    while (pr_key != 27){
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        pr_key = int(ch);
        if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11 && keyb_inp.length() < 4){
          keyb_inp += ch;
        }
        else if (ch == 127) {
          if(keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() -1, 1);
          tft.fillRect(0, 210, 320, 240, 0xe73c);
          tft.setTextColor(0x3186, 0xe73c);
          tft.setTextSize(2);
          tft.setCursor(18,218);
          tft.print("Input:");
          tft.setCursor(155,218);
          tft.print("Esc to cancel");
        }
    int inpl = keyb_inp.length();
    tft.setTextColor(0x3186, 0xe73c);
    tft.setCursor(90,218);
    tft.print("    ");
    tft.setCursor(90,218);
    tft.print(keyb_inp);
    if (pr_key == 13){
      int selected_id = keyb_inp.toInt();
      keyb_inp = "";
      tft.fillScreen(0xef3c);
      tft.setTextColor(0xd827, 0xef3c);
      tft.setTextSize(2);
      tft.fillRect(312, 0, 320, 240, 0x12ea);
      tft.setCursor(0,5);
      tft.println("Enter the new password:");
      tft.fillRect(0, 210, 320, 240, 0xe73c);
      tft.setTextColor(0x2145, 0xe73c);
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
            tft.fillScreen(0xef3c);
            tft.setTextColor(0xd827, 0xef3c);
            tft.setTextSize(2);
            tft.fillRect(312, 0, 320, 240, 0x12ea);
            tft.fillRect(312, 0, 320, 240, 0x12ea);
            tft.setCursor(0,5);
            tft.println("Enter the new password:");
            tft.fillRect(0, 210, 320, 240, 0xe73c);
            tft.setTextColor(0x2145, 0xe73c);
            tft.setTextSize(2);
            tft.setCursor(18,218);
            tft.print("Length:");
      }
      int inpl = keyb_inp.length();
      tft.setTextColor(0x2145, 0xe73c);
      tft.setCursor(100,218);
      tft.print("    ");
      tft.setCursor(100,218);
      tft.print(inpl);
      tft.setTextColor(0xd827, 0xef3c);
      tft.setCursor(0,25);
      tft.println(keyb_inp);
      if (pr_key == 13){
        clb_m = 1;
        dec_st = "";
        tft.fillScreen(0x3186);
        tft.setTextColor(0xe73c, 0x3186);
        tft.setTextSize(1);
        tft.setCursor(0,0);
        int str_len = keyb_inp.length() + 1;
        char keyb_inp_arr[str_len];
        keyb_inp.toCharArray(keyb_inp_arr, str_len);
        int p = 0;
        while(str_len > p+1){
          incr_key();
          incr_second_key();
          split_by_eight(keyb_inp_arr, p, str_len, true, true);
          p+=8;
        }
        rest_k();
        rest_s_k();
        //Serial.println(dec_st);
        exeq_sql_statement_from_string("UPDATE Logins set Password = '" + dec_st + "' where ID = '" + IDs[selected_id][0] + "';");
        dec_st = "";
        tft.setTextSize(2);
        tft.setCursor(0,200);
        tft.print("                                                                                                    ");
        tft.setCursor(5,200);
        tft.print("Press any key to return to");
        tft.setCursor(5,220);
        tft.print("the main menu.            ");
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
    if (pr_key == 27){
      keyb_inp = "";
      show_main_menu();
      return;
    }
   } 
  }
 
  }
  else{
    tft.print("Empty");
    tft.setTextSize(1);
    tft.setCursor(0,224);
    tft.print("                                                                                                    ");
    tft.print("                                                                                                    ");
    tft.setCursor(5,228);
    tft.print("Press any key to return to the main menu");
    keyb_inp = "";
    while (!bus.gotData()){
      bus.tick();
    }
    show_main_menu();
    return;
  }
}

void Edit_credit_card(){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,2);
  tft.print("Select the record to edit and press Enter");
  tft.setCursor(0,12);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Credit_cards");
  if (num_of_IDs != 0){
    String IDs[num_of_IDs][2];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i< dec_st.length()-1; i++){
      if (dec_st.charAt(i) != '\n')
        IDs[c_id][0] += dec_st.charAt(i);
      else{
        c_id++;
      }
    }
    for (int i = 0; i<num_of_IDs; i++){
      if(IDs[i][0].length() > 0)
        IDs[i][0].remove(IDs[i][0].length() -1, 1);
    }
    dec_st = "";
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Credit_cards WHERE ID = '" + IDs[i][0] + "'");
      IDs[i][1] = dec_st;
      dec_st = "";
    }
    clb_m = 0;
    Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++){
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      tft.print("[");
      tft.print(i);
      tft.print("] ");
      tft.println(IDs[i][1]);
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
    }
    tft.fillRect(0, 210, 320, 240, 0xe73c);
    tft.setTextColor(0x3186, 0xe73c);
    tft.setTextSize(2);
    tft.setCursor(18,218);
    tft.print("Input:");
    tft.setCursor(155,218);
    tft.print("Esc to cancel.");
    while (pr_key != 27){
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        pr_key = int(ch);
        if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11 && keyb_inp.length() < 4){
          keyb_inp += ch;
        }
        else if (ch == 127) {
          if(keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() -1, 1);
          tft.fillRect(0, 210, 320, 240, 0xe73c);
          tft.setTextColor(0x3186, 0xe73c);
          tft.setTextSize(2);
          tft.setCursor(18,218);
          tft.print("Input:");
          tft.setCursor(155,218);
          tft.print("Esc to cancel");
        }
    int inpl = keyb_inp.length();
    tft.setTextColor(0x3186, 0xe73c);
    tft.setCursor(90,218);
    tft.print("    ");
    tft.setCursor(90,218);
    tft.print(keyb_inp);
    if (pr_key == 13){
      int selected_id = keyb_inp.toInt();
      keyb_inp = "";
      tft.fillScreen(0xef3c);
      tft.setTextColor(0xd827, 0xef3c);
      tft.setTextSize(2);
      tft.fillRect(312, 0, 320, 240, 0x12ea);
      tft.setCursor(0,5);
      tft.println("Enter the new PIN:");
      tft.fillRect(0, 210, 320, 240, 0xe73c);
      tft.setTextColor(0x2145, 0xe73c);
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
            tft.fillScreen(0xef3c);
            tft.setTextColor(0xd827, 0xef3c);
            tft.setTextSize(2);
            tft.fillRect(312, 0, 320, 240, 0x12ea);
            tft.fillRect(312, 0, 320, 240, 0x12ea);
            tft.setCursor(0,5);
            tft.println("Enter the new PIN:");
            tft.fillRect(0, 210, 320, 240, 0xe73c);
            tft.setTextColor(0x2145, 0xe73c);
            tft.setTextSize(2);
            tft.setCursor(18,218);
            tft.print("Length:");
      }
      int inpl = keyb_inp.length();
      tft.setTextColor(0x2145, 0xe73c);
      tft.setCursor(100,218);
      tft.print("    ");
      tft.setCursor(100,218);
      tft.print(inpl);
      tft.setTextColor(0xd827, 0xef3c);
      tft.setCursor(0,25);
      tft.println(keyb_inp);
      if (pr_key == 13){
        clb_m = 1;
        dec_st = "";
        tft.fillScreen(0x3186);
        tft.setTextColor(0xe73c, 0x3186);
        tft.setTextSize(1);
        tft.setCursor(0,0);
        int str_len = keyb_inp.length() + 1;
        char keyb_inp_arr[str_len];
        keyb_inp.toCharArray(keyb_inp_arr, str_len);
        int p = 0;
        while(str_len > p+1){
          incr_key();
          incr_second_key();
          split_by_eight(keyb_inp_arr, p, str_len, true, true);
          p+=8;
        }
        rest_k();
        rest_s_k();
        //Serial.println(dec_st);
        exeq_sql_statement_from_string("UPDATE Credit_cards set PIN = '" + dec_st + "' where ID = '" + IDs[selected_id][0] + "';");
        dec_st = "";
        tft.setTextSize(2);
        tft.setCursor(0,200);
        tft.print("                                                                                                    ");
        tft.setCursor(5,200);
        tft.print("Press any key to return to");
        tft.setCursor(5,220);
        tft.print("the main menu.            ");
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
    if (pr_key == 27){
      keyb_inp = "";
      show_main_menu();
      return;
    }
   } 
  }
 
  }
  else{
    tft.print("Empty");
    tft.setTextSize(1);
    tft.setCursor(0,224);
    tft.print("                                                                                                    ");
    tft.print("                                                                                                    ");
    tft.setCursor(5,228);
    tft.print("Press any key to return to the main menu");
    keyb_inp = "";
    while (!bus.gotData()){
      bus.tick();
    }
    show_main_menu();
    return;
  }
}

void Edit_note(){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,2);
  tft.print("Select the record to edit and press Enter");
  tft.setCursor(0,12);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Notes");
  if (num_of_IDs != 0){
    String IDs[num_of_IDs][2];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i< dec_st.length()-1; i++){
      if (dec_st.charAt(i) != '\n')
        IDs[c_id][0] += dec_st.charAt(i);
      else{
        c_id++;
      }
    }
    for (int i = 0; i<num_of_IDs; i++){
      if(IDs[i][0].length() > 0)
        IDs[i][0].remove(IDs[i][0].length() -1, 1);
    }
    dec_st = "";
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Notes WHERE ID = '" + IDs[i][0] + "'");
      IDs[i][1] = dec_st;
      dec_st = "";
    }
    clb_m = 0;
    Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++){
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      tft.print("[");
      tft.print(i);
      tft.print("] ");
      tft.println(IDs[i][1]);
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
    }
    tft.fillRect(0, 210, 320, 240, 0xe73c);
    tft.setTextColor(0x3186, 0xe73c);
    tft.setTextSize(2);
    tft.setCursor(18,218);
    tft.print("Input:");
    tft.setCursor(155,218);
    tft.print("Esc to cancel.");
    while (pr_key != 27){
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        pr_key = int(ch);
        if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11 && keyb_inp.length() < 4){
          keyb_inp += ch;
        }
        else if (ch == 127) {
          if(keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() -1, 1);
          tft.fillRect(0, 210, 320, 240, 0xe73c);
          tft.setTextColor(0x3186, 0xe73c);
          tft.setTextSize(2);
          tft.setCursor(18,218);
          tft.print("Input:");
          tft.setCursor(155,218);
          tft.print("Esc to cancel");
        }
    int inpl = keyb_inp.length();
    tft.setTextColor(0x3186, 0xe73c);
    tft.setCursor(90,218);
    tft.print("    ");
    tft.setCursor(90,218);
    tft.print(keyb_inp);
    if (pr_key == 13){
      int selected_id = keyb_inp.toInt();
      keyb_inp = "";
      tft.fillScreen(0xef3c);
      tft.setTextColor(0xd827, 0xef3c);
      tft.setTextSize(2);
      tft.fillRect(312, 0, 320, 240, 0x12ea);
      tft.setCursor(0,5);
      tft.println("Enter the new note:");
      tft.fillRect(0, 210, 320, 240, 0xe73c);
      tft.setTextColor(0x2145, 0xe73c);
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
            tft.fillScreen(0xef3c);
            tft.setTextColor(0xd827, 0xef3c);
            tft.setTextSize(2);
            tft.fillRect(312, 0, 320, 240, 0x12ea);
            tft.fillRect(312, 0, 320, 240, 0x12ea);
            tft.setCursor(0,5);
            tft.println("Enter the new note:");
            tft.fillRect(0, 210, 320, 240, 0xe73c);
            tft.setTextColor(0x2145, 0xe73c);
            tft.setTextSize(2);
            tft.setCursor(18,218);
            tft.print("Length:");
      }
      int inpl = keyb_inp.length();
      tft.setTextColor(0x2145, 0xe73c);
      tft.setCursor(100,218);
      tft.print("    ");
      tft.setCursor(100,218);
      tft.print(inpl);
      tft.setTextColor(0xd827, 0xef3c);
      tft.setCursor(0,25);
      tft.println(keyb_inp);
      if (pr_key == 13){
        clb_m = 1;
        dec_st = "";
        tft.fillScreen(0x3186);
        tft.setTextColor(0xe73c, 0x3186);
        tft.setTextSize(1);
        tft.setCursor(0,0);
        int str_len = keyb_inp.length() + 1;
        char keyb_inp_arr[str_len];
        keyb_inp.toCharArray(keyb_inp_arr, str_len);
        int p = 0;
        while(str_len > p+1){
          incr_key();
          incr_second_key();
          split_by_eight(keyb_inp_arr, p, str_len, true, true);
          p+=8;
        }
        rest_k();
        rest_s_k();
        //Serial.println(dec_st);
        exeq_sql_statement_from_string("UPDATE Notes set Content = '" + dec_st + "' where ID = '" + IDs[selected_id][0] + "';");
        dec_st = "";
        tft.setTextSize(2);
        tft.setCursor(0,200);
        tft.print("                                                                                                    ");
        tft.setCursor(5,200);
        tft.print("Press any key to return to");
        tft.setCursor(5,220);
        tft.print("the main menu.            ");
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
    if (pr_key == 27){
      keyb_inp = "";
      show_main_menu();
      return;
    }
   } 
  }
 
  }
  else{
    tft.print("Empty");
    tft.setTextSize(1);
    tft.setCursor(0,224);
    tft.print("                                                                                                    ");
    tft.print("                                                                                                    ");
    tft.setCursor(5,228);
    tft.print("Press any key to return to the main menu");
    keyb_inp = "";
    while (!bus.gotData()){
      bus.tick();
    }
    show_main_menu();
    return;
  }
}

void Edit_phone_number(){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,2);
  tft.print("Select the record to edit and press Enter");
  tft.setCursor(0,12);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Phone_numbers");
  if (num_of_IDs != 0){
    String IDs[num_of_IDs][2];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i< dec_st.length()-1; i++){
      if (dec_st.charAt(i) != '\n')
        IDs[c_id][0] += dec_st.charAt(i);
      else{
        c_id++;
      }
    }
    for (int i = 0; i<num_of_IDs; i++){
      if(IDs[i][0].length() > 0)
        IDs[i][0].remove(IDs[i][0].length() -1, 1);
    }
    dec_st = "";
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Phone_numbers WHERE ID = '" + IDs[i][0] + "'");
      IDs[i][1] = dec_st;
      dec_st = "";
    }
    clb_m = 0;
    Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++){
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      tft.print("[");
      tft.print(i);
      tft.print("] ");
      tft.println(IDs[i][1]);
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
    }
    tft.fillRect(0, 210, 320, 240, 0xe73c);
    tft.setTextColor(0x3186, 0xe73c);
    tft.setTextSize(2);
    tft.setCursor(18,218);
    tft.print("Input:");
    tft.setCursor(155,218);
    tft.print("Esc to cancel.");
    while (pr_key != 27){
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        pr_key = int(ch);
        if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11 && keyb_inp.length() < 4){
          keyb_inp += ch;
        }
        else if (ch == 127) {
          if(keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() -1, 1);
          tft.fillRect(0, 210, 320, 240, 0xe73c);
          tft.setTextColor(0x3186, 0xe73c);
          tft.setTextSize(2);
          tft.setCursor(18,218);
          tft.print("Input:");
          tft.setCursor(155,218);
          tft.print("Esc to cancel");
        }
    int inpl = keyb_inp.length();
    tft.setTextColor(0x3186, 0xe73c);
    tft.setCursor(90,218);
    tft.print("    ");
    tft.setCursor(90,218);
    tft.print(keyb_inp);
    if (pr_key == 13){
      int selected_id = keyb_inp.toInt();
      keyb_inp = "";
      tft.fillScreen(0xef3c);
      tft.setTextColor(0xd827, 0xef3c);
      tft.setTextSize(2);
      tft.fillRect(312, 0, 320, 240, 0x12ea);
      tft.setCursor(0,5);
      tft.println("Enter the new phone number:");
      tft.fillRect(0, 210, 320, 240, 0xe73c);
      tft.setTextColor(0x2145, 0xe73c);
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
            tft.fillScreen(0xef3c);
            tft.setTextColor(0xd827, 0xef3c);
            tft.setTextSize(2);
            tft.fillRect(312, 0, 320, 240, 0x12ea);
            tft.fillRect(312, 0, 320, 240, 0x12ea);
            tft.setCursor(0,5);
            tft.println("Enter the new phone number:");
            tft.fillRect(0, 210, 320, 240, 0xe73c);
            tft.setTextColor(0x2145, 0xe73c);
            tft.setTextSize(2);
            tft.setCursor(18,218);
            tft.print("Length:");
      }
      int inpl = keyb_inp.length();
      tft.setTextColor(0x2145, 0xe73c);
      tft.setCursor(100,218);
      tft.print("    ");
      tft.setCursor(100,218);
      tft.print(inpl);
      tft.setTextColor(0xd827, 0xef3c);
      tft.setCursor(0,25);
      tft.println(keyb_inp);
      if (pr_key == 13){
        clb_m = 1;
        dec_st = "";
        tft.fillScreen(0x3186);
        tft.setTextColor(0xe73c, 0x3186);
        tft.setTextSize(1);
        tft.setCursor(0,0);
        int str_len = keyb_inp.length() + 1;
        char keyb_inp_arr[str_len];
        keyb_inp.toCharArray(keyb_inp_arr, str_len);
        int p = 0;
        while(str_len > p+1){
          incr_key();
          incr_second_key();
          split_by_eight(keyb_inp_arr, p, str_len, true, true);
          p+=8;
        }
        rest_k();
        rest_s_k();
        //Serial.println(dec_st);
        exeq_sql_statement_from_string("UPDATE Phone_numbers set Phone_number = '" + dec_st + "' where ID = '" + IDs[selected_id][0] + "';");
        dec_st = "";
        tft.setTextSize(2);
        tft.setCursor(0,200);
        tft.print("                                                                                                    ");
        tft.setCursor(5,200);
        tft.print("Press any key to return to");
        tft.setCursor(5,220);
        tft.print("the main menu.            ");
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
    if (pr_key == 27){
      keyb_inp = "";
      show_main_menu();
      return;
    }
   } 
  }
 
  }
  else{
    tft.print("Empty");
    tft.setTextSize(1);
    tft.setCursor(0,224);
    tft.print("                                                                                                    ");
    tft.print("                                                                                                    ");
    tft.setCursor(5,228);
    tft.print("Press any key to return to the main menu");
    keyb_inp = "";
    while (!bus.gotData()){
      bus.tick();
    }
    show_main_menu();
    return;
  }
}

void setup() {
  Serial.begin(115200);
  mySerial.begin(9600);
  Serial.println("\nProject Midbar\n");
  tft.begin();
  tft.setRotation(1);
  spf_ok = false;
  m = 2; // 0- Set AES to 128-bit mode; 1 - Set AES to 192-bit mode; 2 - Set AES to 256-bit mode
  Unlock_device();
  if (SPIFFS.begin(true)) {
    spf_ok = true;
  }
  else{
    Serial.println("An Error has occurred while mounting SPIFFS");
    return;
  }
  // list SPIFFS contents
  File root = SPIFFS.open("/");
  if (!root) {
      Serial.println("- failed to open directory");
      return;
  }
  if (!root.isDirectory()) {
      Serial.println(" - not a directory");
      return;
  }
  /*
  File file = root.openNextFile();
  while (file) {
      if (file.isDirectory()) {
          Serial.print("  DIR : ");
          Serial.println(file.name());
      } else {
          Serial.print("  FILE: ");
          Serial.print(file.name());
          Serial.print("\tSIZE: ");
          Serial.println(file.size());
      }
      file = root.openNextFile();
  }
  */
   sqlite3_initialize();
   create_login_table();
   create_credit_card_table();
   create_notes_table();
   create_numbers_table();
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
  if (esp_now_add_peer(&peerInfo) == ESP_OK){
    peer_ok = true;
  }
  else{
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
    
    if (pr_key == 9)
      send_text_from_keyb();
    
    if (cur_pos == 0 && pr_key == 49) // Login.1
      Add_login();
    if (cur_pos == 0 && pr_key == 50) // Login.2
      Edit_login();
    if (cur_pos == 0 && pr_key == 51) // Login.3
      Remove_login();
    if (cur_pos == 0 && pr_key == 52) // Login.4
      View_login();
    if (cur_pos == 0 && pr_key == 53) // Login.5
      Show_all_logins();

    if (cur_pos == 1 && pr_key == 49) // Credit card.1
      Add_credit_card();
    if (cur_pos == 1 && pr_key == 50) // Credit card.2
      Edit_credit_card();
    if (cur_pos == 1 && pr_key == 51) // Credit card.3
      Remove_credit_card();
    if (cur_pos == 1 && pr_key == 52) // Credit card.4
      View_credit_card();
    if (cur_pos == 1 && pr_key == 53) // Credit card.5
      Show_all_credit_cards();

    if (cur_pos == 2 && pr_key == 49) // Note.1
      Add_note();
    if (cur_pos == 2 && pr_key == 50) // Note.2
      Edit_note();
    if (cur_pos == 2 && pr_key == 51) // Note.3
      Remove_note();
    if (cur_pos == 2 && pr_key == 52) // Note.4
      View_note();
    if (cur_pos == 2 && pr_key == 53) // Note.5
      Show_all_notes();

    if (cur_pos == 3 && pr_key == 49) // Phone number.1
      Add_phone_number();
    if (cur_pos == 3 && pr_key == 50) // Phone number.1
      Edit_phone_number();
    if (cur_pos == 3 && pr_key == 51) // Phone number.3
      Remove_phone_number();
    if (cur_pos == 3 && pr_key == 52) // Phone number.4
      View_phone_number();
    if (cur_pos == 3 && pr_key == 53) // Phone number.5
      Show_all_phone_numbers();
      
    if (cur_pos == 4 && pr_key == 49) // Encryption.1
      enc_text();
    if (cur_pos == 4 && pr_key == 50) // Encryption.2
      enc_text_from_ser();
    if (cur_pos == 4 && pr_key == 51) // Encryption.3
      dec_text();

    if (cur_pos == 5 && pr_key == 49) // SQLite3.1
      exeq_sql_keyb();
    if (cur_pos == 5 && pr_key == 50) // SQLite3.2
      exeq_sql_from_ser();
      
    if (cur_pos == 6 && pr_key == 49) // SHA512.1
      hash_str();
    if (cur_pos == 6 && pr_key == 50) // SHA512.2
      hash_str_from_ser();

    if (cur_pos == 7 && pr_key == 49) // File.1
      Create_file();
    if (cur_pos == 7 && pr_key == 50) // File.2
      Remove_file();
    if (cur_pos == 7 && pr_key == 51) // File.3
      View_file();
    if (cur_pos == 7 && pr_key == 52){ // File.4
      File root = SPIFFS.open("/");
      File file = root.openNextFile();
      while(file){
        Serial.print("FILE: ");
        Serial.println(file.name());
        file = root.openNextFile();
      }
    }
    
    disp_cur_pos();
  }
}
