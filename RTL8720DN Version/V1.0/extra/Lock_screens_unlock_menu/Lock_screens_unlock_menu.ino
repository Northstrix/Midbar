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
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/techpaul/PS2KeyMap
*/
// Wire Peripheral Receiver
// by Nicholas Zambetti <http://www.zambetti.com>

// Demonstrates use of the Wire library
// Receives data as an I2C/TWI Peripheral device
// Refer to the "Wire Master Writer" example for use with this

// Created 29 March 2006

// This example code is in the public domain.

/*

 Example guide:
 https://www.amebaiot.com/en/amebad-arduino-i2c-4/
 */

#include <FlashMemory.h>
#include <Wire.h>
#include "SPI.h"
#include "AmebaILI9341.h"
#include "aes.h"
#include "blowfish.h"
#include "Crypto.h"
#include "midbaricon.h"

#define TFT_RESET       6
#define TFT_DC          2
#define TFT_CS          SPI_SS
#define SPI_BUS         SPI

AmebaILI9341 tft = AmebaILI9341(TFT_CS, TFT_DC, TFT_RESET, SPI_BUS);

String kderalgs = "5t45ZuM8z07OO7m1xMpPpv1mi4Md7q34xtz";
byte hmackey[] = {"yDd0KfbfZsW2xN5s5DtpiEU4DvdUldNWT2tEM6nKIUsW35p14GL2mBDsS173ZYboEIdQwQiQrUw14fo2yOB2P1oQK04f51qA53380TIOc6I0zejz8yWgol5xP021sbZdO"};
uint8_t AES_key[32] = {
   0xd1,0xf0,0x68,0x5b,
   0x33,0xa0,0xb1,0x73,
   0xb6,0x25,0x54,0xf9,
   0xdd,0x2c,0xd3,0x1d,
   0xc1,0x93,0xb3,0x14,
   0x16,0x76,0x28,0x59,
   0x04,0x85,0xd4,0x24,
   0x9d,0xe0,0x2a,0x74
};

unsigned char Blwfsh_key[] = {
   0xd1,0xf0,0x68,0x5b,
   0x33,0xa0,0xb1,0x73,
   0xb6,0x25,0x54,0xf9,
   0xdd,0x2c,0xd3,0x1d,
   0xc1,0x93,0xb3,0x14,
   0x16,0x76,0x28,0x69
};

unsigned char back_Blwfsh_key[16];
uint8_t back_AES_key[32];
Blowfish blowfish;
String keyboard_input;
int curr_key;
int m;
byte i2c_data;
const uint16_t current_inact_clr = 0x051b;
const uint16_t five_six_five_red_color = 0xf940;
bool finish_input;
bool act;
bool rec_d;
byte trash;
String dec_st;
String dec_tag;
char iv[16];
char array_for_CBC_mode[16];
bool xor_with_ct;
bool decrypt_tag;

//#define ILI9341_SPI_FREQUENCY 55000000

void back_keys() {
  back_AES_k();
  back_Bl_k();
}

void rest_keys() {
  rest_AES_k();
  rest_Bl_k();
}

void clear_variables() {
  keyboard_input = "";
  dec_st = "";
  dec_tag = "";
  return;
}

void back_Bl_k(){
  for(int i = 0; i < 16; i++){
    back_Blwfsh_key[i] = Blwfsh_key[i];
  }
}

void rest_Bl_k(){
  for(int i = 0; i < 16; i++){
    Blwfsh_key[i] = back_Blwfsh_key[i];
  }
}

void back_AES_k(){
  for(int i = 0; i<32; i++){
    back_AES_key[i] = AES_key[i];
  }
}

void rest_AES_k(){
  for(int i = 0; i<32; i++){
    AES_key[i] = back_AES_key[i];
  }
}

void incr_AES_key() {
  if (AES_key[0] == 255) {
    AES_key[0] = 0;
    if (AES_key[1] == 255) {
      AES_key[1] = 0;
      if (AES_key[2] == 255) {
        AES_key[2] = 0;
        if (AES_key[3] == 255) {
          AES_key[3] = 0;
          if (AES_key[4] == 255) {
            AES_key[4] = 0;
            if (AES_key[5] == 255) {
              AES_key[5] = 0;
              if (AES_key[6] == 255) {
                AES_key[6] = 0;
                if (AES_key[7] == 255) {
                  AES_key[7] = 0;
                  if (AES_key[8] == 255) {
                    AES_key[8] = 0;
                    if (AES_key[9] == 255) {
                      AES_key[9] = 0;
                      if (AES_key[10] == 255) {
                        AES_key[10] = 0;
                        if (AES_key[11] == 255) {
                          AES_key[11] = 0;
                          if (AES_key[12] == 255) {
                            AES_key[12] = 0;
                            if (AES_key[13] == 255) {
                              AES_key[13] = 0;
                              if (AES_key[14] == 255) {
                                AES_key[14] = 0;
                                if (AES_key[15] == 255) {
                                  AES_key[15] = 0;
                                } else {
                                  AES_key[15]++;
                                }
                              } else {
                                AES_key[14]++;
                              }
                            } else {
                              AES_key[13]++;
                            }
                          } else {
                            AES_key[12]++;
                          }
                        } else {
                          AES_key[11]++;
                        }
                      } else {
                        AES_key[10]++;
                      }
                    } else {
                      AES_key[9]++;
                    }
                  } else {
                    AES_key[8]++;
                  }
                } else {
                  AES_key[7]++;
                }
              } else {
                AES_key[6]++;
              }
            } else {
              AES_key[5]++;
            }
          } else {
            AES_key[4]++;
          }
        } else {
          AES_key[3]++;
        }
      } else {
        AES_key[2]++;
      }
    } else {
      AES_key[1]++;
    }
  } else {
    AES_key[0]++;
  }
}

void incr_Blwfsh_key() {
  if (Blwfsh_key[0] == 255) {
    Blwfsh_key[0] = 0;
    if (Blwfsh_key[1] == 255) {
      Blwfsh_key[1] = 0;
      if (Blwfsh_key[2] == 255) {
        Blwfsh_key[2] = 0;
        if (Blwfsh_key[3] == 255) {
          Blwfsh_key[3] = 0;
          if (Blwfsh_key[4] == 255) {
            Blwfsh_key[4] = 0;
            if (Blwfsh_key[5] == 255) {
              Blwfsh_key[5] = 0;
              if (Blwfsh_key[6] == 255) {
                Blwfsh_key[6] = 0;
                if (Blwfsh_key[7] == 255) {
                  Blwfsh_key[7] = 0;
                  if (Blwfsh_key[8] == 255) {
                    Blwfsh_key[8] = 0;
                    if (Blwfsh_key[9] == 255) {
                      Blwfsh_key[9] = 0;
                      if (Blwfsh_key[10] == 255) {
                        Blwfsh_key[10] = 0;
                        if (Blwfsh_key[11] == 255) {
                          Blwfsh_key[11] = 0;
                          if (Blwfsh_key[12] == 255) {
                            Blwfsh_key[12] = 0;
                            if (Blwfsh_key[13] == 255) {
                              Blwfsh_key[13] = 0;
                              if (Blwfsh_key[14] == 255) {
                                Blwfsh_key[14] = 0;
                                if (Blwfsh_key[15] == 255) {
                                  Blwfsh_key[15] = 0;
                                } else {
                                  Blwfsh_key[15]++;
                                }
                              } else {
                                Blwfsh_key[14]++;
                              }
                            } else {
                              Blwfsh_key[13]++;
                            }
                          } else {
                            Blwfsh_key[12]++;
                          }
                        } else {
                          Blwfsh_key[11]++;
                        }
                      } else {
                        Blwfsh_key[10]++;
                      }
                    } else {
                      Blwfsh_key[9]++;
                    }
                  } else {
                    Blwfsh_key[8]++;
                  }
                } else {
                  Blwfsh_key[7]++;
                }
              } else {
                Blwfsh_key[6]++;
              }
            } else {
              Blwfsh_key[5]++;
            }
          } else {
            Blwfsh_key[4]++;
          }
        } else {
          Blwfsh_key[3]++;
        }
      } else {
        Blwfsh_key[2]++;
      }
    } else {
      Blwfsh_key[1]++;
    }
  } else {
    Blwfsh_key[0]++;
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

void encrypt_iv_for_aes_blwfsh(){
  xor_with_ct = false;
  for (int i = 0; i < 16; i++){
    iv[i] = generate_random_number();
  }
  encr_AES(iv);
}

void split_by_sixteen(char plntxt[], int k, int str_len){
  char res[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 16; i++){
      if(i+k > str_len - 1)
      break;
      res[i] = plntxt[i+k];
  }
  if (k == 0){
    for (int i = 0; i < 16; i++){
      res[i] ^= iv[i];
    }
  }
  else{
    for (int i = 0; i < 16; i++){
      res[i] ^= array_for_CBC_mode[i];
    }
  }
  encr_AES(res);
}

void encr_AES(char t_enc[]){
  uint8_t text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for(int i = 0; i<16; i++){
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t AES_key_bit[3] = {128, 192, 256};
  int i = 0;
  aes_context ctx;
  set_aes_key(&ctx, AES_key, AES_key_bit[m]);
  aes_encrypt_block(&ctx, cipher_text, text);
  /*
  for (int i=0; i<16; i++) {
    if(cipher_text[i]<16)
      Serial.print("0");
    Serial.print(cipher_text[i],HEX);
  }
  Serial.println();
  */
  incr_AES_key();
  unsigned char first_eight[8];
  unsigned char second_eight[8];
  for (int i = 0; i < 8; i++){
    first_eight[i] = (unsigned char) cipher_text[i];
    second_eight[i] = (unsigned char) cipher_text[i+8];
  }
  encrypt_with_Blowfish(first_eight, false);
  encrypt_with_Blowfish(second_eight, true);
  xor_with_ct = true;
}

void encrypt_with_Blowfish(unsigned char inp[], bool ct_half){
  unsigned char plt[8];
  for (int i = 0; i < 8; i++)
    plt[i] = inp[i];
  blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
  blowfish.Encrypt(plt, plt, sizeof(plt));
  for(int i = 0; i < 8; i++){
    if (plt[i] < 16)
        dec_st += "0";
      dec_st += String(plt[i], HEX);
  }
  if (xor_with_ct == true){
    if (ct_half == false){
      for (int i = 0; i < 8; i++){
        array_for_CBC_mode[i] = char(int(plt[i]));
      }
    }
    if (ct_half == true){
      for (int i = 0; i < 8; i++){
        array_for_CBC_mode[i + 8] = char(int(plt[i]));
      }
    }
  }
  incr_Blwfsh_key();
}

void split_dec(char ct[], int ct_len, int p){
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
      unsigned char lh[8];
      unsigned char rh[8];
      for (int i = 0; i < 8; i++){
        lh[i] = (unsigned char) int(res[i]);
        rh[i] = (unsigned char) int(res[i+8]);
      }
      blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
      blowfish.Decrypt(lh, lh, sizeof(lh));
      incr_Blwfsh_key();
      blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
      blowfish.Decrypt(rh, rh, sizeof(rh));
      incr_Blwfsh_key();
      uint8_t ret_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
      uint8_t cipher_text[16] = {0};
      for(int i = 0; i < 8; i++){
        int c = int(lh[i]);
        cipher_text[i] = c;
      }
      for(int i = 0; i < 8; i++){
        int c = int(rh[i]);
        cipher_text[i + 8] = c;
      }
      /*
      for (int i=0; i<16; i++) {
        if(cipher_text[i]<16)
          Serial.print("0");
        Serial.print(cipher_text[i],HEX);
      }
      Serial.println();
      */
      uint32_t AES_key_bit[3] = {128, 192, 256};
      int i = 0;
      aes_context ctx;
      set_aes_key(&ctx, AES_key, AES_key_bit[m]);
      aes_decrypt_block(&ctx, ret_text, cipher_text);
      if (p == 0){
        for (i = 0; i < 16; ++i) {
          iv[i] = char(ret_text[i]);
        }
      }
      if (decrypt_tag == false){
      if (p == 32){
        char rslt[16];
        for (int i = 0; i < 16; i++){
          rslt[i] = iv[i] ^ char(ret_text[i]);
          if (rslt[i] > 0)
            dec_st += rslt[i];
        }
      }
      if (p > 32){
        for (int i = 0; i < 32; i += 2) {
          if (i + p - 32 > ct_len - 1) {
            br = true;
            break;
          }
          if (i == 0) {
            if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] != 0)
              array_for_CBC_mode[i] = 16 * getNum(ct[i + p - 32]) + getNum(ct[i + p - 32 + 1]);
            if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] == 0)
              array_for_CBC_mode[i] = 16 * getNum(ct[i + p - 32]);
            if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] != 0)
              array_for_CBC_mode[i] = getNum(ct[i + p - 32 + 1]);
            if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] == 0)
              array_for_CBC_mode[i] = 0;
          } else {
            if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] != 0)
              array_for_CBC_mode[i / 2] = 16 * getNum(ct[i + p - 32]) + getNum(ct[i + p - 32 + 1]);
            if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] == 0)
              array_for_CBC_mode[i / 2] = 16 * getNum(ct[i + p - 32]);
            if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] != 0)
              array_for_CBC_mode[i / 2] = getNum(ct[i + p - 32 + 1]);
            if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] == 0)
              array_for_CBC_mode[i / 2] = 0;
          }
        }
        char rslt[16];
        for (int i = 0; i < 16; i++){
          rslt[i] = array_for_CBC_mode[i] ^ char(ret_text[i]);
          if (rslt[i] > 0)
            dec_st += rslt[i];
        }
      }
    }
    else{ // Decrypt tag
      if (p == 32){
        char rslt[16];
        for (int i = 0; i < 16; i++){
          rslt[i] = iv[i] ^ char(ret_text[i]);
          if (rslt[i] < 0x10)
            dec_tag += "0";
          dec_tag += String(rslt[i], HEX);
        }
      }
      if (p > 32){
        for (int i = 0; i < 32; i += 2) {
          if (i + p - 32 > ct_len - 1) {
            br = true;
            break;
          }
          if (i == 0) {
            if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] != 0)
              array_for_CBC_mode[i] = 16 * getNum(ct[i + p - 32]) + getNum(ct[i + p - 32 + 1]);
            if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] == 0)
              array_for_CBC_mode[i] = 16 * getNum(ct[i + p - 32]);
            if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] != 0)
              array_for_CBC_mode[i] = getNum(ct[i + p - 32 + 1]);
            if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] == 0)
              array_for_CBC_mode[i] = 0;
          } else {
            if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] != 0)
              array_for_CBC_mode[i / 2] = 16 * getNum(ct[i + p - 32]) + getNum(ct[i + p - 32 + 1]);
            if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] == 0)
              array_for_CBC_mode[i / 2] = 16 * getNum(ct[i + p - 32]);
            if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] != 0)
              array_for_CBC_mode[i / 2] = getNum(ct[i + p - 32 + 1]);
            if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] == 0)
              array_for_CBC_mode[i / 2] = 0;
          }
        }
        char rslt[16];
        for (int i = 0; i < 16; i++){
          rslt[i] = array_for_CBC_mode[i] ^ char(ret_text[i]);
          if (rslt[i] < 0x10)
            dec_tag += "0";
          dec_tag += String(rslt[i], HEX);
        }
      }
    }
      incr_AES_key();
   }
}

void encrypt_with_AES_Blowfish(String input) {
  back_keys();
  clear_variables();
  encrypt_iv_for_aes_blwfsh();
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  int p = 0;
    while(str_len > p+1){
      split_by_sixteen(input_arr, p, str_len);
      p+=16;
    }
  rest_keys();
}

void decrypt_with_AES_Blowfish(String ct) {
  back_keys();
  clear_variables();
  decrypt_tag = false;
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  while (ct_len > ext) {
    split_dec(ct_array, ct_len, 0 + ext);
    ext += 32;
  }
  rest_keys();
}

void encrypt_tag_with_AES_Blowfish(String input) {
  back_keys();
  clear_variables();
  encrypt_iv_for_aes_blwfsh();
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  hmac.doUpdate(input_arr);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  char hmacchar[32];
  for (int i = 0; i < 32; i++) {
    hmacchar[i] = char(authCode[i]);
  }
  /*  
    Serial.println("\nTag:");

      for (int i = 0; i < 32; i++) {
        if (hmacchar[i] < 16)
          Serial.print("0");
        Serial.print(hmacchar[i], HEX);
      }
    Serial.println();
  */
  int p = 0;
  for (int i = 0; i < 2; i++){
      split_by_sixteen(hmacchar, p, 32);
      p+=16;
    }
  rest_keys();
}

void decrypt_tag_with_AES_Blowfish(String ct) {
  back_keys();
  clear_variables();
  decrypt_tag = true;
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  while (ct_len > ext) {
    split_dec(ct_array, ct_len, 0 + ext);
    ext += 32;
  }
  rest_keys();
}

String get_tag(String input) {
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  hmac.doUpdate(input_arr);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  String cmptd_tag;
  for (int i = 0; i < 32; i++) {
    if (authCode[i] < 0x10)
      cmptd_tag += "0";
    cmptd_tag += String(authCode[i], HEX);
  }
  return cmptd_tag;
}

void set_stuff_for_input(String blue_inscr) {
  act = true;
  curr_key = 65;
  tft.fillScreen(0x0000);
  tft.setFontSize(2);
  tft.setForeground(0xffff);
  tft.setCursor(2, 0);
  tft.print("Char'");
  tft.setCursor(74, 0);
  tft.print("'");
  disp();
  tft.setCursor(0, 24);
  tft.setFontSize(2);
  tft.setForeground(current_inact_clr);
  tft.print(blue_inscr);
  tft.fillRectangle(312, 0, 8, 240, current_inact_clr);
  tft.setForeground(0x07e0);
  tft.setCursor(216, 0);
  tft.print("ASCII:");
}

void check_bounds_and_change_char() {
  if (curr_key < 32)
    curr_key = 126;

  if (curr_key > 126)
    curr_key = 32;
  curr_key = keyboard_input.charAt(keyboard_input.length() - 1);
}

void disp() {
  //gfx->fillScreen(0x0000);
  tft.setFontSize(2);
  tft.setForeground(0xffff);
  tft.fillRectangle(62, 0, 10, 16, 0x0000);
  tft.setCursor(62, 0);
  tft.print(char(curr_key));
  tft.fillRectangle(288, 0, 22, 14, 0x0000);
  tft.setCursor(288, 0);
  String hexstr;
  if (curr_key < 16)
    hexstr += 0;
  hexstr += String(curr_key, HEX);
  hexstr.toUpperCase();
  tft.setForeground(0x07e0);
  tft.print(hexstr);
  tft.setForeground(0xffff);
  tft.setFontSize(2);
  tft.setCursor(0, 48);
  tft.print(keyboard_input);
}

void disp_stars() {
  //gfx->fillScreen(0x0000);
  tft.setFontSize(2);
  tft.setForeground(0xffff);
  tft.fillRectangle(62, 0, 10, 16, 0x0000);
  tft.setCursor(62, 0);
  tft.print(char(curr_key));
  tft.fillRectangle(288, 0, 22, 14, 0x0000);
  tft.setCursor(288, 0);
  String hexstr;
  if (curr_key < 16)
    hexstr += 0;
  hexstr += String(curr_key, HEX);
  hexstr.toUpperCase();
  tft.setForeground(0x07e0);
  tft.print(hexstr);
  int plnt = keyboard_input.length();
  String stars = "";
  for (int i = 0; i < plnt; i++) {
    stars += "*";
  }
  tft.setForeground(0xffff);
  tft.setFontSize(2);
  tft.setCursor(0, 48);
  tft.print(stars);
}

void encdr_and_keyb_input() {
  finish_input = false;
  rec_d = false;
  while (finish_input == false) {
    if (rec_d == true) {
      rec_d = false;

      if (i2c_data > 31 && i2c_data < 127) {
        curr_key = i2c_data;
        keyboard_input += char(curr_key);
        //Serial.println(keyboard_input);
        disp();
      }

      if (i2c_data == 27) {
        act = false;
        finish_input = true;
      }

      if (i2c_data == 13) {
        finish_input = true;
      }

      if (i2c_data == 130) {
        curr_key++;
        disp();
        if (curr_key < 32)
          curr_key = 126;

        if (curr_key > 126)
          curr_key = 32;
      }

      if (i2c_data == 129) {
        curr_key--;
        disp();
        if (curr_key < 32)
          curr_key = 126;

        if (curr_key > 126)
          curr_key = 32;
      }

      if (i2c_data == 131 || i2c_data == 133) {
        keyboard_input += char(curr_key);
        //Serial.println(keyboard_input);
        disp();
      }

      if (i2c_data == 132 || i2c_data == 8) {
        if (keyboard_input.length() > 0)
          keyboard_input.remove(keyboard_input.length() - 1, 1);
        //Serial.println(keyboard_input);
        tft.fillRectangle(0, 48, 312, 192, 0x0000);
        //Serial.println(keyboard_input);
        disp();
      }
      //Serial.println(i2c_data);
    }
    delayMicroseconds(400);
  }
}

void star_encdr_and_keyb_input() {
  finish_input = false;
  rec_d = false;
  while (finish_input == false) {
    if (rec_d == true) {
      rec_d = false;

      if (i2c_data > 31 && i2c_data < 127) {
        curr_key = i2c_data;
        keyboard_input += char(curr_key);
        //Serial.println(keyboard_input);
        disp_stars();
      }

      if (i2c_data == 27) {
        act = false;
        finish_input = true;
      }

      if (i2c_data == 13) {
        finish_input = true;
      }

      if (i2c_data == 130) {
        curr_key++;
        disp_stars();
        if (curr_key < 32)
          curr_key = 126;

        if (curr_key > 126)
          curr_key = 32;
      }

      if (i2c_data == 129) {
        curr_key--;
        disp_stars();
        if (curr_key < 32)
          curr_key = 126;

        if (curr_key > 126)
          curr_key = 32;
      }

      if (i2c_data == 131 || i2c_data == 133) {
        keyboard_input += char(curr_key);
        //Serial.println(keyboard_input);
        disp_stars();
      }

      if (i2c_data == 132 || i2c_data == 8) {
        if (keyboard_input.length() > 0)
          keyboard_input.remove(keyboard_input.length() - 1, 1);
        //Serial.println(keyboard_input);
        tft.fillRectangle(0, 48, 312, 192, 0x0000);
        //Serial.println(keyboard_input);
        disp_stars();
      }
    }
    delayMicroseconds(400);
  }
}

void get_random_number(){
  rec_d = false;
  digitalWrite(3, HIGH);
  while (rec_d == false){
    delay(1);
  }
  digitalWrite(3, LOW);
  delay(4);
}

int generate_random_number(){
  get_random_number();
  randomSeed(i2c_data);
  get_random_number();
  byte random_number = i2c_data;
  random_number ^= byte(random(256));
  //get_random_number();
  //random_number ^= i2c_data;
  return int(random_number);
}

void disp_centered_text(String text, int h) {
  int text_width = text.length() * 12;
  tft.setCursor((320 - text_width) / 2, h);
  tft.print(text);
}

void disp_button_designation() {
  tft.setFontSize(1);
  tft.setForeground(0x07e0);
  tft.setCursor(0, 232);
  tft.print("A button, 'Enter' - continue ");
  tft.setForeground(five_six_five_red_color);
  tft.print("B button, 'Esc' - cancel");
}

void disp_button_designation_for_del() {
  tft.setFontSize(1);
  tft.setForeground(five_six_five_red_color);
  tft.setCursor(0, 232);
  tft.print("A button, 'Enter' - continue ");
  tft.setForeground(0x07e0);
  tft.print("B button, 'Esc' - cancel");
}

void call_main_menu() {
  tft.fillScreen(0x0000);
  for (int i = 0; i < 320; i++) {
    for (int j = 0; j < 40; j++) {
      tft.drawPixel(i, j + 10, handwritten_midbar[i][j]);
    }
  }
  curr_key = 0;
  main_menu();
}

void main_menu() {
  tft.setFontSize(2);
  byte sdown = 80;
  if (curr_key == 0) {
    tft.setForeground(0xffff);
    disp_centered_text("Logins", sdown + 10);
    tft.setForeground(current_inact_clr);
    disp_centered_text("Credit Cards", sdown + 30);
    disp_centered_text("SHA-256", sdown + 50);
    disp_centered_text("Factory Reset", sdown + 70);
  }
  if (curr_key == 1) {
    tft.setForeground(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    tft.setForeground(0xffff);
    disp_centered_text("Credit Cards", sdown + 30);
    tft.setForeground(current_inact_clr);
    disp_centered_text("SHA-256", sdown + 50);
    disp_centered_text("Factory Reset", sdown + 70);
  }
  if (curr_key == 2) {
    tft.setForeground(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    disp_centered_text("Credit Cards", sdown + 30);
    tft.setForeground(0xffff);
    disp_centered_text("SHA-256", sdown + 50);
    tft.setForeground(current_inact_clr);
    disp_centered_text("Factory Reset", sdown + 70);
  }
  if (curr_key == 3) {
    tft.setForeground(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    disp_centered_text("Credit Cards", sdown + 30);
    disp_centered_text("SHA-256", sdown + 50);
    tft.setForeground(0xffff);
    disp_centered_text("Factory Reset", sdown + 70);
  }
}

void logins_in_flash_menu(){
  tft.setFontSize(2);
  byte sdown = 60;
  if (curr_key == 0) {
    tft.setForeground(0xffff);
    disp_centered_text("Add", sdown + 10);
    tft.setForeground(current_inact_clr);
    disp_centered_text("Delete", sdown + 30);
    disp_centered_text("View", sdown + 50);
  }
  if (curr_key == 1) {
    tft.setForeground(current_inact_clr);
    disp_centered_text("Add", sdown + 10);
    tft.setForeground(0xffff);
    disp_centered_text("Delete", sdown + 30);
    tft.setForeground(current_inact_clr);
    disp_centered_text("View", sdown + 50);
  }
  if (curr_key == 2) {
    tft.setForeground(current_inact_clr);
    disp_centered_text("Add", sdown + 10);
    disp_centered_text("Delete", sdown + 30);
    tft.setForeground(0xffff);
    disp_centered_text("View", sdown + 50);
  }
}

void logins_in_flash(){
  tft.fillScreen(0x0000);
  tft.setFontSize(2);
  tft.setForeground(current_inact_clr);
  disp_centered_text("Logins Menu", 10);
  curr_key = 0;
  disp_button_designation();
  logins_in_flash_menu();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    if (rec_d == true) {
      rec_d = false;
      //Serial.println(i2c_data);
      if (i2c_data == 130 || i2c_data == 132) { // Rightwards Arrow or Downwards Arrow
        curr_key++;
      }

      if (i2c_data == 129 || i2c_data == 131) { // Leftwards Arrow or Upwards Arrow
        curr_key--;
      }

      if (curr_key < 0)
        curr_key = 2;

      if (curr_key > 2)
        curr_key = 0;
      
      logins_in_flash_menu();
      
      if (i2c_data == 13 || i2c_data == 133) { // Enter or A
        if (curr_key == 0 && cont_to_next == false){
          cont_to_next = true;
          Serial.println("Add Login");
        }
        if (curr_key == 1 && cont_to_next == false){
          cont_to_next = true;
          Serial.println("Delete Login");
        }
        if (curr_key == 2 && cont_to_next == false){
          cont_to_next = true;
          Serial.println("View Login");
        }
      }

      if (i2c_data == 27 || i2c_data == 8) { // ESC, Backspace or B
        cont_to_next = true;
      }
    }
    delay(1);
  }
  call_main_menu();
  return;
}

void credit_cards_in_flash_menu(){
  tft.setFontSize(2);
  byte sdown = 60;
  if (curr_key == 0) {
    tft.setForeground(0xffff);
    disp_centered_text("Add", sdown + 10);
    tft.setForeground(current_inact_clr);
    disp_centered_text("Delete", sdown + 30);
    disp_centered_text("View", sdown + 50);
  }
  if (curr_key == 1) {
    tft.setForeground(current_inact_clr);
    disp_centered_text("Add", sdown + 10);
    tft.setForeground(0xffff);
    disp_centered_text("Delete", sdown + 30);
    tft.setForeground(current_inact_clr);
    disp_centered_text("View", sdown + 50);
  }
  if (curr_key == 2) {
    tft.setForeground(current_inact_clr);
    disp_centered_text("Add", sdown + 10);
    disp_centered_text("Delete", sdown + 30);
    tft.setForeground(0xffff);
    disp_centered_text("View", sdown + 50);
  }
}

void credit_cards_in_flash(){
  tft.fillScreen(0x0000);
  tft.setFontSize(2);
  tft.setForeground(current_inact_clr);
  disp_centered_text("Credit Cards Menu", 10);
  curr_key = 0;
  disp_button_designation();
  credit_cards_in_flash_menu();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    if (rec_d == true) {
      rec_d = false;
      //Serial.println(i2c_data);
      if (i2c_data == 130 || i2c_data == 132) { // Rightwards Arrow or Downwards Arrow
        curr_key++;
      }

      if (i2c_data == 129 || i2c_data == 131) { // Leftwards Arrow or Upwards Arrow
        curr_key--;
      }

      if (curr_key < 0)
        curr_key = 2;

      if (curr_key > 2)
        curr_key = 0;
      
      credit_cards_in_flash_menu();
      
      if (i2c_data == 13 || i2c_data == 133) { // Enter or A
        if (curr_key == 0 && cont_to_next == false){
          cont_to_next = true;
          Serial.println("Add Credit Card");
        }
        if (curr_key == 1 && cont_to_next == false){
          cont_to_next = true;
          Serial.println("Delete Credit Card");
        }
        if (curr_key == 2 && cont_to_next == false){
          cont_to_next = true;
          Serial.println("View Credit Card");
        }
      }

      if (i2c_data == 27 || i2c_data == 8) { // ESC, Backspace or B
        cont_to_next = true;
      }
    }
    delay(1);
  }
  call_main_menu();
  return;
}

void disp_random_lock_scr(byte scr_num) {
  tft.fillScreen(0x0000);
  if (scr_num == 0) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 170; j++) {
        tft.drawPixel(i, j + 35, Dallas[i][j]);
      }
    }
  }
  if (scr_num == 1) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 170; j++) {
        tft.drawPixel(i, j + 35, Denver[i][j]);
      }
    }
  }
  if (scr_num == 2) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 170; j++) {
        tft.drawPixel(i, j + 35, Downtown_Tel_Aviv[i][j]);
      }
    }
  }
  if (scr_num == 3) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 170; j++) {
        tft.drawPixel(i, j + 35, London[i][j]);
      }
    }
  }
  if (scr_num == 4) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 170; j++) {
        tft.drawPixel(i, j + 35, Miami[i][j]);
      }
    }
  }
  if (scr_num == 5) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 170; j++) {
        tft.drawPixel(i, j + 35, Milan[i][j]);
      }
    }
  }
  if (scr_num == 6) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 170; j++) {
        tft.drawPixel(i, j + 35, New_Orleans[i][j]);
      }
    }
  }
  if (scr_num == 7) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 170; j++) {
        tft.drawPixel(i, j + 35, Pittsburgh[i][j]);
      }
    }
  }
  if (scr_num == 8) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 170; j++) {
        tft.drawPixel(i, j + 35, Tel_Aviv[i][j]);
      }
    }
  }
  if (scr_num == 9) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 170; j++) {
        tft.drawPixel(i, j + 35, Vancouver[i][j]);
      }
    }
  }
  if (scr_num == 10) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 170; j++) {
        tft.drawPixel(i, j + 35, Zurich[i][j]);
      }
    }
  }
  tft.setFontSize(2);
  tft.setForeground(0xf7de);
  disp_centered_text("Midbar RTL8720DN", 9);
  disp_centered_text("Press Any Key", 215);
}

void press_any_key_to_continue(){
  rec_d = false;
  while (rec_d == false){
    trash = random(256);
    delayMicroseconds(200);
  }
}

void continue_to_unlock() {
  FlashMemory.read();
  if (FlashMemory.buf[8] == 0x00)
    set_pass();
  else
    unlock_midbar();
  return;
}

void unlock_midbar() {
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setForeground(0xffff);
  tft.setFontSize(2);
  set_stuff_for_input("Enter Master Password");
  star_encdr_and_keyb_input();
  tft.fillScreen(0x0000);
  for (int i = 0; i < 125; i++) {
    for (int j = 0; j < 40; j++) {
      tft.drawPixel(i + 97, j + 10, handwritten_midbar[i + 193][j]);
    }
  }
  tft.setFontSize(2);
  disp_centered_text("Unlocking Midbar", 65);
  disp_centered_text("Please wait", 85);
  disp_centered_text("for a while", 105);
  //Serial.println(keyboard_input);
  String bck = keyboard_input;
  modify_keys();
  keyboard_input = bck;
  bool next_act = hash_psswd();
  clear_variables();
  tft.fillScreen(0x0000);
  for (int i = 0; i < 125; i++) {
    for (int j = 0; j < 40; j++) {
      tft.drawPixel(i + 97, j + 10, handwritten_midbar[i + 193][j]);
    }
  }
  if (next_act == true) {
    tft.setFontSize(2);
    disp_centered_text("Midbar unlocked", 65);
    disp_centered_text("successfully", 85);
    disp_centered_text("Press Any Key", 105);
    disp_centered_text("To Continue", 125);
    //check_EEPROM_integrity();
    press_any_key_to_continue();
    delay(24);
    i2c_data = 0;
    call_main_menu();
    return;
  } else {
    tft.setFontSize(2);
    tft.setForeground(five_six_five_red_color);
    disp_centered_text("Wrong Password!", 65);
    tft.setForeground(0xffff);
    disp_centered_text("Please reboot", 100);
    disp_centered_text("the device", 120);
    disp_centered_text("and try again", 140);
    for (;;)
      delay(1000);
  }
}

bool hash_psswd() {
  String h = get_tag(keyboard_input);
  for (int i = 0; i < 4; i++){
    h += char(AES_key[i]);
    h += char(Blwfsh_key[i]);
  }
  int nofincr = int(kderalgs.charAt(0)) + int(kderalgs.charAt(1)) + int(kderalgs.charAt(2)) + int(AES_key[2]) + int(Blwfsh_key[1]) + int(Blwfsh_key[9]);
  for (int i = 0; i < nofincr; i++){
    h = get_tag(h);
  }
  for (int i = 3; i < 5; i++){
    h += char(AES_key[i]);
    h += char(Blwfsh_key[i]);
  }
  h = get_tag(h);
  String encr_h;
  FlashMemory.read();
  for (int i = 0; i < 48; i++) {
    if (FlashMemory.buf[i + 9] < 16)
      encr_h += "0";
    encr_h += String(FlashMemory.buf[i + 9], HEX);
  }
  back_keys();
  clear_variables();
  decrypt_tag_with_AES_Blowfish(encr_h);
  rest_keys();
  return dec_tag.equals(h);
}

void set_pass() {
  tft.fillScreen(0x0000);
  tft.setForeground(0xffff);
  set_stuff_for_input("Set Master Password");
  encdr_and_keyb_input();
  tft.fillScreen(0x0000);
  tft.setFontSize(2);
  for (int i = 0; i < 161; i++) {
    for (int j = 0; j < 40; j++) {
      tft.drawPixel(i + 79, j + 10, handwritten_midbar[i][j]);
    }
  }
  tft.setForeground(0xffff);
  disp_centered_text("Setting Master Password", 65);
  disp_centered_text("Please wait", 85);
  disp_centered_text("for a while", 105);
  //Serial.println(keyboard_input);
  String bck = keyboard_input;
  modify_keys();
  keyboard_input = bck;
  set_psswd();
  tft.fillScreen(0x0000);
  tft.setFontSize(2);
  for (int i = 0; i < 161; i++) {
    for (int j = 0; j < 40; j++) {
      tft.drawPixel(i + 79, j + 10, handwritten_midbar[i][j]);
    }
  }
  tft.setForeground(0xffff);
  disp_centered_text("Master Password Set", 65);
  disp_centered_text("Successfully", 85);
  disp_centered_text("Press Any Key", 105);
  disp_centered_text("To Continue", 125);
  press_any_key_to_continue();
  delay(24);
  i2c_data = 0;
  call_main_menu();
  return;
}

void set_psswd() {
  String h = get_tag(keyboard_input);
  for (int i = 0; i < 4; i++){
    h += char(AES_key[i]);
    h += char(Blwfsh_key[i]);
  }
  int nofincr = int(kderalgs.charAt(0)) + int(kderalgs.charAt(1)) + int(kderalgs.charAt(2)) + int(AES_key[2]) + int(Blwfsh_key[1]) + int(Blwfsh_key[9]);
  for (int i = 0; i < nofincr; i++){
    h = get_tag(h);
  }
  for (int i = 3; i < 5; i++){
    h += char(AES_key[i]);
    h += char(Blwfsh_key[i]);
  }
  back_keys();
  clear_variables();
  encrypt_tag_with_AES_Blowfish(h);
  rest_keys();
  int dec_st_len = dec_st.length() + 1;
  char dec_st_array[dec_st_len];
  dec_st.toCharArray(dec_st_array, dec_st_len);
  byte res[48];
  for (int i = 0; i < 96; i += 2) {
    if (i == 0) {
      if (dec_st_array[i] != 0 && dec_st_array[i + 1] != 0)
        res[i] = 16 * getNum(dec_st_array[i]) + getNum(dec_st_array[i + 1]);
      if (dec_st_array[i] != 0 && dec_st_array[i + 1] == 0)
        res[i] = 16 * getNum(dec_st_array[i]);
      if (dec_st_array[i] == 0 && dec_st_array[i + 1] != 0)
        res[i] = getNum(dec_st_array[i + 1]);
      if (dec_st_array[i] == 0 && dec_st_array[i + 1] == 0)
        res[i] = 0;
    } else {
      if (dec_st_array[i] != 0 && dec_st_array[i + 1] != 0)
        res[i / 2] = 16 * getNum(dec_st_array[i]) + getNum(dec_st_array[i + 1]);
      if (dec_st_array[i] != 0 && dec_st_array[i + 1] == 0)
        res[i / 2] = 16 * getNum(dec_st_array[i]);
      if (dec_st_array[i] == 0 && dec_st_array[i + 1] != 0)
        res[i / 2] = getNum(dec_st_array[i + 1]);
      if (dec_st_array[i] == 0 && dec_st_array[i + 1] == 0)
        res[i / 2] = 0;
    }
  }

  FlashMemory.buf[8] = 255;
  for (int i = 0; i < 48; i++) {
    FlashMemory.buf[i + 9] = res[i];
  }
  FlashMemory.update();
  delay(100);
  //compute_and_write_encrypted_tag_for_EEPROM_integrity_check();
}

void modify_keys() {
  keyboard_input += kderalgs;
  String h = get_tag(keyboard_input);
  int nofincr = int(kderalgs.charAt(0));
  for (int i = 0; i < nofincr; i++){
    h = get_tag(h);
  }
  int h_len = h.length() + 1;
  char h_array[h_len];
  h.toCharArray(h_array, h_len);
  byte res[32];
  for (int i = 0; i < 64; i += 2) {
    if (i == 0) {
      if (h_array[i] != 0 && h_array[i + 1] != 0)
        res[i] = 16 * getNum(h_array[i]) + getNum(h_array[i + 1]);
      if (h_array[i] != 0 && h_array[i + 1] == 0)
        res[i] = 16 * getNum(h_array[i]);
      if (h_array[i] == 0 && h_array[i + 1] != 0)
        res[i] = getNum(h_array[i + 1]);
      if (h_array[i] == 0 && h_array[i + 1] == 0)
        res[i] = 0;
    } else {
      if (h_array[i] != 0 && h_array[i + 1] != 0)
        res[i / 2] = 16 * getNum(h_array[i]) + getNum(h_array[i + 1]);
      if (h_array[i] != 0 && h_array[i + 1] == 0)
        res[i / 2] = 16 * getNum(h_array[i]);
      if (h_array[i] == 0 && h_array[i + 1] != 0)
        res[i / 2] = getNum(h_array[i + 1]);
      if (h_array[i] == 0 && h_array[i + 1] == 0)
        res[i / 2] = 0;
    }
  }
  /*
  for (int i = 0; i < 32; i++){
    Serial.println(res[i]);
  }
  */
  for (int i = 0; i < 12; i++) {
    hmackey[i] = res[i];
  }
  for (int i = 0; i < 12; i++) {
    AES_key[i] = int(res[i + 12]);
  }
  for (int i = 0; i < 8; i++) {
    Blwfsh_key[i] = (unsigned char) res[i + 24];
  }
}

void setup() {
  //SPI_BUS.setDefaultFrequency(ILI9341_SPI_FREQUENCY);
  tft.begin();
  tft.setRotation(1);
  tft.fillScreen(0x0000);
  FlashMemory.read();
  if (FlashMemory.buf[0] != 0 || FlashMemory.buf[1] != 0  || FlashMemory.buf[2] != 0  || FlashMemory.buf[3] != 0  || FlashMemory.buf[4] != 0  || FlashMemory.buf[5] != 0  || FlashMemory.buf[6] != 0  || FlashMemory.buf[7] != 0)
  {
    tft.setCursor(0, 0);
    tft.print("Clearing flash...");
    tft.setCursor(0, 10);
    tft.print("Please wait for a while.");
    for (int i = 0; i < 4096; i++)
      FlashMemory.buf[i] = 0x00;
    FlashMemory.update();
  }
  else{
    tft.setCursor(0, 0);
    tft.print("Loading...");
    tft.setCursor(0, 10);
    tft.print("Please wait for a while.");
  }
  Serial.begin(115200);
  Wire.begin(13);                // join i2c bus with address #13
  Wire.onReceive(receiveEvent); // register event
  pinMode(3, OUTPUT);
  digitalWrite(3, LOW);
  disp_random_lock_scr(generate_random_number() % 11);
  press_any_key_to_continue();
  m = 2; // Set AES to 256-bit mode
  continue_to_unlock();
}

void loop() {
    if (rec_d == true) {
      rec_d = false;
      //Serial.println(i2c_data);
      if (i2c_data == 130 || i2c_data == 132) { // Rightwards Arrow or Downwards Arrow
        curr_key++;
      }

      if (i2c_data == 129 || i2c_data == 131) { // Leftwards Arrow or Upwards Arrow
        curr_key--;
      }

      if (curr_key < 0)
        curr_key = 3;

      if (curr_key > 3)
        curr_key = 0;
      
      main_menu();
      
      if (i2c_data == 13 || i2c_data == 133) { // Enter or A
        if (curr_key == 0)
          logins_in_flash();
        if (curr_key == 1)
          credit_cards_in_flash();
        if (curr_key == 2)
          Serial.println("SHA-256");
        if (curr_key == 3)
          Serial.println("Factory Reset");
      }
    }
    delay(1);
}

// function that executes whenever data is received from master
// this function is registered as an event, see setup()
void receiveEvent(int howMany) {
  howMany = howMany;              // clear warning msg
  i2c_data = Wire.read();
  rec_d = true;
}
