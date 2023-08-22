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
#include <FlashMemory.h>
#include <Wire.h>
#include "SPI.h"
#include "AmebaILI9341.h"
#include "aes.h"
#include "blowfish.h"
#include "Crypto.h"
#include "midbaricon.h"

// Keys (Below)

String kderalgs = "pTV0o3rjd9Om23Wcl8IzotaHnQBu1P";
byte hmackey[] = {"428RW4734862ETrJTj299ACo8Df68QkBi6Qq5z27R9bPm98ugA09M1rN5yOMYx8fkKC5XCMs323b45cN6D5aAgOCsQ5KP3fhAh664swl4041tXRB64sEPq70U7C4zprfbddSk1z"};
uint8_t AES_key[32] = {
0x47,0xe7,0x4c,0x9d,
0x3b,0x91,0xb3,0x64,
0xd1,0x9e,0xcd,0xce,
0xdc,0x02,0x7d,0xb7,
0x34,0xe2,0xfe,0x9a,
0x3d,0xbc,0xbb,0x0a,
0xbd,0xeb,0x45,0x17,
0xfc,0x6b,0xa7,0xdb
};
unsigned char Blwfsh_key[] = {
0xad,0xb6,0x5f,0xd5,
0x8b,0xdc,0x4a,0xa7,
0x90,0x8d,0xef,0x80,
0x2b,0xce,0xbd,0x9c,
0x7c,0x38,0x21,0xb9,
0xee,0x64,0xa0,0xf9
};

// Keys (Above)

#define TFT_RESET       6
#define TFT_DC          2
#define TFT_CS          SPI_SS
#define SPI_BUS         SPI

AmebaILI9341 tft = AmebaILI9341(TFT_CS, TFT_DC, TFT_RESET, SPI_BUS);

#define MAX_NUM_OF_CHARS_FOR_USERNAME 52
#define MAX_NUM_OF_CHARS_FOR_PASSWORD 52
#define MAX_NUM_OF_CHARS_FOR_WEBSITE 56
#define MAX_NUM_OF_CHARS_FOR_CARDHOLDER 39
#define MAX_NUM_OF_CHARS_FOR_CARD_NUMBER 20
#define MAX_NUM_OF_CHARS_FOR_EXPIRATION_DATE 16
#define MAX_NUM_OF_CHARS_FOR_CVN 3
#define MAX_NUM_OF_CHARS_FOR_PIN 8
#define MAX_NUM_OF_CHARS_FOR_ZIP_CODE 10
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
String rfid_card1;
String rfid_card2;
String rfid_card3;
String rfid_card4;

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
  disp_length_panel();
}

void disp_length_panel(){
  tft.fillRectangle(0, 210, 320, 240, 0xe73c);
  tft.setBackground(0xe73c);
  tft.setForeground(0x2145);
  tft.setFontSize(2);
  tft.setCursor(18,218);
  tft.print("Length:");
  tft.setBackground(0x0000);
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
        tft.fillRectangle(0, 48, 312, 162, 0x0000);
        //Serial.println(keyboard_input);
        disp();
        //disp_length_panel();
      }

      int inpl = keyboard_input.length();
      tft.setBackground(0xe73c);
      tft.setForeground(0x2145);
      tft.setCursor(100,218);
      tft.print("    ");
      tft.setCursor(100,218);
      tft.print(inpl);
      tft.setBackground(0x0000);
      
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
        tft.fillRectangle(0, 48, 312, 162, 0x0000);
        //Serial.println(keyboard_input);
        disp_stars();
        //disp_length_panel();
      }

      int inpl = keyboard_input.length();
      tft.setBackground(0xe73c);
      tft.setForeground(0x2145);
      tft.setCursor(100,218);
      tft.print("    ");
      tft.setCursor(100,218);
      tft.print(inpl);
      tft.setBackground(0x0000);
      
    }
    delayMicroseconds(400);
  }
}

void get_random_number(){
  rec_d = false;
  digitalWrite(3, HIGH);
  digitalWrite(11, LOW);
  while (rec_d == false){
    delay(1);
  }
  digitalWrite(3, LOW);
  digitalWrite(11, LOW);
  delay(4);
}

int generate_random_number(){
  //Serial.println("Genrating Random Number");
  get_random_number();
  randomSeed(i2c_data);
  get_random_number();
  byte random_number = i2c_data;
  random_number ^= byte(random(256));
  //get_random_number();
  //random_number ^= i2c_data;
  //Serial.println("Random Number Generating");
  return int(random_number);
}

void disp_centered_text(String text, int h) {
  if (text.length() < 27){
    int text_width = text.length() * 12;
    tft.setCursor((320 - text_width) / 2, h);
    tft.print(text);
  }
  else{
    tft.setCursor(0, h);
    tft.print(text);
  }
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

void data_in_flash_menu(){
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
  data_in_flash_menu();
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
      
      data_in_flash_menu();
      
      if (i2c_data == 13 || i2c_data == 133) { // Enter or A
        if (curr_key == 0 && cont_to_next == false){
          cont_to_next = true;
          select_login_from_flash(0);
        }
        if (curr_key == 1 && cont_to_next == false){
          cont_to_next = true;
          select_login_from_flash(1);
        }
        if (curr_key == 2 && cont_to_next == false){
          cont_to_next = true;
          select_login_from_flash(2);
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

void credit_cards_in_flash(){
  tft.fillScreen(0x0000);
  tft.setFontSize(2);
  tft.setForeground(current_inact_clr);
  disp_centered_text("Credit Cards Menu", 10);
  curr_key = 0;
  disp_button_designation();
  data_in_flash_menu();
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
      
      data_in_flash_menu();
      
      if (i2c_data == 13 || i2c_data == 133) { // Enter or A
        if (curr_key == 0 && cont_to_next == false){
          cont_to_next = true;
          select_credit_card_from_flash(0);
        }
        if (curr_key == 1 && cont_to_next == false){
          cont_to_next = true;
          select_credit_card_from_flash(1);
        }
        if (curr_key == 2 && cont_to_next == false){
          cont_to_next = true;
          select_credit_card_from_flash(2);
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

void disp_lock_scr(byte scr_num, String inscr) {
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
        tft.drawPixel(i, j + 35, Downtown_Dallas[i][j]);
      }
    }
  }
  if (scr_num == 3) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 170; j++) {
        tft.drawPixel(i, j + 35, Downtown_Tel_Aviv[i][j]);
      }
    }
  }
  if (scr_num == 4) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 170; j++) {
        tft.drawPixel(i, j + 35, London[i][j]);
      }
    }
  }
  if (scr_num == 5) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 170; j++) {
        tft.drawPixel(i, j + 35, Miami[i][j]);
      }
    }
  }
  if (scr_num == 6) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 170; j++) {
        tft.drawPixel(i, j + 35, Milan[i][j]);
      }
    }
  }
  if (scr_num == 7) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 170; j++) {
        tft.drawPixel(i, j + 35, Minneapolis[i][j]);
      }
    }
  }
  if (scr_num == 8) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 170; j++) {
        tft.drawPixel(i, j + 35, New_Orleans[i][j]);
      }
    }
  }
  if (scr_num == 9) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 170; j++) {
        tft.drawPixel(i, j + 35, Paris[i][j]);
      }
    }
  }
  if (scr_num == 10) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 170; j++) {
        tft.drawPixel(i, j + 35, Pittsburgh[i][j]);
      }
    }
  }
  if (scr_num == 11) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 170; j++) {
        tft.drawPixel(i, j + 35, Tel_Aviv[i][j]);
      }
    }
  }
  if (scr_num == 12) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 170; j++) {
        tft.drawPixel(i, j + 35, Vancouver[i][j]);
      }
    }
  }
  if (scr_num == 13) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 170; j++) {
        tft.drawPixel(i, j + 35, Zurich[i][j]);
      }
    }
  }
  disp_centered_text(inscr, 215);
}

void press_any_key_to_continue(){
  rec_d = false;
  while (rec_d == false){
    trash = random(256);
    delayMicroseconds(200);
  }
  delay(12);
  i2c_data = 0;
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
  tft.setForeground(0xffff);
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
    disp_centered_text("Midbar Unlocked", 65);
    disp_centered_text("Successfully", 85);
    disp_centered_text("Press Any Key", 105);
    disp_centered_text("To Continue", 125);
    check_flash_integrity();
    press_any_key_to_continue();
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
  int nofincr = int(kderalgs.charAt(0)) + int(kderalgs.charAt(1)) + int(kderalgs.charAt(2)) + int(AES_key[2]) + int(Blwfsh_key[1]);
  for (int i = 0; i < nofincr; i++){
    h = get_tag(h);
  }
  h += rfid_card1;
  nofincr = int(kderalgs.charAt(2)) + int(Blwfsh_key[2]) + int(Blwfsh_key[9]);
  for (int i = 0; i < nofincr; i++){
    h = get_tag(h);
  }
  h += rfid_card2;
  nofincr = int(kderalgs.charAt(3)) + int(Blwfsh_key[6]) + int(Blwfsh_key[7] + int(AES_key[2]));
  for (int i = 0; i < nofincr; i++){
    h = get_tag(h);
  }
  for (int i = 3; i < 5; i++){
    h += char(AES_key[i]);
    h += char(Blwfsh_key[i]);
  }
  hmackey[14] = byte(h.charAt(8));
  hmackey[15] = byte(h.charAt(9));
  hmackey[16] = byte(h.charAt(10));
  hmackey[17] = byte(h.charAt(11));
  hmackey[18] = byte(h.charAt(12));
  
  h += rfid_card3;
  nofincr = int(kderalgs.charAt(4)) + int(Blwfsh_key[8]) + int(AES_key[10]) + int(AES_key[11]) + int(AES_key[12]);
  for (int i = 0; i < nofincr; i++){
    h = get_tag(h);
  }
  h += rfid_card4;
  nofincr = int(kderalgs.charAt(5)) + int(AES_key[13]) + int(AES_key[11]) + int(AES_key[12]);
  for (int i = 0; i < nofincr; i++){
    h = get_tag(h);
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
  call_main_menu();
  return;
}

void set_psswd() {
  String h = get_tag(keyboard_input);
  for (int i = 0; i < 4; i++){
    h += char(AES_key[i]);
    h += char(Blwfsh_key[i]);
  }
  int nofincr = int(kderalgs.charAt(0)) + int(kderalgs.charAt(1)) + int(kderalgs.charAt(2)) + int(AES_key[2]) + int(Blwfsh_key[1]);
  for (int i = 0; i < nofincr; i++){
    h = get_tag(h);
  }
  h += rfid_card1;
  nofincr = int(kderalgs.charAt(2)) + int(Blwfsh_key[2]) + int(Blwfsh_key[9]);
  for (int i = 0; i < nofincr; i++){
    h = get_tag(h);
  }
  h += rfid_card2;
  nofincr = int(kderalgs.charAt(3)) + int(Blwfsh_key[6]) + int(Blwfsh_key[7] + int(AES_key[2]));
  for (int i = 0; i < nofincr; i++){
    h = get_tag(h);
  }
  for (int i = 3; i < 5; i++){
    h += char(AES_key[i]);
    h += char(Blwfsh_key[i]);
  }
  hmackey[14] = byte(h.charAt(8));
  hmackey[15] = byte(h.charAt(9));
  hmackey[16] = byte(h.charAt(10));
  hmackey[17] = byte(h.charAt(11));
  hmackey[18] = byte(h.charAt(12));
  
  h += rfid_card3;
  nofincr = int(kderalgs.charAt(4)) + int(Blwfsh_key[8]) + int(AES_key[10]) + int(AES_key[11]) + int(AES_key[12]);
  for (int i = 0; i < nofincr; i++){
    h = get_tag(h);
  }
  h += rfid_card4;
  nofincr = int(kderalgs.charAt(5)) + int(AES_key[13]) + int(AES_key[11]) + int(AES_key[12]);
  for (int i = 0; i < nofincr; i++){
    h = get_tag(h);
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
  compute_and_write_encrypted_tag_for_flash_integrity_check();
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

void compute_and_write_encrypted_tag_for_flash_integrity_check(){
  FlashMemory.read();
  String h;
  for (int i = 0; i < 3993; i++) {
    int cv = FlashMemory.buf[i];
    if (cv < 16)
      h += "0";
    h += String(cv, HEX);
  }
  encrypt_tag_with_AES_Blowfish(h);
  //Serial.println(dec_st);

  byte res[48];
  for (int i = 0; i < 96; i += 2) {
    if (i == 0) {
      if (dec_st.charAt(i) != 0 && dec_st.charAt(i + 1) != 0)
        res[i] = 16 * getNum(dec_st.charAt(i)) + getNum(dec_st.charAt(i + 1));
      if (dec_st.charAt(i) != 0 && dec_st.charAt(i + 1) == 0)
        res[i] = 16 * getNum(dec_st.charAt(i));
      if (dec_st.charAt(i) == 0 && dec_st.charAt(i + 1) != 0)
        res[i] = getNum(dec_st.charAt(i + 1));
      if (dec_st.charAt(i) == 0 && dec_st.charAt(i + 1) == 0)
        res[i] = 0;
    } else {
      if (dec_st.charAt(i) != 0 && dec_st.charAt(i + 1) != 0)
        res[i / 2] = 16 * getNum(dec_st.charAt(i)) + getNum(dec_st.charAt(i + 1));
      if (dec_st.charAt(i) != 0 && dec_st.charAt(i + 1) == 0)
        res[i / 2] = 16 * getNum(dec_st.charAt(i));
      if (dec_st.charAt(i) == 0 && dec_st.charAt(i + 1) != 0)
        res[i / 2] = getNum(dec_st.charAt(i + 1));
      if (dec_st.charAt(i) == 0 && dec_st.charAt(i + 1) == 0)
        res[i / 2] = 0;
    }
  }

  for (int i = 0; i < 48; i++) {
    FlashMemory.buf[i + 3993] = res[i];
  }
  FlashMemory.update();
}

void check_flash_integrity(){
  FlashMemory.read();
  String h;
  for (int i = 0; i < 3993; i++) {
    int cv = FlashMemory.buf[i];
    if (cv < 16)
      h += "0";
    h += String(cv, HEX);
  }
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  int h_len1 = h.length() + 1;
  char h_arr[h_len1];
  h.toCharArray(h_arr, h_len1);
  hmac.doUpdate(h_arr);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  int p = 0;
  char hmacchar[32];
  for (int i = 0; i < 32; i++) {
    hmacchar[i] = char(authCode[i]);
  }

  String res_hash;
  for (int i = 0; i < 32; i++) {
    if (hmacchar[i] < 0x10)
      res_hash += "0";
    res_hash += String(hmacchar[i], HEX);
  }
  /*
    Serial.println();

      for (int i = 0; i < 30; i++) {
        if (hmacchar[i] < 16)
          Serial.print("0");
        Serial.print(hmacchar[i], HEX);
      }
    Serial.println();
  */
  FlashMemory.read();
  String encr_h;
  for (int i = 0; i < 48; i++) {
    if (FlashMemory.buf[i + 3993] < 16)
      encr_h += "0";
    encr_h += String(FlashMemory.buf[i + 3993], HEX);
  }
  decrypt_tag_with_AES_Blowfish(encr_h);
  //Serial.println(dec_tag);
  tft.setFontSize(1);
  if (dec_tag.equals(res_hash)){
    tft.setForeground(0xf7de);
    tft.setCursor(0, 230);
    tft.print("Flash integrity check completed successfully!");
  }
  else{
    tft.setForeground(five_six_five_red_color);
    tft.setCursor(0, 230);
    tft.print("Flash integrity check failed!!!");
  }
}

void select_login_from_flash(byte what_to_do_with_it) {
  // 0 - Add login
  // 1 - Delete login
  // 2 - View login
  delay(1);
  curr_key = 1;
  header_for_select_login_from_flash(what_to_do_with_it);
  display_website_from_login_in_flash();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    if (rec_d == true) {
      rec_d = false;
      //Serial.println(i2c_data);
      if (i2c_data == 130) { // Rightwards Arrow
        curr_key++;
      }

      if (i2c_data == 129) { // Leftwards Arrow
        curr_key--;
      }

    if (curr_key < 1)
      curr_key = 16;

    if (curr_key > 16)
      curr_key = 1;
      
      header_for_select_login_from_flash(what_to_do_with_it);
      display_website_from_login_in_flash();
      
      if (i2c_data == 13 || i2c_data == 133) { // Enter or A
        if (what_to_do_with_it == 0 && cont_to_next == false){
          cont_to_next = true;
          add_login_to_flash_from_keyboard_and_encdr(curr_key);
        }
        if (what_to_do_with_it == 1 && cont_to_next == false){
          cont_to_next = true;
          delete_login_from_flash(curr_key);
        }
        if (what_to_do_with_it == 2 && cont_to_next == false){
          cont_to_next = true;
          view_login_from_flash(curr_key);
        }
      }

      if (i2c_data == 27 || i2c_data == 8) { // ESC, Backspace or B
        //call_main_menu();
        cont_to_next = true;
      }
    }
    delay(1);
  }
  return;
}

void add_login_to_flash_from_keyboard_and_encdr(int chsn_slot) {
  enter_username_for_login_in_flash_in_flash(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void enter_username_for_login_in_flash_in_flash(int chsn_slot) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Username");
  encdr_and_keyb_input();
  if (act == true) {
    enter_password_for_login_in_flash_in_flash(chsn_slot, keyboard_input);
  }
  return;
}

void enter_password_for_login_in_flash_in_flash(int chsn_slot, String entered_username) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Password");
  encdr_and_keyb_input();
  if (act == true) {
    enter_website_for_login_in_flash_in_flash(chsn_slot, entered_username, keyboard_input);
  }
  return;
}

void enter_website_for_login_in_flash_in_flash(int chsn_slot, String entered_username, String entered_password) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Website");
  encdr_and_keyb_input();
  if (act == true) {
    write_login_to_flash(chsn_slot, entered_username, entered_password, keyboard_input);
  }
  return;
}

void write_login_to_flash(int chsn_slot, String entered_username, String entered_password, String entered_website) {
  /*
  Serial.println();
  Serial.println(chsn_slot);
  Serial.println(entered_username);
  Serial.println(entered_password);
  Serial.println(entered_website);
  */
  tft.fillScreen(0x0000);
  tft.setFontSize(1);
  tft.setForeground(0xffff);
  tft.setCursor(0, 0);
  tft.print("Adding login to the slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  int seed = generate_random_number();
  int seed1 = generate_random_number();
  if (seed1 != 0)
    seed *= seed1;
  int seed2 = generate_random_number();
  if (seed2 != 0)
    seed *= seed2;

  randomSeed(seed);
  
  char usrnarr[MAX_NUM_OF_CHARS_FOR_USERNAME];
  char passarr[MAX_NUM_OF_CHARS_FOR_PASSWORD];
  char websarr[MAX_NUM_OF_CHARS_FOR_WEBSITE];

  for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_USERNAME; i++){
    usrnarr[i] = 127 + random(129);
  }

  for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_PASSWORD; i++){
    passarr[i] = 127 + random(129);
  }

  for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_WEBSITE; i++){
    websarr[i] = 127 + random(129);
  }

  int username_length = entered_username.length();
  for (int i = 0; i < username_length; i++){
    if (i < MAX_NUM_OF_CHARS_FOR_USERNAME)
      usrnarr[i] = entered_username.charAt(i);
  }

  int password_length = entered_password.length();
  for (int i = 0; i < password_length; i++){
    if (i < MAX_NUM_OF_CHARS_FOR_PASSWORD)
      passarr[i] = entered_password.charAt(i);
  }

  int website_length = entered_website.length();
  for (int i = 0; i < website_length; i++){
    if (i < MAX_NUM_OF_CHARS_FOR_WEBSITE)
      websarr[i] = entered_website.charAt(i);
  }

  String resulted_string;

  for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_USERNAME; i++){
    resulted_string += usrnarr[i];
  }

  for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_PASSWORD; i++){
    resulted_string += passarr[i];
  }

  for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_WEBSITE; i++){
    resulted_string += websarr[i];
  }

  //Serial.println(resulted_string);
  //Serial.println(resulted_string.length());
  encrypt_with_AES_Blowfish(resulted_string);
  //Serial.println(dec_st);
  //Serial.println(dec_st.length());
  byte res[176];
  for (int i = 0; i < 352; i += 2) {
    if (i == 0) {
      if (dec_st.charAt(i) != 0 && dec_st.charAt(i + 1) != 0)
        res[i] = 16 * getNum(dec_st.charAt(i)) + getNum(dec_st.charAt(i + 1));
      if (dec_st.charAt(i) != 0 && dec_st.charAt(i + 1) == 0)
        res[i] = 16 * getNum(dec_st.charAt(i));
      if (dec_st.charAt(i) == 0 && dec_st.charAt(i + 1) != 0)
        res[i] = getNum(dec_st.charAt(i + 1));
      if (dec_st.charAt(i) == 0 && dec_st.charAt(i + 1) == 0)
        res[i] = 0;
    } else {
      if (dec_st.charAt(i) != 0 && dec_st.charAt(i + 1) != 0)
        res[i / 2] = 16 * getNum(dec_st.charAt(i)) + getNum(dec_st.charAt(i + 1));
      if (dec_st.charAt(i) != 0 && dec_st.charAt(i + 1) == 0)
        res[i / 2] = 16 * getNum(dec_st.charAt(i));
      if (dec_st.charAt(i) == 0 && dec_st.charAt(i + 1) != 0)
        res[i / 2] = getNum(dec_st.charAt(i + 1));
      if (dec_st.charAt(i) == 0 && dec_st.charAt(i + 1) == 0)
        res[i / 2] = 0;
    }
  }
  //for (int i = 1; i < 17; i++)
    //Serial.println(get_slot_start_address_for_login(i));
  int start_address = get_slot_start_address_for_login(chsn_slot);
  for (int i = 0; i < 176; i++) {
    FlashMemory.buf[i + start_address] = res[i];
  }
  FlashMemory.update();
  tft.fillScreen(0x0000);
  tft.setFontSize(1);
  tft.setForeground(0xffff);
  tft.setCursor(0, 0);
  tft.print("Computing and encrypting new verification tag...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  compute_and_write_encrypted_tag_for_flash_integrity_check();
  return;
}

void header_for_select_login_from_flash(byte what_to_do_with_it){
  tft.fillScreen(0x0000);
  tft.setFontSize(2);
  if (what_to_do_with_it == 0) {
    tft.setForeground(current_inact_clr);
    disp_centered_text("Add Login to Slot " + String(curr_key) + "/" + String(16), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 1) {
    tft.setForeground(five_six_five_red_color);
    disp_centered_text("Delete Login " + String(curr_key) + "/" + String(16), 5);
    disp_button_designation_for_del();
  }
  if (what_to_do_with_it == 2) {
    tft.setForeground(current_inact_clr);
    disp_centered_text("View Login " + String(curr_key) + "/" + String(16), 5);
    disp_button_designation();
  }
}

void display_website_from_login_in_flash(){
  tft.setFontSize(2);
  int start_address = get_slot_start_address_for_login(curr_key);
  
  int extr_data[176];

  FlashMemory.read();
  for (int i = 0; i < 176; i++) {
    extr_data[i] = FlashMemory.buf[i + start_address];
      
  }
  int noz = 0; // Number of zeroes
  for (int i = 0; i < 176; i++) {
    if (extr_data[i] == 0)
      noz++;
  }
  //Serial.println(noz);
  if (noz == 176) {
    tft.setForeground(0x07e0);
    disp_centered_text("Empty", 35);
  } else {
    clear_variables();
    String extr_ct;
    for (int i = 0; i < 176; i++) {
      int cv = extr_data[i];
      if (cv < 16)
        extr_ct += "0";
      extr_ct += String(cv, HEX);
    }
    decrypt_tag = false;
    decrypt_with_AES_Blowfish(extr_ct);
    tft.setForeground(0xffff);
    int shift_to_webs = MAX_NUM_OF_CHARS_FOR_USERNAME + MAX_NUM_OF_CHARS_FOR_PASSWORD;
    String webs_to_disp;
    for (int i = shift_to_webs; i < 150; i ++){
      if (dec_st.charAt(i) > 31 && dec_st.charAt(i) < 127)
        webs_to_disp += dec_st.charAt(i);
    }
    disp_centered_text(webs_to_disp, 35);
  }
}

void delete_login_from_flash(int chsn_slot){
  tft.fillScreen(0x0000);
  tft.setFontSize(1);
  tft.setForeground(0xffff);
  tft.setCursor(0, 0);
  tft.print("Deleting login from the slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  int start_address = get_slot_start_address_for_login(chsn_slot);
  for (int i = 0; i < 176; i++) {
    FlashMemory.buf[i + start_address] = 0;
  }
  FlashMemory.update();
  tft.fillScreen(0x0000);
  tft.setFontSize(1);
  tft.setForeground(0xffff);
  tft.setCursor(0, 0);
  tft.print("Computing and encrypting new verification tag...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  compute_and_write_encrypted_tag_for_flash_integrity_check();
  return;
}

void view_login_from_flash(int chsn_slot){
  tft.setFontSize(2);
  int start_address = get_slot_start_address_for_login(chsn_slot);
  
  int extr_data[176];

  FlashMemory.read();
  for (int i = 0; i < 176; i++) {
    extr_data[i] = FlashMemory.buf[i + start_address];
      
  }
  int noz = 0; // Number of zeroes
  for (int i = 0; i < 176; i++) {
    if (extr_data[i] == 0)
      noz++;
  }
  //Serial.println(noz);
  if (noz == 176) {
    tft.fillScreen(0x0000);
    tft.setForeground(0x07e0);
    tft.setFontSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setFontSize(1);
    tft.setForeground(0xffff);
    tft.setCursor(0, 232);
    tft.print("Press any key to return to the main menu");
    press_any_key_to_continue();
  } else {
    clear_variables();
    String extr_ct;
    for (int i = 0; i < 176; i++) {
      int cv = extr_data[i];
      if (cv < 16)
        extr_ct += "0";
      extr_ct += String(cv, HEX);
    }
    decrypt_tag = false;
    decrypt_with_AES_Blowfish(extr_ct);

    String usrn_to_disp;
    for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_USERNAME; i ++){
      if (dec_st.charAt(i) > 31 && dec_st.charAt(i) < 127)
        usrn_to_disp += dec_st.charAt(i);
    }

    int shift_to_pass = MAX_NUM_OF_CHARS_FOR_USERNAME;
    int end_of_pass = MAX_NUM_OF_CHARS_FOR_USERNAME + MAX_NUM_OF_CHARS_FOR_PASSWORD;
    String pass_to_disp;
    for (int i = shift_to_pass; i < end_of_pass; i ++){
      if (dec_st.charAt(i) > 31 && dec_st.charAt(i) < 127)
        pass_to_disp += dec_st.charAt(i);
    }

    int shift_to_webs = MAX_NUM_OF_CHARS_FOR_USERNAME + MAX_NUM_OF_CHARS_FOR_PASSWORD;
    int end_of_webs = MAX_NUM_OF_CHARS_FOR_USERNAME + MAX_NUM_OF_CHARS_FOR_PASSWORD + MAX_NUM_OF_CHARS_FOR_WEBSITE;
    String webs_to_disp;
    for (int i = shift_to_webs; i < end_of_webs; i ++){
      if (dec_st.charAt(i) > 31 && dec_st.charAt(i) < 127)
        webs_to_disp += dec_st.charAt(i);
    }

    tft.fillScreen(0x0000);
    tft.setFontSize(2);
    tft.setCursor(0, 5);
    tft.setForeground(current_inact_clr);
    tft.print("Username:");
    tft.setForeground(0xffff);
    tft.println(usrn_to_disp);
    tft.setForeground(current_inact_clr);
    tft.print("Password:");
    tft.setForeground(0xffff);
    tft.println(pass_to_disp);
    tft.setForeground(current_inact_clr);
    tft.print("Website:");
    tft.setForeground(0xffff);
    tft.println(webs_to_disp);
    tft.setFontSize(1);
    tft.setForeground(0xffff);
    tft.setCursor(0, 222);
    tft.print("Press 'A' to print the record to the Serial Terminal");
    tft.setCursor(0, 232);
    tft.print("Press any key to return to the main menu");
    finish_input = false;
    rec_d = false;
    while (finish_input == false) {
      if (rec_d == true) {
        rec_d = false;

      if (i2c_data == 133 || i2c_data == 65 || i2c_data == 97) {
        print_login_to_serial(usrn_to_disp, pass_to_disp, webs_to_disp);
        finish_input = true;
      }
      else{
        finish_input = true;
      }
      }
      delayMicroseconds(400);
    }
    }
}

void print_login_to_serial(String decrypted_username, String decrypted_password, String decrypted_website){
  Serial.println();
  Serial.print("Username:\"");
  Serial.print(decrypted_username);
  Serial.println("\"");
  Serial.print("Password:\"");
  Serial.print(decrypted_password);
  Serial.println("\"");
  Serial.print("Website:\"");
  Serial.print(decrypted_website);
  Serial.println("\"");
}

void select_credit_card_from_flash(byte what_to_do_with_it) {
  // 0 - Add credit card
  // 1 - Delete credit card
  // 2 - View credit card
  delay(1);
  curr_key = 1;
  header_for_select_credit_card_from_flash(what_to_do_with_it);
  display_card_number_from_credit_card_in_flash();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    if (rec_d == true) {
      rec_d = false;
      //Serial.println(i2c_data);
      if (i2c_data == 130) { // Rightwards Arrow
        curr_key++;
      }

      if (i2c_data == 129) { // Leftwards Arrow
        curr_key--;
      }

    if (curr_key < 1)
      curr_key = 10;

    if (curr_key > 10)
      curr_key = 1;
      
      header_for_select_credit_card_from_flash(what_to_do_with_it);
      display_card_number_from_credit_card_in_flash();
      
      if (i2c_data == 13 || i2c_data == 133) { // Enter or A
        if (what_to_do_with_it == 0 && cont_to_next == false){
          cont_to_next = true;
          add_credit_card_to_flash_from_keyboard_and_encdr(curr_key);
        }
        if (what_to_do_with_it == 1 && cont_to_next == false){
          cont_to_next = true;
          delete_credit_card_from_flash(curr_key);
        }
        if (what_to_do_with_it == 2 && cont_to_next == false){
          cont_to_next = true;
          view_credit_card_from_flash(curr_key);
        }
      }

      if (i2c_data == 27 || i2c_data == 8) { // ESC, Backspace or B
        //call_main_menu();
        cont_to_next = true;
      }
    }
    delay(1);
  }
  return;
}

void add_credit_card_to_flash_from_keyboard_and_encdr(int chsn_slot) {
  enter_cardholder_for_credit_card(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void enter_cardholder_for_credit_card(int chsn_slot) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Cardholder Name");
  encdr_and_keyb_input();
  if (act == true) {
    enter_card_number_for_credit_card(chsn_slot, keyboard_input);
  }
  return;
}

void enter_card_number_for_credit_card(int chsn_slot, String entered_cardholder) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Card Number");
  encdr_and_keyb_input();
  if (act == true) {
    enter_expiry_for_credit_card(chsn_slot, entered_cardholder, keyboard_input);
  }
  return;
}

void enter_expiry_for_credit_card(int chsn_slot, String entered_cardholder, String entered_card_number) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Expiration Date");
  encdr_and_keyb_input();
  if (act == true) {
    enter_cvn_for_credit_card(chsn_slot, entered_cardholder, entered_card_number, keyboard_input);
  }
  return;
}

void enter_cvn_for_credit_card(int chsn_slot, String entered_cardholder, String entered_card_number, String entered_expiry) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter CVN");
  encdr_and_keyb_input();
  if (act == true) {
    enter_pin_for_credit_card(chsn_slot, entered_cardholder, entered_card_number, entered_expiry, keyboard_input);
  }
  return;
}

void enter_pin_for_credit_card(int chsn_slot, String entered_cardholder, String entered_card_number, String entered_expiry, String entered_cvn) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter PIN");
  encdr_and_keyb_input();
  if (act == true) {
    enter_zip_code_for_credit_card(chsn_slot, entered_cardholder, entered_card_number, entered_expiry, entered_cvn, keyboard_input);
  }
  return;
}

void enter_zip_code_for_credit_card(int chsn_slot, String entered_cardholder, String entered_card_number, String entered_expiry, String entered_cvn, String entered_pin) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter ZIP Code");
  encdr_and_keyb_input();
  if (act == true) {
    write_credit_card_to_flash(chsn_slot, entered_cardholder, entered_card_number, entered_expiry, entered_cvn, entered_pin, keyboard_input);
  }
  return;
}

void write_credit_card_to_flash(int chsn_slot, String entered_cardholder, String entered_card_number, String entered_expiry, String entered_cvn, String entered_pin, String entered_zip) {
  tft.fillScreen(0x0000);
  tft.setFontSize(1);
  tft.setForeground(0xffff);
  tft.setCursor(0, 0);
  tft.print("Adding credit card to the slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  int seed = generate_random_number();
  int seed1 = generate_random_number();
  if (seed1 != 0)
    seed *= seed1;
  int seed2 = generate_random_number();
  if (seed2 != 0)
    seed *= seed2;

  randomSeed(seed);
  
  char crdhldr [MAX_NUM_OF_CHARS_FOR_CARDHOLDER];
  char crdnmbr [MAX_NUM_OF_CHARS_FOR_CARD_NUMBER];
  char exprdt [MAX_NUM_OF_CHARS_FOR_EXPIRATION_DATE];
  char cvn_arr [MAX_NUM_OF_CHARS_FOR_CVN];
  char pin_arr [MAX_NUM_OF_CHARS_FOR_PIN];
  char zpc_arr [MAX_NUM_OF_CHARS_FOR_ZIP_CODE];

  for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_CARDHOLDER; i++){
    crdhldr[i] = 127 + random(129);
  }

  for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_CARD_NUMBER; i++){
    crdnmbr[i] = 127 + random(129);
  }

  for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_EXPIRATION_DATE; i++){
    exprdt[i] = 127 + random(129);
  }

  for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_CVN; i++){
    cvn_arr[i] = 127 + random(129);
  }

  for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_PIN; i++){
    pin_arr[i] = 127 + random(129);
  }

  for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_ZIP_CODE; i++){
    zpc_arr[i] = 127 + random(129);
  }
  
  int entered_cardholder_length = entered_cardholder.length();
  for (int i = 0; i < entered_cardholder_length; i++){
    if (i < MAX_NUM_OF_CHARS_FOR_CARDHOLDER)
      crdhldr[i] = entered_cardholder.charAt(i);
  }

  int entered_card_number_length = entered_card_number.length();
  for (int i = 0; i < entered_card_number_length; i++){
    if (i < MAX_NUM_OF_CHARS_FOR_CARD_NUMBER)
      crdnmbr[i] = entered_card_number.charAt(i);
  }

  int entered_expiry_length = entered_expiry.length();
  for (int i = 0; i < entered_expiry_length; i++){
    if (i < MAX_NUM_OF_CHARS_FOR_EXPIRATION_DATE)
      exprdt[i] = entered_expiry.charAt(i);
  }

  int entered_cvn_length = entered_cvn.length();
  for (int i = 0; i < entered_cvn_length; i++){
    if (i < MAX_NUM_OF_CHARS_FOR_CVN)
      cvn_arr[i] = entered_cvn.charAt(i);
  }

  int entered_pin_length = entered_pin.length();
  for (int i = 0; i < entered_pin_length; i++){
    if (i < MAX_NUM_OF_CHARS_FOR_PIN)
      pin_arr[i] = entered_pin.charAt(i);
  }

  int entered_zip_length = entered_zip.length();
  for (int i = 0; i < entered_zip_length; i++){
    if (i < MAX_NUM_OF_CHARS_FOR_ZIP_CODE)
      zpc_arr[i] = entered_zip.charAt(i);
  }

  String resulted_string;

  for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_CARDHOLDER; i++){
    resulted_string += crdhldr[i];
  }

  for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_CARD_NUMBER; i++){
    resulted_string += crdnmbr[i];
  }

  for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_EXPIRATION_DATE; i++){
    resulted_string += exprdt[i];
  }

  for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_CVN; i++){
    resulted_string += cvn_arr[i];
  }

  for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_PIN; i++){
    resulted_string += pin_arr[i];
  }

  for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_ZIP_CODE; i++){
    resulted_string += zpc_arr[i];
  }

  //Serial.println(resulted_string);
  //Serial.println(resulted_string.length());
  encrypt_with_AES_Blowfish(resulted_string);
  //Serial.println(dec_st);
  //Serial.println(dec_st.length());
  byte res[112];
  for (int i = 0; i < 224; i += 2) {
    if (i == 0) {
      if (dec_st.charAt(i) != 0 && dec_st.charAt(i + 1) != 0)
        res[i] = 16 * getNum(dec_st.charAt(i)) + getNum(dec_st.charAt(i + 1));
      if (dec_st.charAt(i) != 0 && dec_st.charAt(i + 1) == 0)
        res[i] = 16 * getNum(dec_st.charAt(i));
      if (dec_st.charAt(i) == 0 && dec_st.charAt(i + 1) != 0)
        res[i] = getNum(dec_st.charAt(i + 1));
      if (dec_st.charAt(i) == 0 && dec_st.charAt(i + 1) == 0)
        res[i] = 0;
    } else {
      if (dec_st.charAt(i) != 0 && dec_st.charAt(i + 1) != 0)
        res[i / 2] = 16 * getNum(dec_st.charAt(i)) + getNum(dec_st.charAt(i + 1));
      if (dec_st.charAt(i) != 0 && dec_st.charAt(i + 1) == 0)
        res[i / 2] = 16 * getNum(dec_st.charAt(i));
      if (dec_st.charAt(i) == 0 && dec_st.charAt(i + 1) != 0)
        res[i / 2] = getNum(dec_st.charAt(i + 1));
      if (dec_st.charAt(i) == 0 && dec_st.charAt(i + 1) == 0)
        res[i / 2] = 0;
    }
  }
  //for (int i = 1; i < 17; i++)
    //Serial.println(get_slot_start_address_for_credit_card(i));
  int start_address = get_slot_start_address_for_credit_card(chsn_slot);
  for (int i = 0; i < 112; i++) {
    FlashMemory.buf[i + start_address] = res[i];
  }
  FlashMemory.update();
  tft.fillScreen(0x0000);
  tft.setFontSize(1);
  tft.setForeground(0xffff);
  tft.setCursor(0, 0);
  tft.print("Computing and encrypting new verification tag...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  compute_and_write_encrypted_tag_for_flash_integrity_check();
  return;
}

void header_for_select_credit_card_from_flash(byte what_to_do_with_it){
  tft.fillScreen(0x0000);
  tft.setFontSize(2);
  if (what_to_do_with_it == 0) {
    tft.setForeground(current_inact_clr);
    disp_centered_text("Add Card to Slot " + String(curr_key) + "/" + String(10), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 1) {
    tft.setForeground(five_six_five_red_color);
    disp_centered_text("Delete Card " + String(curr_key) + "/" + String(10), 5);
    disp_button_designation_for_del();
  }
  if (what_to_do_with_it == 2) {
    tft.setForeground(current_inact_clr);
    disp_centered_text("View Card " + String(curr_key) + "/" + String(10), 5);
    disp_button_designation();
  }
}

void display_card_number_from_credit_card_in_flash(){
  tft.setFontSize(2);
  int start_address = get_slot_start_address_for_credit_card(curr_key);
  
  int extr_data[112];

  FlashMemory.read();
  for (int i = 0; i < 112; i++) {
    extr_data[i] = FlashMemory.buf[i + start_address];
      
  }
  int noz = 0; // Number of zeroes
  for (int i = 0; i < 112; i++) {
    if (extr_data[i] == 0)
      noz++;
  }
  //Serial.println(noz);
  if (noz == 112) {
    tft.setForeground(0x07e0);
    disp_centered_text("Empty", 35);
  } else {
    clear_variables();
    String extr_ct;
    for (int i = 0; i < 112; i++) {
      int cv = extr_data[i];
      if (cv < 16)
        extr_ct += "0";
      extr_ct += String(cv, HEX);
    }
    decrypt_tag = false;
    decrypt_with_AES_Blowfish(extr_ct);
    tft.setForeground(0xffff);
    int shift_to_card_number = MAX_NUM_OF_CHARS_FOR_CARDHOLDER;
    int end_of_card_number = MAX_NUM_OF_CHARS_FOR_CARDHOLDER + MAX_NUM_OF_CHARS_FOR_CARD_NUMBER;
    String crdn_to_disp;
    for (int i = shift_to_card_number; i < end_of_card_number; i ++){
      if (dec_st.charAt(i) > 31 && dec_st.charAt(i) < 127)
        crdn_to_disp += dec_st.charAt(i);
    }
    disp_centered_text(crdn_to_disp, 35);
  }
}

void delete_credit_card_from_flash(int chsn_slot){
  tft.fillScreen(0x0000);
  tft.setFontSize(1);
  tft.setForeground(0xffff);
  tft.setCursor(0, 0);
  tft.print("Deleting credit card from the slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  int start_address = get_slot_start_address_for_credit_card(chsn_slot);
  for (int i = 0; i < 112; i++) {
    FlashMemory.buf[i + start_address] = 0;
  }
  FlashMemory.update();
  tft.fillScreen(0x0000);
  tft.setFontSize(1);
  tft.setForeground(0xffff);
  tft.setCursor(0, 0);
  tft.print("Computing and encrypting new verification tag...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  compute_and_write_encrypted_tag_for_flash_integrity_check();
  return;
}

void view_credit_card_from_flash(int chsn_slot){
  tft.setFontSize(2);
  int start_address = get_slot_start_address_for_credit_card(chsn_slot);
  
  int extr_data[112];

  FlashMemory.read();
  for (int i = 0; i < 112; i++) {
    extr_data[i] = FlashMemory.buf[i + start_address];
      
  }
  int noz = 0; // Number of zeroes
  for (int i = 0; i < 112; i++) {
    if (extr_data[i] == 0)
      noz++;
  }
  //Serial.println(noz);
  if (noz == 112) {
    tft.fillScreen(0x0000);
    tft.setForeground(0x07e0);
    tft.setFontSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setFontSize(1);
    tft.setForeground(0xffff);
    tft.setCursor(0, 232);
    tft.print("Press any key to return to the main menu");
    press_any_key_to_continue();
  } else {
    clear_variables();
    String extr_ct;
    for (int i = 0; i < 112; i++) {
      int cv = extr_data[i];
      if (cv < 16)
        extr_ct += "0";
      extr_ct += String(cv, HEX);
    }
    decrypt_tag = false;
    decrypt_with_AES_Blowfish(extr_ct);

    String cardholder_to_disp;
    for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_CARDHOLDER; i ++){
      if (dec_st.charAt(i) > 31 && dec_st.charAt(i) < 127)
        cardholder_to_disp += dec_st.charAt(i);
    }

    int shift_to_card_num = MAX_NUM_OF_CHARS_FOR_CARDHOLDER;
    int end_of_card_num = MAX_NUM_OF_CHARS_FOR_CARDHOLDER + MAX_NUM_OF_CHARS_FOR_CARD_NUMBER;
    String card_num_to_disp;
    for (int i = shift_to_card_num; i < end_of_card_num; i ++){
      if (dec_st.charAt(i) > 31 && dec_st.charAt(i) < 127)
        card_num_to_disp += dec_st.charAt(i);
    }

    int shift_to_exp = MAX_NUM_OF_CHARS_FOR_CARDHOLDER + MAX_NUM_OF_CHARS_FOR_CARD_NUMBER;
    int end_of_exp = MAX_NUM_OF_CHARS_FOR_CARDHOLDER + MAX_NUM_OF_CHARS_FOR_CARD_NUMBER + MAX_NUM_OF_CHARS_FOR_EXPIRATION_DATE;
    String exp_to_disp;
    for (int i = shift_to_exp; i < end_of_exp; i ++){
      if (dec_st.charAt(i) > 31 && dec_st.charAt(i) < 127)
        exp_to_disp += dec_st.charAt(i);
    }

    int shift_to_cvn = MAX_NUM_OF_CHARS_FOR_CARDHOLDER + MAX_NUM_OF_CHARS_FOR_CARD_NUMBER + MAX_NUM_OF_CHARS_FOR_EXPIRATION_DATE;
    int end_of_cvn = MAX_NUM_OF_CHARS_FOR_CARDHOLDER + MAX_NUM_OF_CHARS_FOR_CARD_NUMBER + MAX_NUM_OF_CHARS_FOR_EXPIRATION_DATE + MAX_NUM_OF_CHARS_FOR_CVN;
    String cvn_to_disp;
    for (int i = shift_to_cvn; i < end_of_cvn; i ++){
      if (dec_st.charAt(i) > 31 && dec_st.charAt(i) < 127)
        cvn_to_disp += dec_st.charAt(i);
    }

    int shift_to_pin = MAX_NUM_OF_CHARS_FOR_CARDHOLDER + MAX_NUM_OF_CHARS_FOR_CARD_NUMBER + MAX_NUM_OF_CHARS_FOR_EXPIRATION_DATE + MAX_NUM_OF_CHARS_FOR_CVN;
    int end_of_pin = MAX_NUM_OF_CHARS_FOR_CARDHOLDER + MAX_NUM_OF_CHARS_FOR_CARD_NUMBER + MAX_NUM_OF_CHARS_FOR_EXPIRATION_DATE + MAX_NUM_OF_CHARS_FOR_CVN + MAX_NUM_OF_CHARS_FOR_PIN;
    String pin_to_disp;
    for (int i = shift_to_pin; i < end_of_pin; i ++){
      if (dec_st.charAt(i) > 31 && dec_st.charAt(i) < 127)
        pin_to_disp += dec_st.charAt(i);
    }

    int shift_to_zip = MAX_NUM_OF_CHARS_FOR_CARDHOLDER + MAX_NUM_OF_CHARS_FOR_CARD_NUMBER + MAX_NUM_OF_CHARS_FOR_EXPIRATION_DATE + MAX_NUM_OF_CHARS_FOR_CVN + MAX_NUM_OF_CHARS_FOR_PIN;
    int end_of_zip = MAX_NUM_OF_CHARS_FOR_CARDHOLDER + MAX_NUM_OF_CHARS_FOR_CARD_NUMBER + MAX_NUM_OF_CHARS_FOR_EXPIRATION_DATE + MAX_NUM_OF_CHARS_FOR_CVN + MAX_NUM_OF_CHARS_FOR_PIN + MAX_NUM_OF_CHARS_FOR_ZIP_CODE;
    String zip_to_disp;
    for (int i = shift_to_zip; i < end_of_zip; i ++){
      if (dec_st.charAt(i) > 31 && dec_st.charAt(i) < 127)
        zip_to_disp += dec_st.charAt(i);
    }

    tft.fillScreen(0x0000);
    tft.setFontSize(2);
    tft.setCursor(0, 5);
    tft.setForeground(current_inact_clr);
    tft.print("Cardholder Name:");
    tft.setForeground(0xffff);
    tft.println(cardholder_to_disp);
    tft.setForeground(current_inact_clr);
    tft.print("Card Number:");
    tft.setForeground(0xffff);
    tft.println(card_num_to_disp);
    tft.setForeground(current_inact_clr);
    tft.print("Espiration Date:");
    tft.setForeground(0xffff);
    tft.println(exp_to_disp);
    tft.setForeground(current_inact_clr);
    tft.print("CVN:");
    tft.setForeground(0xffff);
    tft.println(cvn_to_disp);
    tft.setForeground(current_inact_clr);
    tft.print("PIN:");
    tft.setForeground(0xffff);
    tft.println(pin_to_disp);
    tft.setForeground(current_inact_clr);
    tft.print("ZIP Code:");
    tft.setForeground(0xffff);
    tft.println(zip_to_disp);
    tft.setFontSize(1);
    tft.setForeground(0xffff);
    tft.setCursor(0, 222);
    tft.print("Press 'A' to print the record to the Serial Terminal");
    tft.setCursor(0, 232);
    tft.print("Press any key to return to the main menu");
    finish_input = false;
    rec_d = false;
    while (finish_input == false) {
      if (rec_d == true) {
        rec_d = false;

      if (i2c_data == 133 || i2c_data == 65 || i2c_data == 97) {
        print_credit_card_to_serial(cardholder_to_disp, card_num_to_disp, exp_to_disp, cvn_to_disp, pin_to_disp, zip_to_disp);
        finish_input = true;
      }
      else{
        finish_input = true;
      }
      }
      delayMicroseconds(400);
    }
    }
}

void print_credit_card_to_serial(String decrypted_cardholder, String decrypted_card_number, String decrypted_expiry, String decrypted_cvn, String decrypted_pin, String decrypted_zip){
  Serial.println();
  Serial.print("Cardholder Name:\"");
  Serial.print(decrypted_cardholder);
  Serial.println("\"");
  Serial.print("Card Number:\"");
  Serial.print(decrypted_card_number);
  Serial.println("\"");
  Serial.print("Expiration Date:\"");
  Serial.print(decrypted_expiry);
  Serial.println("\"");
  Serial.print("CVN:\"");
  Serial.print(decrypted_cvn);
  Serial.println("\"");
  Serial.print("PIN:\"");
  Serial.print(decrypted_pin);
  Serial.println("\"");
  Serial.print("ZIP Code:\"");
  Serial.print(decrypted_zip);
  Serial.println("\"");
}

int get_slot_start_address_for_credit_card(int chsn_slot){
  if (chsn_slot == 1)
    return 2873;
  else{
    return (2873 + (112 * (chsn_slot - 1)));
  }
}

int get_slot_start_address_for_login(int chsn_slot){
  if (chsn_slot == 1)
    return 57;
  else{
    return (57 + (176 * (chsn_slot - 1)));
  }
}

void hash_string_with_sha256() {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setForeground(0xffff);
  tft.setFontSize(1);
  set_stuff_for_input("Enter string to hash:");
  encdr_and_keyb_input();
  if (act == true) {
    hash_with_sha256();
  }
  clear_variables();
  call_main_menu();
  return;
}

void hash_with_sha256() {
  int str_len = keyboard_input.length() + 1;
  char keyb_inp_arr[str_len];
  keyboard_input.toCharArray(keyb_inp_arr, str_len);
  SHA256 hasher;
  hasher.doUpdate(keyb_inp_arr, strlen(keyb_inp_arr));
  byte authCode[SHA256_SIZE];
  hasher.doFinal(authCode);

  String res_hash;
  for (byte i = 0; i < SHA256HMAC_SIZE; i++) {
    if (authCode[i] < 0x10) {
      res_hash += 0;
    } {
      res_hash += String(authCode[i], HEX);
    }
  }
  tft.fillScreen(0x0000);
  tft.setForeground(current_inact_clr);
  tft.setFontSize(2);
  disp_centered_text("Resulted hash", 10);
  tft.setForeground(0xffff);
  tft.setCursor(0, 40);
  tft.println(res_hash);
  press_any_key_to_continue();
}

void Factory_Reset() {
  tft.fillScreen(0x0000);
  tft.setForeground(five_six_five_red_color);
  disp_centered_text("Factory Reset", 10);
  delay(500);
  disp_centered_text("Attention!!!", 50);
  tft.setForeground(0xffff);
  delay(500);
  disp_centered_text("All your data", 90);
  delay(500);
  disp_centered_text("will be lost!", 110);
  delay(500);
  tft.setForeground(0x1557);
  disp_centered_text("Are you sure you want", 150);
  disp_centered_text("to continue?", 170);
  tft.setFontSize(1);
  delay(5000);
  disp_button_designation_for_del();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    if (rec_d == true) {
      rec_d = false;
      
      if (i2c_data == 13 || i2c_data == 133) { // Enter or A
        perform_factory_reset();
        cont_to_next = true;
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

void perform_factory_reset() {
  tft.fillScreen(0x0000);
  tft.setFontSize(1);
  tft.setForeground(0xffff);
  tft.setCursor(0, 0);
  tft.print("Performing Factory Reset...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  delay(100);
  for (int i = 0; i < 4096; i++)
    FlashMemory.buf[i] = 0x00;
  FlashMemory.update();
  tft.fillScreen(0x0000);
  tft.setFontSize(2);
  tft.setForeground(0xffff);
  disp_centered_text("DONE", 10);
  disp_centered_text("Please reboot", 50);
  disp_centered_text("the device", 70);
  delay(100);
  for (;;) {}
}

String get_rfid_card() {
  digitalWrite(3, LOW);
  digitalWrite(11, HIGH);
  String read_card;
  finish_input = false;
  rec_d = false;
  while (finish_input == false) {
    if (rec_d == true) {
      rec_d = false;

      if (i2c_data > 31 && i2c_data < 127) {
        curr_key = i2c_data;
        read_card += char(curr_key);
      }

      if (i2c_data == 13) {
        finish_input = true;
      }
      
      //Serial.println(i2c_data);
    }
    delayMicroseconds(400);
  }
  digitalWrite(3, LOW);
  digitalWrite(11, LOW);
  delay(4);
  return read_card;
}

void approx_rfid_cards(){
  delay(24);
  int scr1 = generate_random_number() % 14;
  int scr2 = generate_random_number() % 14;
  int scr3 = generate_random_number() % 14;
  int scr4 = generate_random_number() % 14;
  if (scr1 == scr2)
    scr2++;
  if (scr2 > 13)
    scr2 = 0;
  if (scr2 == scr3)
    scr3++;
  if (scr3 > 13)
    scr3 = 0;
  if (scr3 == scr4)
    scr4++;
  if (scr4 > 13)
    scr4 = 0;
  tft.fillScreen(0x39e7);
  tft.setFontSize(2);
  tft.setBackground(0x39e7);
  tft.setForeground(0xffff);
  disp_centered_text("Midbar RTL8720DN", 9);
  disp_lock_scr(scr1, "Tap RFID Card N1");
  rfid_card1 = get_rfid_card();
  delay(24);
  disp_lock_scr(scr2, "Tap RFID Card N2");
  delay(500);
  rfid_card2 = get_rfid_card();
  delay(24);
  disp_lock_scr(scr3, "Tap RFID Card N3");
  delay(500);
  rfid_card3 = get_rfid_card();
  delay(24);
  disp_lock_scr(scr4, "Tap RFID Card N4");
  delay(500);
  rfid_card4 = get_rfid_card();
  tft.setBackground(0x0000);
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
    tft.fillScreen(0x0000);
    tft.setCursor(0, 0);
    tft.print("Loading...");
    tft.setCursor(0, 10);
    tft.print("Please wait for a while.");
  }
  else{
    tft.setCursor(0, 0);
    tft.print("Loading...");
    tft.setCursor(0, 10);
    tft.print("Please wait for a while.");
  }
  Serial.begin(115200);
  m = 2; // Set AES to 256-bit mode
  Wire.begin(7); // join i2c bus with address #7
  Wire.onReceive(receiveEvent); // register event
  pinMode(3, OUTPUT);
  digitalWrite(3, LOW);
  pinMode(11, OUTPUT);
  digitalWrite(11, LOW);
  approx_rfid_cards();
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
          hash_string_with_sha256();
        if (curr_key == 3)
          Factory_Reset();
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
