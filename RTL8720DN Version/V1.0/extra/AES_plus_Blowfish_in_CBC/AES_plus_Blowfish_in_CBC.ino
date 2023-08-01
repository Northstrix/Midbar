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
#include "aes.h"
#include "blowfish.h"
#include <Wire.h>

int m;
bool rec_d;
byte i2c_data;
String dec_st;
char iv[16];
char array_for_CBC_mode[16];
bool xor_with_ct;

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
  get_random_number();
  random_number ^= i2c_data;
  return int(random_number);
}

void receiveEvent(int howMany) {
  howMany = howMany;
  i2c_data = Wire.read();
  rec_d = true;
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
      incr_AES_key();
   }
}

void setup() {
  Serial.begin(115200);
  m = 2;
  Wire.begin(13);                // join i2c bus with address #13
  Wire.onReceive(receiveEvent); // register event
  Serial.begin(115200);         // start serial for output
  pinMode(3, OUTPUT);
  digitalWrite(3, LOW);
}

void loop() {
  back_AES_k();
  back_Bl_k();
  Serial.println();
  Serial.println("What do you want to do?");
  Serial.println("1.Encrypt record");
  Serial.println("2.Decrypt record");
  Serial.println("3.Set encryption algorithm to AES-128");
  Serial.println("4.Set encryption algorithm to AES-192");
  Serial.println("5.Set encryption algorithm to AES-256");
  while (!Serial.available()) {}
  int x = Serial.parseInt();
  if(x == 1){
    Serial.println("Enter plaintext:");
    String input;
    while (!Serial.available()) {}
    input = Serial.readString();
    int str_len = input.length() + 1;
    char input_arr[str_len];
    input.toCharArray(input_arr, str_len);
    int p = 0;
    dec_st = "";
    encrypt_iv_for_aes_blwfsh();
    while(str_len > p+1){
      split_by_sixteen(input_arr, p, str_len);
      p+=16;
    }
    Serial.println();
    Serial.println(dec_st);
    rest_AES_k();
    rest_Bl_k();
  }
  if(x == 2){
     String ct;
     Serial.println("Enter ciphertext");
     while (!Serial.available()) {}
     ct = Serial.readString();
     int ct_len = ct.length() + 1;
     char ct_array[ct_len];
     ct.toCharArray(ct_array, ct_len);
     int ext = 0;
     dec_st = "";
     while( ct_len > ext){
       split_dec(ct_array, ct_len, 0+ext);
       ext+=32;
     }
     Serial.println("Plaintext");
     Serial.println(dec_st);
     rest_AES_k();
     rest_Bl_k();
   }
   if(x == 3)
    m = 0;
   if(x == 4)
    m = 1;
   if(x == 5)
    m = 2;
}
