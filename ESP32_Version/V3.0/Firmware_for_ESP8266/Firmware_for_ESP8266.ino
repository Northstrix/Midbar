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
https://github.com/peterferrie/serpent
https://github.com/ddokkaebi/Blowfish
https://github.com/Northstrix/DES_and_3DES_Library_for_MCUs
https://github.com/ulwanski/sha512
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_ILI9341
https://github.com/adafruit/Adafruit_BusIO
https://github.com/GyverLibs/GyverBus
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/intrbiz/arduino-crypto
https://github.com/GyverLibs/EncButton
https://github.com/Chris--A/Keypad
https://github.com/platisd/nokia-5110-lcd-library
*/
#include <ESP8266WiFi.h>
#include <espnow.h>
#include <SoftwareSerial.h>
#include "sha512.h"
#include "aes.h"
#include "serpent.h"
#include "GBUS.h"
#include "Crypto.h"
#include <SPI.h>
#include <Adafruit_GFX.h>
#include <Adafruit_PCD8544.h>
Adafruit_PCD8544 display = Adafruit_PCD8544(D4, D3, D2, D1, D0);
SoftwareSerial mySerial(14, 12); // RX, TX
GBUS bus(&mySerial, 3, 10);
typedef struct struct_message {
  char l_srp[16];
  char r_srp[16];
  bool n;
} struct_message;

struct_message myData;
String plt;
byte tmp_st[8];
int tmp_s[8];
int m = 2; // AES-256

struct myStruct {
  char x;
};

byte hmackey_for_session_key[] = {"mgC32QpQfdYp1Y5J2q2sI9Rb1r9gT8L41R6e922ORMiAyW9yZV55L34v3eB2MGT2n0gX05dR8yO3F2g2WhsT35KpN3tLxL45WyuRBsEM2dc2Pg23k84m9okJk9y6TgXzH5tZr9743"};
uint8_t projection_key[32] = {
0xad,0x95,0xc0,0xce,
0xa5,0x41,0x3a,0x21,
0x0b,0xcb,0x5f,0xf6,
0x83,0xfb,0xb3,0x6f,
0x55,0x63,0xd6,0x9a,
0xd3,0xfe,0x1c,0x66,
0xf9,0x70,0x8e,0x89,
0xb4,0xe5,0x2e,0x6c
};
uint8_t proj_serp_key[32] = {
0xba,0x86,0x24,0xfc,
0x19,0x6f,0xe2,0xee,
0x87,0x8b,0x2d,0x6e,
0x76,0xc5,0x83,0x88,
0x33,0xe4,0x8f,0x38,
0x1e,0xbc,0xae,0x2f,
0x04,0x3a,0x66,0xae,
0xe7,0x61,0x02,0xdd
};

void incr_projection_key() {
  if (projection_key[0] == 255) {
    projection_key[0] = 0;
    if (projection_key[1] == 255) {
      projection_key[1] = 0;
      if (projection_key[2] == 255) {
        projection_key[2] = 0;
        if (projection_key[3] == 255) {
          projection_key[3] = 0;

          if (projection_key[4] == 255) {
            projection_key[4] = 0;
            if (projection_key[5] == 255) {
              projection_key[5] = 0;
              if (projection_key[6] == 255) {
                projection_key[6] = 0;
                if (projection_key[7] == 255) {
                  projection_key[7] = 0;

                  if (projection_key[8] == 255) {
                    projection_key[8] = 0;
                    if (projection_key[9] == 255) {
                      projection_key[9] = 0;
                      if (projection_key[10] == 255) {
                        projection_key[10] = 0;
                        if (projection_key[11] == 255) {
                          projection_key[11] = 0;

                          if (projection_key[12] == 255) {
                            projection_key[12] = 0;
                            if (projection_key[13] == 255) {
                              projection_key[13] = 0;
                              if (projection_key[14] == 255) {
                                projection_key[14] = 0;
                                if (projection_key[15] == 255) {
                                  projection_key[15] = 0;
                                } else {
                                  projection_key[15]++;
                                }
                              } else {
                                projection_key[14]++;
                              }
                            } else {
                              projection_key[13]++;
                            }
                          } else {
                            projection_key[12]++;
                          }

                        } else {
                          projection_key[11]++;
                        }
                      } else {
                        projection_key[10]++;
                      }
                    } else {
                      projection_key[9]++;
                    }
                  } else {
                    projection_key[8]++;
                  }

                } else {
                  projection_key[7]++;
                }
              } else {
                projection_key[6]++;
              }
            } else {
              projection_key[5]++;
            }
          } else {
            projection_key[4]++;
          }

        } else {
          projection_key[3]++;
        }
      } else {
        projection_key[2]++;
      }
    } else {
      projection_key[1]++;
    }
  } else {
    projection_key[0]++;
  }
}

void incr_proj_serp_key() {
  if (proj_serp_key[15] == 255) {
    proj_serp_key[15] = 0;
    if (proj_serp_key[14] == 255) {
      proj_serp_key[14] = 0;
      if (proj_serp_key[13] == 255) {
        proj_serp_key[13] = 0;
        if (proj_serp_key[12] == 255) {
          proj_serp_key[12] = 0;

          if (proj_serp_key[11] == 255) {
            proj_serp_key[11] = 0;
            if (proj_serp_key[10] == 255) {
              proj_serp_key[10] = 0;
              if (proj_serp_key[9] == 255) {
                proj_serp_key[9] = 0;
                if (proj_serp_key[8] == 255) {
                  proj_serp_key[8] = 0;

                  if (proj_serp_key[7] == 255) {
                    proj_serp_key[7] = 0;
                    if (proj_serp_key[6] == 255) {
                      proj_serp_key[6] = 0;
                      if (proj_serp_key[5] == 255) {
                        proj_serp_key[5] = 0;
                        if (proj_serp_key[4] == 255) {
                          proj_serp_key[4] = 0;

                          if (proj_serp_key[3] == 255) {
                            proj_serp_key[3] = 0;
                            if (proj_serp_key[2] == 255) {
                              proj_serp_key[2] = 0;
                              if (proj_serp_key[1] == 255) {
                                proj_serp_key[1] = 0;
                                if (proj_serp_key[0] == 255) {
                                  proj_serp_key[0] = 0;
                                } else {
                                  proj_serp_key[0]++;
                                }
                              } else {
                                proj_serp_key[1]++;
                              }
                            } else {
                              proj_serp_key[2]++;
                            }
                          } else {
                            proj_serp_key[3]++;
                          }

                        } else {
                          proj_serp_key[4]++;
                        }
                      } else {
                        proj_serp_key[5]++;
                      }
                    } else {
                      proj_serp_key[6]++;
                    }
                  } else {
                    proj_serp_key[7]++;
                  }

                } else {
                  proj_serp_key[8]++;
                }
              } else {
                proj_serp_key[9]++;
              }
            } else {
              proj_serp_key[10]++;
            }
          } else {
            proj_serp_key[11]++;
          }

        } else {
          proj_serp_key[12]++;
        }
      } else {
        proj_serp_key[13]++;
      }
    } else {
      proj_serp_key[14]++;
    }
  } else {
    proj_serp_key[15]++;
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
    display.clearDisplay();
  }
  delayMicroseconds(24);
  decr_Serpent(myData.l_srp, false);
  decr_Serpent(myData.r_srp, true);
  incr_projection_key();
  incr_proj_serp_key();
  incr_proj_serp_key();
}

void decr_Serpent(char res[], bool pass){
      uint8_t ct1[32], pt1[32], key[64];
      int plen, clen, i, j;
      serpent_key skey;
      serpent_blk ct2;
      uint32_t *p;
  
  for (i=0; i<1; i++) {
    hex2binproj (key);
  
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
      display.setCursor(0,0);
      display.println("Received text:");
      display.setTextSize(1);
      display.setTextColor(BLACK);
      display.setCursor(0,8);
      display.println(plt);
      display.display(); 
}

size_t hex2binproj (void *bin) {
  size_t len, i;
  int x;
  uint8_t *p=(uint8_t*)bin;
  for (i=0; i < 32; i++) {
    p[i] = (uint8_t)proj_serp_key[i];
  }
  return 32;
}

size_t hex2bin_for_der (void *bin) {
  size_t len, i;
  int x;
  uint8_t *p=(uint8_t*)bin;
  for (i=0; i < 32; i++) {
    p[i] = (uint8_t)proj_serp_key[i];
  }
  return 32;
}

void derive_session_keys(String inp_to_kder){
  inp_to_kder += "FFE";
  SHA256HMAC hmac(hmackey_for_session_key, sizeof(hmackey_for_session_key));
  int str_len = inp_to_kder.length() + 1;
  char input_arr[str_len];
  inp_to_kder.toCharArray(input_arr, str_len);
  hmac.doUpdate(input_arr);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  for(int i = 0; i < 4; i++){
    proj_serp_key[i] = authCode[16 + i];
  }
  for(int i = 0; i < 4; i++){
    projection_key[i] = authCode[20 + i];
  }
  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, i, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t *p;
  
  for (i=0; i < 1; i++) {
    hex2bin_for_der (key);
  
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
      ct2.b[i] = authCode[i];
    }
    //Serial.printf("\n");
    for (int i = 0; i < 1000; i++)
      serpent_encrypt (ct2.b, &skey, SERPENT_DECRYPT);

    for(int i = 0; i < 6; i++){
      proj_serp_key[i + 7] = ct2.b[i];
    }
    for(int i = 0; i < 6; i++){
      projection_key[i + 8] = ct2.b[8 + i];
    }
    /*
    for(int i = 0; i < 32; i++){
      Serial.println(proj_serp_key[i]);
    }
    for(int i = 0; i < 32; i++){
      Serial.println(projection_key[i]);
    }
    */
   /*
   Serial.println("Verification numbers");
   Serial.println(int(ct2.b[7]));
   Serial.println(int(ct2.b[6]));
   Serial.println(int(ct2.b[15]));
   */
   int firstnum = int(ct2.b[7]);
   int secondnum = int(ct2.b[6]);
   int thirdnum = int(ct2.b[15]);
   delay(24);
   disp_ver_num(firstnum, secondnum, thirdnum);
}

void disp_ver_num(int firstnum, int secondnum, int thirdnum){
   display.clearDisplay();
   display.setCursor(4,0);
   display.println(" Verification");
   display.setCursor(4,10);
   display.println("   numbers");
   display.setCursor(0,20);
   display.println(firstnum);
   display.setCursor(0,30);
   display.println(secondnum);
   display.setCursor(0,40);
   display.println(thirdnum);
   display.display();
}

void mdbr(){
  Serial.println("\nMibdar");
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(BLACK);
  display.setCursor(25,0);
  display.println("Midbar");
  display.display();
}

void setup() {
  Serial.begin(115200);
  mySerial.begin(9600);
  WiFi.mode(WIFI_STA);
  display.begin();
  display.setContrast(60);
  display.clearDisplay();
  display.display();
  delay(50);
  mdbr();
  delay(50);
  display.setCursor(4,10);
  display.println("Enter the key");
  display.display();
  // Init ESP-NOW
  if (esp_now_init() != 0) {
    Serial.println("Error initializing ESP-NOW");
    return;
  }
  esp_now_set_self_role(ESP_NOW_ROLE_SLAVE);
  esp_now_register_recv_cb(OnDataRecv);

  //Serial.println("Enter the key:");
  String pass_f_p;
  bool br = false;
  while(br == false){
    bus.tick();
    if (bus.gotData()) {
     myStruct data;
     bus.readData(data);
     pass_f_p += data.x;
     if (pass_f_p.length() == 2)
      pass_f_p += " ";
     if (pass_f_p.length() == 5)
      pass_f_p += " ";
     if (pass_f_p.length() == 8)
      pass_f_p += " ";
     if (pass_f_p.length() == 11)
      pass_f_p += " ";
     if (pass_f_p.length() == 14)
      pass_f_p += " ";
     if (pass_f_p.length() == 17)
      pass_f_p += " ";
     if (pass_f_p.length() == 20)
      pass_f_p += " ";
     if (pass_f_p.length() == 23)
      pass_f_p += " ";
     if (pass_f_p.length() == 26)
      pass_f_p += " ";
      /*
      Serial.print(pass_f_p);
      Serial.println();
      */
      display.setCursor(0,23);
      for( int i = 0; i < 14; i++){
        if (i > pass_f_p.length())
          break;
        display.print(pass_f_p.charAt(i)); 
      }
      display.setCursor(0,33);
      for( int i = 0; i < 14; i++){
        if (i > (pass_f_p.length() + 15))
          break;
        display.print(pass_f_p.charAt(i + 15));
      }
      display.display();
      if (pass_f_p.length() > 28){
        br = true;
        delay(120);
      }
      //Serial.print(pass_f_p.length());
   }
  }
  display.clearDisplay();
  display.setCursor(4,0);
  display.println("Deriving keys");
  display.display();
  derive_session_keys(pass_f_p);
}

void loop() {

}
