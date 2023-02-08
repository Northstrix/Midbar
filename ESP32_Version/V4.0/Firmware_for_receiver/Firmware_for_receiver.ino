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
https://github.com/Bodmer/TFT_eSPI
https://github.com/intrbiz/arduino-crypto
https://github.com/GyverLibs/EncButton
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/techpaul/PS2KeyMap
https://github.com/miguelbalboa/rfid
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/adafruit/Adafruit-ST7735-Library
https://github.com/Chris--A/Keypad
*/
#include <esp_now.h>
#include <WiFi.h>
#include "sha512.h"
#include "aes.h"
#include "serpent.h"
#include "Crypto.h"
#include <SPI.h>
#include <Adafruit_GFX.h>
#include <Adafruit_ST7735.h>
#define TFT_CS1         5
#define TFT_RST1        19
#define TFT_DC1         22
Adafruit_ST7735 tft = Adafruit_ST7735(TFT_CS1, TFT_DC1, TFT_RST1);

#include <Keypad.h>
#define ROW_NUM     4
#define COLUMN_NUM  4

char p_k[ROW_NUM][COLUMN_NUM] = {
  {'1', '2', '3', 'A'},
  {'4', '5', '6', 'B'},
  {'7', '8', '9', 'C'},
  {'F', '0', 'E', 'D'}
};
byte pin_rows[ROW_NUM]      = {13, 12, 14, 27};
byte pin_column[COLUMN_NUM] = {26, 25, 33, 32};
Keypad keypad = Keypad( makeKeymap(p_k), pin_rows, pin_column, ROW_NUM, COLUMN_NUM );

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

byte hmackey_for_session_key[] = {"e3D7j87lFl00I6yl348424TmpvO3z9w0s2m0NIC6UExscY9DyjdF3hE8Z3ig62hl4Q5qq49nbQnDEfz442c7z9Yv2yvEX48B8t9ZMhafAd8N3G0jljRjsI1bAK4sV0y36b4ya4w71O1W09Glv"};
uint8_t projection_key[32] = {
0x24,0xfc,0x4a,0xac,
0xff,0x31,0x5d,0x20,
0xd1,0x0b,0xcb,0x5b,
0x79,0x7e,0x51,0x79,
0x2a,0x93,0x16,0x9d,
0x84,0x8a,0x80,0x91,
0x38,0x9b,0xbe,0xbc,
0x30,0xe3,0x3b,0xc4
};
uint8_t proj_serp_key[32] = {
0x53,0x7d,0x1b,0x40,
0x27,0xef,0x0b,0x28,
0x93,0x96,0xb6,0xac,
0x5a,0x09,0x87,0x2c,
0xef,0x15,0x0b,0xe0,
0x9d,0xea,0xf7,0xad,
0xeb,0xef,0xba,0xde,
0xce,0xfa,0xf5,0x01
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

void disp_centered_text(String t_disp, int y){
   int16_t x1, y1;
   uint16_t w, h;
   tft.getTextBounds(t_disp, 160, 0, &x1, &y1, &w, &h);
   tft.setCursor(80 - (w / 2), y);
   tft.print(t_disp);
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
void OnDataRecv(const uint8_t * mac, const uint8_t *incomingData, int len) {
  memcpy(&myData, incomingData, sizeof(myData));
  if (myData.n == false){
    plt = "";
    tft.fillScreen(0x0000);
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
      disp_centered_text("Received text:", 5);
      tft.setTextSize(1);
      tft.setCursor(0,15);
      tft.println(plt);
       
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
   tft.fillScreen(0x0000);
   disp_centered_text("Verification", 5);
   disp_centered_text("numbers", 15);
   String ver_nmbr;
   ver_nmbr += String(firstnum);
   ver_nmbr += "   ";
   ver_nmbr += String(secondnum);
   ver_nmbr += "   ";
   ver_nmbr += String(thirdnum);  
   disp_centered_text(ver_nmbr, 30); 
}

void setup() {
  Serial.begin(115200);
  tft.initR(INITR_BLACKTAB);
  tft.setRotation(1);
  tft.fillScreen(0x0000);
  delay(50);
  disp_centered_text("MIDBAR", 5);
  delay(50);
  disp_centered_text("Enter the key", 20);
  WiFi.mode(WIFI_STA);
  if (esp_now_init() != ESP_OK) {
    Serial.println("Error initializing ESP-NOW");
    return;
  }
  esp_now_register_recv_cb(OnDataRecv);

  //Serial.println("Enter the key:");
  String pass_f_p;
  bool br = false;
  while(br == false){
    char key = keypad.getKey();
    if (key) {
     pass_f_p += key;
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
      tft.setCursor(38,40);
      for( int i = 0; i < 14; i++){
        if (i > pass_f_p.length())
          break;
        tft.print(pass_f_p.charAt(i)); 
      }
      tft.setCursor(38,50);
      for( int i = 0; i < 14; i++){
        if (i > (pass_f_p.length() + 15))
          break;
        tft.print(pass_f_p.charAt(i + 15));
      }
      
      if (pass_f_p.length() > 28){
        br = true;
        delay(120);
      }
      //Serial.print(pass_f_p.length());
   }
   delayMicroseconds(400);
  }
  delay(50);
  tft.fillScreen(0x0000);
  disp_centered_text("Deriving keys", 5);
  delay(50);
  derive_session_keys(pass_f_p);
}

void loop() {

}
