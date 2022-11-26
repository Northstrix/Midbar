/*
Midbar
Distributed under the MIT License
© Copyright Maxim Bortnikov 2022
For more information please visit
https://sourceforge.net/projects/midbar/
https://osdn.net/projects/midbar/
https://github.com/Northstrix/Midbar
Required libraries:
https://github.com/zhouyangchao/AES
https://github.com/peterferrie/serpent
https://github.com/ddokkaebi/Blowfish
https://github.com/ulwanski/sha512
https://github.com/adafruit/Adafruit_SSD1306
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/intrbiz/arduino-crypto
https://github.com/Northstrix/DES_and_3DES_Library_for_MCUs
https://github.com/GyverLibs/EncButton
*/
#include <SPI.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <EEPROM.h>
#include <EncButton2.h>
#include "DES.h"
#include "aes.h"
#include "blowfish.h"
#include "serpent.h"
#include "Crypto.h"
#include "ESP8266TrueRandom.h"
#include "midbaricon.h"
#include "sha512.h"

#define EEPROM_SIZE 4095
Adafruit_SSD1306 oled(128, 64, &Wire);

EncButton2<EB_ENC> enc0(INPUT, D5, D6);
EncButton2<EB_BTN> a_button(INPUT, D4);
EncButton2<EB_BTN> b_button(INPUT, D3);
EncButton2<EB_BTN> encoder_button(INPUT, D7);
int curr_key;
String encoder_input;

DES des;
Blowfish blowfish;

int m;
String dec_st;
String dec_tag;
int pass_to_serp[16];
int decract;

// Keys (Below)

String kderalgs = "M4x6m6dvs94bpUpQh7Y10Dt09FuqDKIQYH1alCxcA58A3CRX";
int numofkincr = 353;
byte hmackey[] = {"pUZf2Oz76jRV1vNiYZQ91cz6Tgz2q62Fz6T30dzGKqu2ZUEHd9cf8L3cyqlY9aOmY1801K6C6A4ErC9WPkIAq25o83GEDCrhG22rrDsQ4kW3piEZG333iwGSYSM7U5TZuFG25ErCfMi188"};
byte des_key[] = {
0x03,0x08,0xdb,0xc0,0xb7,0xc9,0x22,0x9a,
0x2c,0x62,0x50,0x93,0x81,0xb2,0x9b,0x92,
0x7b,0xac,0xb8,0xb1,0xa3,0xfb,0xec,0xaf
};
uint8_t AES_key[32] = {
0xac,0x64,0x7c,0xe3,
0xa4,0x78,0xf0,0xf3,
0xfe,0x60,0x8c,0x19,
0x03,0xbd,0x45,0xeb,
0xd2,0x3e,0xc1,0x5b,
0x50,0xcb,0x55,0x8f,
0xc8,0xa5,0xcd,0xc8,
0xf0,0x8b,0x12,0xbc
};
unsigned char Blwfsh_key[] = {
0xf1,0x5a,0xae,0x52,
0xf3,0xdf,0xbc,0xe2,
0xae,0x16,0x57,0xbb,
0x3b,0xf6,0xb6,0xd4,
0xad,0x6d,0xbd,0x7b,
0x51,0x74,0xcb,0x38
};
uint8_t serp_key[32] = {
0x12,0xc9,0xfb,0xf2,
0xf7,0x13,0xdf,0x82,
0xe4,0x1f,0xb6,0xa0,
0x4a,0x91,0xda,0xd2,
0x72,0xf0,0x44,0x2f,
0x2f,0xf4,0x62,0x6a,
0xae,0x3f,0xc2,0x3c,
0xe8,0xa0,0xa0,0x6b
};

// Keys (Above)

byte back_des_key[24];
uint8_t back_serp_key[32];
unsigned char back_Blwfsh_key[16];
uint8_t back_AES_key[32];

void back_serp_k() {
  for (int i = 0; i < 32; i++) {
    back_serp_key[i] = serp_key[i];
  }
}

void rest_serp_k() {
  for (int i = 0; i < 32; i++) {
    serp_key[i] = back_serp_key[i];
  }
}

void back_Bl_k() {
  for (int i = 0; i < 16; i++) {
    back_Blwfsh_key[i] = Blwfsh_key[i];
  }
}

void rest_Bl_k() {
  for (int i = 0; i < 16; i++) {
    Blwfsh_key[i] = back_Blwfsh_key[i];
  }
}

void back_AES_k() {
  for (int i = 0; i < 32; i++) {
    back_AES_key[i] = AES_key[i];
  }
}

void rest_AES_k() {
  for (int i = 0; i < 32; i++) {
    AES_key[i] = back_AES_key[i];
  }
}

void back_3des_k() {
  for (int i = 0; i < 24; i++) {
    back_des_key[i] = des_key[i];
  }
}

void rest_3des_k() {
  for (int i = 0; i < 24; i++) {
    des_key[i] = back_des_key[i];
  }
}

void incr_des_key() {
  if (des_key[7] == 255) {
    des_key[7] = 0;
    if (des_key[6] == 255) {
      des_key[6] = 0;
      if (des_key[5] == 255) {
        des_key[5] = 0;
        if (des_key[4] == 255) {
          des_key[4] = 0;
          if (des_key[3] == 255) {
            des_key[3] = 0;
            if (des_key[2] == 255) {
              des_key[2] = 0;
              if (des_key[1] == 255) {
                des_key[1] = 0;
                if (des_key[0] == 255) {
                  des_key[0] = 0;
                } else {
                  des_key[0]++;
                }
              } else {
                des_key[1]++;
              }
            } else {
              des_key[2]++;
            }
          } else {
            des_key[3]++;
          }
        } else {
          des_key[4]++;
        }
      } else {
        des_key[5]++;
      }
    } else {
      des_key[6]++;
    }
  } else {
    des_key[7]++;
  }

  if (des_key[15] == 255) {
    des_key[15] = 0;
    if (des_key[14] == 255) {
      des_key[14] = 0;
      if (des_key[13] == 255) {
        des_key[13] = 0;
        if (des_key[12] == 255) {
          des_key[12] = 0;
          if (des_key[11] == 255) {
            des_key[11] = 0;
            if (des_key[10] == 255) {
              des_key[10] = 0;
              if (des_key[9] == 255) {
                des_key[9] = 0;
                if (des_key[8] == 255) {
                  des_key[8] = 0;
                } else {
                  des_key[8]++;
                }
              } else {
                des_key[9]++;
              }
            } else {
              des_key[10]++;
            }
          } else {
            des_key[11]++;
          }
        } else {
          des_key[12]++;
        }
      } else {
        des_key[13]++;
      }
    } else {
      des_key[14]++;
    }
  } else {
    des_key[15]++;
  }

  if (des_key[23] == 255) {
    des_key[23] = 0;
    if (des_key[22] == 255) {
      des_key[22] = 0;
      if (des_key[21] == 255) {
        des_key[21] = 0;
        if (des_key[20] == 255) {
          des_key[20] = 0;
          if (des_key[19] == 255) {
            des_key[19] = 0;
            if (des_key[18] == 255) {
              des_key[18] = 0;
              if (des_key[17] == 255) {
                des_key[17] = 0;
                if (des_key[16] == 255) {
                  des_key[16] = 0;
                } else {
                  des_key[16]++;
                }
              } else {
                des_key[17]++;
              }
            } else {
              des_key[18]++;
            }
          } else {
            des_key[19]++;
          }
        } else {
          des_key[20]++;
        }
      } else {
        des_key[21]++;
      }
    } else {
      des_key[22]++;
    }
  } else {
    des_key[23]++;
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

void incr_serp_key() {
  if (serp_key[15] == 255) {
    serp_key[15] = 0;
    if (serp_key[14] == 255) {
      serp_key[14] = 0;
      if (serp_key[13] == 255) {
        serp_key[13] = 0;
        if (serp_key[12] == 255) {
          serp_key[12] = 0;
          if (serp_key[11] == 255) {
            serp_key[11] = 0;
            if (serp_key[10] == 255) {
              serp_key[10] = 0;
              if (serp_key[9] == 255) {
                serp_key[9] = 0;
                if (serp_key[8] == 255) {
                  serp_key[8] = 0;
                  if (serp_key[7] == 255) {
                    serp_key[7] = 0;
                    if (serp_key[6] == 255) {
                      serp_key[6] = 0;
                      if (serp_key[5] == 255) {
                        serp_key[5] = 0;
                        if (serp_key[4] == 255) {
                          serp_key[4] = 0;
                          if (serp_key[3] == 255) {
                            serp_key[3] = 0;
                            if (serp_key[2] == 255) {
                              serp_key[2] = 0;
                              if (serp_key[1] == 255) {
                                serp_key[1] = 0;
                                if (serp_key[0] == 255) {
                                  serp_key[0] = 0;
                                } else {
                                  serp_key[0]++;
                                }
                              } else {
                                serp_key[1]++;
                              }
                            } else {
                              serp_key[2]++;
                            }
                          } else {
                            serp_key[3]++;
                          }
                        } else {
                          serp_key[4]++;
                        }
                      } else {
                        serp_key[5]++;
                      }
                    } else {
                      serp_key[6]++;
                    }
                  } else {
                    serp_key[7]++;
                  }
                } else {
                  serp_key[8]++;
                }
              } else {
                serp_key[9]++;
              }
            } else {
              serp_key[10]++;
            }
          } else {
            serp_key[11]++;
          }
        } else {
          serp_key[12]++;
        }
      } else {
        serp_key[13]++;
      }
    } else {
      serp_key[14]++;
    }
  } else {
    serp_key[15]++;
  }
}

size_t hex2bin(void * bin) {
  size_t len, i;
  int x;
  uint8_t * p = (uint8_t * ) bin;
  for (i = 0; i < 32; i++) {
    p[i] = (uint8_t) serp_key[i];
  }
  return 32;
}

int getNum(char ch) {
  int num = 0;
  if (ch >= '0' && ch <= '9') {
    num = ch - 0x30;
  } else {
    switch (ch) {
    case 'A':
    case 'a':
      num = 10;
      break;
    case 'B':
    case 'b':
      num = 11;
      break;
    case 'C':
    case 'c':
      num = 12;
      break;
    case 'D':
    case 'd':
      num = 13;
      break;
    case 'E':
    case 'e':
      num = 14;
      break;
    case 'F':
    case 'f':
      num = 15;
      break;
    default:
      num = 0;
    }
  }
  return num;
}

char getChar(int num) {
  char ch;
  if (num >= 0 && num <= 9) {
    ch = char(num + 48);
  } else {
    switch (num) {
    case 10:
      ch = 'a';
      break;
    case 11:
      ch = 'b';
      break;
    case 12:
      ch = 'c';
      break;
    case 13:
      ch = 'd';
      break;
    case 14:
      ch = 'e';
      break;
    case 15:
      ch = 'f';
      break;
    }
  }
  return ch;
}

void back_keys() {
  back_3des_k();
  back_AES_k();
  back_Bl_k();
  back_serp_k();
}

void rest_keys() {
  rest_3des_k();
  rest_AES_k();
  rest_Bl_k();
  rest_serp_k();
}

void clear_variables() {
  encoder_input = "";
  dec_st = "";
  dec_tag = "";
  decract = 0;
}

// 3DES + AES + Blowfish + Serpent (Below)

void split_by_ten(char plntxt[], int k, int str_len) {
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  byte res2[8] = {
    0,
    0
  };

  for (int i = 0; i < 8; i++) {
    if (i + k > str_len - 1)
      break;
    res[i] = byte(plntxt[i + k]);
  }

  for (int i = 0; i < 2; i++) {
    if (i + 8 + k > str_len - 1)
      break;
    res2[i] = byte(plntxt[i + 8 + k]);
  }
  encrypt_with_tdes(res, res2);
}

void encrypt_with_tdes(byte res[], byte res2[]) {
  randomSeed(ESP8266TrueRandom.random());
  for (int i = 2; i < 8; i++) {
    res2[i] = ESP8266TrueRandom.random(0, 256);
  }

  byte out[8];
  byte out2[8];
  des.tripleEncrypt(out, res, des_key);
  incr_des_key();
  des.tripleEncrypt(out2, res2, des_key);
  incr_des_key();

  char t_aes[16];

  for (int i = 0; i < 8; i++) {
    int b = out[i];
    t_aes[i] = char(b);
  }

  for (int i = 0; i < 8; i++) {
    int b = out2[i];
    t_aes[i + 8] = char(b);
  }

  encrypt_with_AES(t_aes);
}

void encrypt_with_AES(char t_enc[]) {
  uint8_t text[16] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 16; i++) {
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  uint32_t AES_key_bit[3] = {
    128,
    192,
    256
  };
  int i = 0;
  aes_context ctx;
  aes_set_key( & ctx, AES_key, AES_key_bit[m]);
  aes_encrypt_block( & ctx, cipher_text, text);
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
  for (int i = 0; i < 8; i++) {
    first_eight[i] = (unsigned char) cipher_text[i];
    second_eight[i] = (unsigned char) cipher_text[i + 8];
  }
  encrypt_with_Blowfish(first_eight, false);
  encrypt_with_Blowfish(second_eight, true);
  encrypt_with_serpent();
}

void encrypt_with_Blowfish(unsigned char inp[], bool lrside) {
  unsigned char plt[8];
  for (int i = 0; i < 8; i++)
    plt[i] = inp[i];
  blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
  blowfish.Encrypt(plt, plt, sizeof(plt));
  String encrypted_with_blowfish;
  for (int i = 0; i < 8; i++) {
    if (lrside == false)
      pass_to_serp[i] = int(plt[i]);
    if (lrside == true)
      pass_to_serp[i + 8] = int(plt[i]);
  }
  incr_Blwfsh_key();
}

void encrypt_with_serpent() {
  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, b, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t * p;

  for (b = 0; b < 1; b++) {
    hex2bin(key);

    // set key
    memset( & skey, 0, sizeof(skey));
    p = (uint32_t * ) & skey.x[0][0];

    serpent_setkey( & skey, key);
    //Serial.printf ("\nkey=");
    /*
    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      Serial.printf ("%08X ", p[j]);
    }
    */
    for (int i = 0; i < 16; i++) {
      ct2.b[i] = pass_to_serp[i];
    }
    serpent_encrypt(ct2.b, & skey, SERPENT_ENCRYPT);
    incr_serp_key();
    /*
    for (int i = 0; i < 16; i++) {
      if (ct2.b[i] < 16)
        Serial.print("0");
      Serial.print(ct2.b[i], HEX);
    }
    */
    for (int i = 0; i < 16; i++) {
      if (ct2.b[i] < 16)
        dec_st += "0";
      dec_st += String(ct2.b[i], HEX);
    }
  }
}

void split_for_decryption(char ct[], int ct_len, int p) {
  int br = false;
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 32; i += 2) {
    if (i + p > ct_len - 1) {
      br = true;
      break;
    }
    if (i == 0) {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i] = 0;
    } else {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i / 2] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i / 2] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i / 2] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i / 2] = 0;
    }
  }
  if (br == false) {
    uint8_t ct1[32], pt1[32], key[64];
    int plen, clen, i, j;
    serpent_key skey;
    serpent_blk ct2;
    uint32_t * p;

    for (i = 0; i < 1; i++) {
      hex2bin(key);

      // set key
      memset( & skey, 0, sizeof(skey));
      p = (uint32_t * ) & skey.x[0][0];

      serpent_setkey( & skey, key);
      //Serial.printf ("\nkey=");

      for (j = 0; j < sizeof(skey) / sizeof(serpent_subkey_t) * 4; j++) {
        if ((j % 8) == 0) putchar('\n');
        //Serial.printf ("%08X ", p[j]);
      }

      for (int i = 0; i < 16; i++)
        ct2.b[i] = res[i];
      /*
      Serial.printf ("\n\n");
      for(int i = 0; i<16; i++){
      Serial.printf("%x", ct2.b[i]);
      Serial.printf(" ");
      */
    }
    //Serial.printf("\n");
    serpent_encrypt(ct2.b, & skey, SERPENT_DECRYPT);
    incr_serp_key();
    unsigned char lh[8];
    unsigned char rh[8];
    for (int i = 0; i < 8; i++) {
      lh[i] = (unsigned char) int(ct2.b[i]);
      rh[i] = (unsigned char) int(ct2.b[i + 8]);
    }
    blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
    blowfish.Decrypt(lh, lh, sizeof(lh));
    incr_Blwfsh_key();
    blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
    blowfish.Decrypt(rh, rh, sizeof(rh));
    incr_Blwfsh_key();
    uint8_t ret_text[16] = {
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0
    };
    uint8_t cipher_text[16] = {
      0
    };
    for (int i = 0; i < 8; i++) {
      int c = int(lh[i]);
      cipher_text[i] = c;
    }
    for (int i = 0; i < 8; i++) {
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
    uint32_t AES_key_bit[3] = {
      128,
      192,
      256
    };
    aes_context ctx;
    aes_set_key( & ctx, AES_key, AES_key_bit[m]);
    aes_decrypt_block( & ctx, ret_text, cipher_text);
    incr_AES_key();

    byte res[8];
    byte res2[8];

    for (int i = 0; i < 8; i++) {
      res[i] = int(ret_text[i]);
      res2[i] = int(ret_text[i + 8]);
    }

    byte out[8];
    byte out2[8];
    des.tripleDecrypt(out, res, des_key);
    incr_des_key();
    des.tripleDecrypt(out2, res2, des_key);
    incr_des_key();
    /*
        Serial.println();
        for (int i=0; i<8; i++) {
          if(out[i]<8)
            Serial.print("0");
          Serial.print(out[i],HEX);
        }

        for (int i=0; i<8; i++) {
          if(out2[i]<8)
            Serial.print("0");
          Serial.print(out[i],HEX);
        }
        Serial.println();
    */

    if (decract > 2) {
      for (i = 0; i < 8; ++i) {
        if (out[i] > 0)
          dec_st += char(out[i]);
      }

      for (i = 0; i < 2; ++i) {
        if (out2[i] > 0)
          dec_st += char(out2[i]);
      }
    } else {
      for (i = 0; i < 8; ++i) {
        if (out[i] < 0x10)
          dec_tag += "0";
        dec_tag += String(out[i], HEX);
      }

      for (i = 0; i < 2; ++i) {
        if (out2[i] < 0x10)
          dec_tag += "0";
        dec_tag += String(out2[i], HEX);
      }
    }
    decract++;
  }
}

void encr_hash_for_tdes_aes_blf_srp(String input) {
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  hmac.doUpdate(input_arr);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  int p = 0;
  char hmacchar[30];
  for (int i = 0; i < 30; i++) {
    hmacchar[i] = char(authCode[i]);
  }
  for (int i = 0; i < 3; i++) {
    split_by_ten(hmacchar, p, 100);
    p += 10;
  }
}

void encrypt_with_TDES_AES_Blowfish_Serp(String input) {
  back_keys();
  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(input);
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  int p = 0;
  while (str_len > p + 1) {
    split_by_ten(input_arr, p, str_len);
    p += 10;
  }
  rest_keys();
}

void encrypt_without_hash_TDES_AES_Blowfish_Serp(String input) {
  back_keys();
  clear_variables();
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  int p = 0;
  while (str_len > p + 1) {
    split_by_ten(input_arr, p, str_len);
    p += 10;
  }
  rest_keys();
}

void decrypt_with_TDES_AES_Blowfish_Serp(String ct) {
  back_keys();
  clear_variables();
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  while (ct_len > ext) {
    split_for_decryption(ct_array, ct_len, 0 + ext);
    ext += 32;
  }
  rest_keys();
}

// 3DES + AES + Blowfish + Serpent (Above)

// Serpent (Below)

void split_by_eight_for_serp_only(char plntxt[], int k, int str_len) {
  char res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 8; i++) {
    if (i + k > str_len - 1)
      break;
    res[i] = plntxt[i + k];
  }
  randomSeed(ESP8266TrueRandom.random());
  for (int i = 8; i < 16; i++) {
    res[i] = ESP8266TrueRandom.random(0, 256);
  }
  int tmp_s[16];
  for (int i = 0; i < 16; i++) {
    tmp_s[i] = res[i];
  }

  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, b, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t * p;

  for (b = 0; b < 1; b++) {
    hex2bin(key);

    // set key
    memset( & skey, 0, sizeof(skey));
    p = (uint32_t * ) & skey.x[0][0];

    serpent_setkey( & skey, key);
    //Serial.printf ("\nkey=");
    /*
    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      Serial.printf ("%08X ", p[j]);
    }
    */
    for (int i = 0; i < 16; i++) {
      ct2.b[i] = tmp_s[i];
    }
    serpent_encrypt(ct2.b, & skey, SERPENT_ENCRYPT);
    for (int i = 0; i < 16; i++) {
      if (ct2.b[i] < 16)
        Serial.print("0");
      Serial.print(ct2.b[i], HEX);
    }
  }
  incr_serp_key();
}

void split_for_dec_serp_only(char ct[], int ct_len, int p) {
  int br = false;
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 32; i += 2) {
    if (i + p > ct_len - 1) {
      br = true;
      break;
    }
    if (i == 0) {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i] = 0;
    } else {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i / 2] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i / 2] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i / 2] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i / 2] = 0;
    }
  }
  if (br == false) {
    uint8_t ct1[32], pt1[32], key[64];
    int plen, clen, i, j;
    serpent_key skey;
    serpent_blk ct2;
    uint32_t * p;

    for (i = 0; i < 1; i++) {
      hex2bin(key);

      // set key
      memset( & skey, 0, sizeof(skey));
      p = (uint32_t * ) & skey.x[0][0];

      serpent_setkey( & skey, key);
      //Serial.printf ("\nkey=");

      for (j = 0; j < sizeof(skey) / sizeof(serpent_subkey_t) * 4; j++) {
        if ((j % 8) == 0) putchar('\n');
        //Serial.printf ("%08X ", p[j]);
      }

      for (int i = 0; i < 16; i++)
        ct2.b[i] = res[i];
      /*
      Serial.printf ("\n\n");
      for(int i = 0; i<16; i++){
      Serial.printf("%x", ct2.b[i]);
      Serial.printf(" ");
      */
    }
    //Serial.printf("\n");
    serpent_encrypt(ct2.b, & skey, SERPENT_DECRYPT);
    if (decract < 4) {
      for (i = 0; i < 8; i++) {
        if (ct2.b[i] < 0x10)
          dec_tag += 0;
        dec_tag += String(ct2.b[i], HEX);
      }
    } else {
      for (i = 0; i < 8; ++i) {
        dec_st += (char(ct2.b[i]));
      }
    }
    decract++;
  }
  incr_serp_key();
}

void encr_hash_for_serpent_only(String input) {
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  hmac.doUpdate(input_arr);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  int p = 0;
  char hmacchar[32];
  for (int i = 0; i < 32; i++) {
    hmacchar[i] = char(authCode[i]);
  }
  for (int i = 0; i < 4; i++) {
    split_by_eight_for_serp_only(hmacchar, p, 100);
    p += 8;
  }
}

void encrypt_with_seprent_only(String input) {
  back_keys();
  clear_variables();
  encr_hash_for_serpent_only(input);
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  int p = 0;
  while (str_len > p + 1) {
    split_by_eight_for_serp_only(input_arr, p, str_len);
    p += 8;
  }
  rest_keys();
}

void decrypt_with_serpent_only(String ct) {
  back_keys();
  clear_variables();
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  while (ct_len > ext) {
    split_for_dec_serp_only(ct_array, ct_len, 0 + ext);
    ext += 32;
  }
  rest_keys();
}

// Serpent (Above)

// 3DES (Below)

void split_by_four_for_encr_tdes(char plntxt[], int k, int str_len) {
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 4; i++) {
    if (i + k > str_len - 1)
      break;
    res[i] = byte(plntxt[i + k]);
  }
  randomSeed(ESP8266TrueRandom.random());
  for (int i = 4; i < 8; i++) {
    res[i] = ESP8266TrueRandom.random(0, 256);
  }
  encr_TDES(res);
}

void encr_TDES(byte inp_for_tdes[]) {
  byte out_of_tdes[8];
  des.tripleEncrypt(out_of_tdes, inp_for_tdes, des_key);
  for (int i = 0; i < 8; i++) {
    if (out_of_tdes[i] < 16)
      Serial.print("0");
    Serial.print(out_of_tdes[i], HEX);
  }
  incr_des_key();
}

void decr_eight_chars_block_tdes(char ct[], int ct_len, int p) {
  int br = false;
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 16; i += 2) {
    if (i + p > ct_len - 1) {
      br = true;
      break;
    }
    if (i == 0) {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i] = 0;
    } else {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i / 2] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i / 2] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i / 2] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i / 2] = 0;
    }
  }
  if (br == false) {
    byte decr_text[8];
    des.tripleDecrypt(decr_text, res, des_key);
    for (int i = 0; i < 4; ++i) {
      dec_st += (char(decr_text[i]));
    }
    decract++;
  }
  incr_des_key();
}

void encrypt_with_tdes_only(String input) {
  back_keys();
  clear_variables();
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  int p = 0;
  while (str_len > p + 1) {
    split_by_four_for_encr_tdes(input_arr, p, str_len);
    p += 4;
  }
  rest_keys();
}

void decrypt_with_tdes_only(String ct) {
  back_keys();
  clear_variables();
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  while (ct_len > ext) {
    decr_eight_chars_block_tdes(ct_array, ct_len, 0 + ext);
    ext += 16;
  }
  rest_keys();
}

// 3DES (Above)

bool verify_integrity() {
  int str_lentg = dec_st.length() + 1;
  char char_arraytg[str_lentg];
  dec_st.toCharArray(char_arraytg, str_lentg);
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  hmac.doUpdate(char_arraytg);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  String res_hash;

  for (byte i = 0; i < SHA256HMAC_SIZE - 2; i++) {
    if (authCode[i] < 0x10) {
      res_hash += 0;
    } {
      res_hash += String(authCode[i], HEX);
    }
  }
  /*
  Serial.println(dec_tag);
  Serial.println(res_hash);
  */
  return dec_tag.equals(res_hash);
}

bool verify_integrity_thirty_two() {
  int str_lentg = dec_st.length() + 1;
  char char_arraytg[str_lentg];
  dec_st.toCharArray(char_arraytg, str_lentg);
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  hmac.doUpdate(char_arraytg);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  String res_hash;

  for (byte i = 0; i < SHA256HMAC_SIZE; i++) {
    if (authCode[i] < 0x10) {
      res_hash += 0;
    } {
      res_hash += String(authCode[i], HEX);
    }
  }

  return dec_tag.equals(res_hash);
}

void display_midbar_icon() {
  oled.clearDisplay();
  for (int i = 0; i < 68; i++) {
    for (int j = 0; j < 16; j++) {
      if (mdbicon[i][j] == false)
        oled.drawPixel(i + 29, j, WHITE);
    }
  }
  for (int i = 0; i < 12; i++)
    oled.drawPixel(97, 4 + i, WHITE);
  oled.display();
}

void disp_centered_text(String text, int h) {
  int16_t x1;
  int16_t y1;
  uint16_t width;
  uint16_t height;
  oled.getTextBounds(text, 0, 0, & x1, & y1, & width, & height);
  oled.setCursor((128 - width) / 2, h);
  oled.print(text);
  oled.display();
}

void disp() {
  //oled.clearDisplay();
  oled.fillRect(104, 0, 22, 16, BLACK);
  oled.fillRect(62, 0, 10, 16, BLACK);
  oled.setTextSize(2);
  oled.setTextColor(WHITE);
  oled.setCursor(2, 0);
  oled.print("Char'");
  oled.print(char(curr_key));
  oled.print("' ");
  oled.setCursor(104, 0);
  String hexstr;
  if (curr_key < 16)
    hexstr += 0;
  hexstr += String(curr_key, HEX);
  hexstr.toUpperCase();
  oled.print(hexstr);
  oled.setTextSize(1);
  oled.setCursor(0, 30);
  oled.print(encoder_input);
  oled.display();
}

void disp_stars() {
  //oled.clearDisplay();
  oled.fillRect(104, 0, 22, 16, BLACK);
  oled.fillRect(62, 0, 10, 16, BLACK);
  oled.setTextSize(2);
  oled.setTextColor(WHITE);
  oled.setCursor(2, 0);
  oled.print("Char'");
  oled.print(char(curr_key));
  oled.print("' ");
  oled.setCursor(104, 0);
  String hexstr;
  if (curr_key < 16)
    hexstr += 0;
  hexstr += String(curr_key, HEX);
  hexstr.toUpperCase();
  oled.print(hexstr);
  oled.setTextSize(1);
  oled.setCursor(0, 30);
  int plnt = encoder_input.length();
  String stars = "";
  for (int i = 0; i < plnt; i++) {
    stars += "*";
  }
  oled.print(stars);
  oled.display();
}

void encdr_in() {
  enc0.tick();
  if (enc0.left()) {
    curr_key--;
    disp();
  }
  if (enc0.right()) {
    curr_key++;
    disp();
  }

  if (curr_key < 32)
    curr_key = 126;

  if (curr_key > 126)
    curr_key = 32;

  if (enc0.turn()) {
    //Serial.println(char(curr_key));
    disp();
  }
  a_button.tick();
  if (a_button.press()) {
    encoder_input += char(curr_key);
    //Serial.println(encoder_input);
    disp();
  }
  b_button.tick();
  if (b_button.press()) {
    if (encoder_input.length() > 0) {
      encoder_input.remove(encoder_input.length() - 1, 1);
      oled.fillRect(0, 30, 128, 34, BLACK);
    }
    //Serial.println(encoder_input);
    disp();
  }
}

void star_encdr_in() {
  enc0.tick();
  if (enc0.left()) {
    curr_key--;
    disp_stars();
  }
  if (enc0.right()) {
    curr_key++;
    disp_stars();
  }

  if (curr_key < 32)
    curr_key = 126;

  if (curr_key > 126)
    curr_key = 32;

  if (enc0.turn()) {
    //Serial.println(char(curr_key));
    disp_stars();
  }
  a_button.tick();
  if (a_button.press()) {
    encoder_input += char(curr_key);
    //Serial.println(encoder_input);
    disp_stars();
  }
  b_button.tick();
  if (b_button.press()) {
    if (encoder_input.length() > 0) {
      encoder_input.remove(encoder_input.length() - 1, 1);
      oled.fillRect(0, 30, 128, 34, BLACK);
    }
    //Serial.println(encoder_input);
    disp_stars();
  }
}

void cont_to_inl() {
  bool unl = true;
  EEPROM.begin(EEPROM_SIZE);
  if (EEPROM.read(0) == 255)
    unl = false;
  //Serial.println(EEPROM.read(0));
  EEPROM.end();
  if (unl == true)
    unlock_midbar();
  else
    set_pass();
  return;
}

void set_pass() {
  clear_variables();
  oled.clearDisplay();
  oled.setTextColor(WHITE);
  oled.setCursor(0, 20);
  oled.setTextSize(1);
  oled.print("Set your password");
  curr_key = 65;
  disp();
  bool cont = true;
  while (cont == true) {
    encdr_in();
    delay(1);
    encoder_button.tick();
    if (encoder_button.hasClicks(4))
      cont = false;
    delay(1);
  }
  oled.clearDisplay();
  oled.setTextSize(1);
  disp_centered_text("Setting password", 20);
  disp_centered_text("Please wait", 30);
  disp_centered_text("for a while", 40);
  //Serial.println(encoder_input);
  String bck = encoder_input;
  modify_keys();
  encoder_input = bck;
  set_psswd();
  oled.clearDisplay();
  disp_centered_text("Password set", 16);
  disp_centered_text("Successfully", 26);
  disp_centered_text("Quad-click", 36);
  disp_centered_text("the encoder button", 46);
  disp_centered_text("to continue", 56);
  bool cont1 = true;
  while (cont1 == true) {
    encoder_button.tick();
    if (encoder_button.hasClicks(4))
      cont1 = false;
    delay(1);
  }
  curr_key = 0;
  main_menu(curr_key);
  return;
}

void set_psswd() {
  int str_len = encoder_input.length() + 1;
  char input_arr[str_len];
  encoder_input.toCharArray(input_arr, str_len);
  std::string str = "";
  if (str_len > 1) {
    for (int i = 0; i < str_len - 1; i++) {
      str += input_arr[i];
    }
  }
  String h = sha512(str).c_str();
  for (int i = 0; i < numofkincr * 2; i++) {
    int str_len1 = h.length() + 1;
    char input_arr1[str_len1];
    h.toCharArray(input_arr1, str_len1);
    std::string str1 = "";
    if (str_len1 > 1) {
      for (int i = 0; i < str_len1 - 1; i++) {
        str1 += input_arr1[i];
      }
    }
    h = sha512(str1).c_str();
    delay(1);
  }
  //Serial.println();
  //Serial.println(h);
  back_keys();
  dec_st = "";
  encr_hash_for_tdes_aes_blf_srp(h);
  rest_keys();
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

  EEPROM.begin(EEPROM_SIZE);
  EEPROM.write(0, 0);
  for (int i = 0; i < 48; i++) {
    EEPROM.write(i + 1, res[i]);
  }
  EEPROM.end();
}

void modify_keys() {
  encoder_input += kderalgs;
  int str_len = encoder_input.length() + 1;
  char input_arr[str_len];
  encoder_input.toCharArray(input_arr, str_len);
  std::string str = "";
  if (str_len > 1) {
    for (int i = 0; i < str_len - 1; i++) {
      str += input_arr[i];
    }
  }
  String h = sha512(str).c_str();
  for (int i = 0; i < numofkincr; i++) {
    int str_len1 = h.length() + 1;
    char input_arr1[str_len1];
    h.toCharArray(input_arr1, str_len1);
    std::string str1 = "";
    if (str_len1 > 1) {
      for (int i = 0; i < str_len1 - 1; i++) {
        str1 += input_arr1[i];
      }
    }
    h = sha512(str1).c_str();
    delay(1);
  }
  //Serial.println(h);
  int h_len = h.length() + 1;
  char h_array[h_len];
  h.toCharArray(h_array, h_len);
  byte res[64];
  for (int i = 0; i < 128; i += 2) {
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
  for (int i = 0; i < 13; i++) {
    hmackey[i] = res[i];
  }
  des_key[9] = res[13];
  des_key[16] = (unsigned char) res[31];
  des_key[17] = (unsigned char) res[32];
  des_key[18] = (unsigned char) res[33];
  serp_key[12] = int(res[34]);
  serp_key[14] = int(res[35]);
  for (int i = 0; i < 9; i++) {
    Blwfsh_key[i] = (unsigned char) res[i + 14];
  }
  for (int i = 0; i < 3; i++) {
    des_key[i] = (unsigned char) res[i + 23];
  }
  for (int i = 0; i < 5; i++) {
    hmackey[i + 13] = int(res[i + 26]);
  }
  for (int i = 0; i < 10; i++) {
    AES_key[i] = int(res[i + 36]);
  }
  for (int i = 0; i < 9; i++) {
    serp_key[i] = int(res[i + 46]);
  }
  for (int i = 0; i < 4; i++) {
    hmackey[i + 18] = res[i + 55];
    des_key[i + 3] = (unsigned char) res[i + 59];
  }
  //int vn = ((res[62] + 1) * (res[62] + 3)) % 9987;
}

void unlock_midbar() {
  clear_variables();
  oled.clearDisplay();
  oled.setTextColor(WHITE);
  oled.setCursor(0, 20);
  oled.setTextSize(1);
  oled.print("Enter your password");
  curr_key = 65;
  disp();
  bool cont = true;
  while (cont == true) {
    star_encdr_in();
    delay(1);
    encoder_button.tick();
    if (encoder_button.hasClicks(4))
      cont = false;
    delay(1);
  }
  oled.clearDisplay();
  disp_centered_text("Unlocking Midbar", 20);
  disp_centered_text("Please wait", 30);
  disp_centered_text("for a while", 40);
  //Serial.println(encoder_input);
  String bck = encoder_input;
  modify_keys();
  encoder_input = bck;
  bool next_act = hash_psswd();
  clear_variables();
  if (next_act == true) {
    oled.clearDisplay();
    disp_centered_text("Midbar unlocked", 16);
    disp_centered_text("Successfully", 26);
    disp_centered_text("Quad-click", 36);
    disp_centered_text("the encoder button", 46);
    disp_centered_text("to continue", 56);
    bool cont1 = true;
    while (cont1 == true) {
      encoder_button.tick();
      if (encoder_button.hasClicks(4))
        cont1 = false;
      delay(1);
    }
    curr_key = 0;
    main_menu(curr_key);
    return;
  } else {
    oled.clearDisplay();
    disp_centered_text("Wrong Password!", 17);
    disp_centered_text("Please reboot", 27);
    disp_centered_text("the device", 37);
    disp_centered_text("and try again", 47);
    for (;;)
      delay(1000);
  }
}

bool hash_psswd() {
  int str_len = encoder_input.length() + 1;
  char input_arr[str_len];
  encoder_input.toCharArray(input_arr, str_len);
  std::string str = "";
  if (str_len > 1) {
    for (int i = 0; i < str_len - 1; i++) {
      str += input_arr[i];
    }
  }
  String h = sha512(str).c_str();
  for (int i = 0; i < numofkincr * 2; i++) {
    int str_len1 = h.length() + 1;
    char input_arr1[str_len1];
    h.toCharArray(input_arr1, str_len1);
    std::string str1 = "";
    if (str_len1 > 1) {
      for (int i = 0; i < str_len1 - 1; i++) {
        str1 += input_arr1[i];
      }
    }
    h = sha512(str1).c_str();
    delay(1);
  }
  //Serial.println();
  //Serial.println(h);

  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  int h_len1 = h.length() + 1;
  char h_arr[h_len1];
  h.toCharArray(h_arr, h_len1);
  hmac.doUpdate(h_arr);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  int p = 0;
  char hmacchar[30];
  for (int i = 0; i < 30; i++) {
    hmacchar[i] = char(authCode[i]);
  }

  String res_hash;
  for (int i = 0; i < 30; i++) {
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
  back_keys();
  clear_variables();
  String encr_h;
  EEPROM.begin(EEPROM_SIZE);
  for (int i = 1; i < 49; i++) {
    if (EEPROM.read(i) < 16)
      encr_h += "0";
    encr_h += String(EEPROM.read(i), HEX);
  }
  EEPROM.end();
  decrypt_with_TDES_AES_Blowfish_Serp(encr_h);
  //Serial.println(dec_tag);
  return dec_tag.equals(res_hash);
}

void main_menu(int curr_pos) {
  oled.clearDisplay();
  if (curr_pos == 0) {
    highl_f();
  }
  if (curr_pos == 1) {
    highl_s();

  }
  if (curr_pos == 2) {
    highl_t();
  }
  if (curr_pos == 3) {
    highl_frth();
  }
  return;
}

void highl_f() {
  oled.setTextColor(WHITE);
  oled.setTextSize(1);
  disp_centered_text("->Logins<-", 8);
  disp_centered_text("Credit Cards", 18);
  disp_centered_text("Encryption Algs", 28);
  disp_centered_text("Hash Functions", 38);
}

void highl_s() {
  oled.setTextColor(WHITE);
  oled.setTextSize(1);
  disp_centered_text("Logins", 8);
  disp_centered_text("->Credit Cards<-", 18);
  disp_centered_text("Encryption Algs", 28);
  disp_centered_text("Hash Functions", 38);
}

void highl_t() {
  oled.setTextColor(WHITE);
  oled.setTextSize(1);
  disp_centered_text("Logins", 8);
  disp_centered_text("Credit Cards", 18);
  disp_centered_text("->Encryption Algs<-", 28);
  disp_centered_text("Hash Functions", 38);
}

void highl_frth() {
  oled.setTextColor(WHITE);
  oled.setTextSize(1);
  disp_centered_text("Logins", 8);
  disp_centered_text("Credit Cards", 18);
  disp_centered_text("Encryption Algs", 28);
  disp_centered_text("->Hash Functions<-", 38);
}

void Records_menu(int curr_pos) {
  oled.clearDisplay();
  if (curr_pos == 0) {
    highl_f_r();
  }
  if (curr_pos == 1) {
    highl_s_r();

  }
  if (curr_pos == 2) {
    highl_t_r();
  }
  return;
}

void highl_f_r() {
  oled.setTextColor(WHITE);
  oled.setTextSize(1);
  disp_centered_text("->Add<-", 8);
  disp_centered_text("Delete", 18);
  disp_centered_text("View", 28);
}

void highl_s_r() {
  oled.setTextColor(WHITE);
  oled.setTextSize(1);
  disp_centered_text("Add", 8);
  disp_centered_text("->Delete<-", 18);
  disp_centered_text("View", 28);
}

void highl_t_r() {
  oled.setTextColor(WHITE);
  oled.setTextSize(1);
  disp_centered_text("Add", 8);
  disp_centered_text("Delete", 18);
  disp_centered_text("->View<-", 28);
}

void Enc_algs_menu(int curr_pos) {
  oled.clearDisplay();
  if (curr_pos == 0) {
    highl_f_e();
  }
  if (curr_pos == 1) {
    highl_s_e();

  }
  if (curr_pos == 2) {
    highl_t_e();
  }
  return;
}

void highl_f_e() {
  oled.setTextColor(WHITE);
  oled.setTextSize(1);
  disp_centered_text("->3DES+AES+BLF+Serp<-", 8);
  disp_centered_text("Serpent", 18);
  disp_centered_text("3DES", 28);
}

void highl_s_e() {
  oled.setTextColor(WHITE);
  oled.setTextSize(1);
  disp_centered_text("3DES+AES+BLF+Serp", 8);
  disp_centered_text("->Serpent<-", 18);
  disp_centered_text("3DES", 28);
}

void highl_t_e() {
  oled.setTextColor(WHITE);
  oled.setTextSize(1);
  disp_centered_text("3DES+AES+BLF+Serp", 8);
  disp_centered_text("Serpent", 18);
  disp_centered_text("->3DES<-", 28);
}

void h_funcs_menu(int curr_pos) {
  oled.clearDisplay();
  if (curr_pos == 0) {
    highl_f_h();
  }
  if (curr_pos == 1) {
    highl_s_h();

  }
  return;
}

void highl_f_h() {
  oled.setTextColor(WHITE);
  oled.setTextSize(1);
  disp_centered_text("->SHA-256<-", 8);
  disp_centered_text("SHA-512", 18);
}

void highl_s_h() {
  oled.setTextColor(WHITE);
  oled.setTextSize(1);
  disp_centered_text("SHA-256", 8);
  disp_centered_text("->SHA-512<-", 18);
}

void logins_menu() {
  curr_key = 0;
  Records_menu(curr_key);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 2;

    if (curr_key > 2)
      curr_key = 0;

    if (enc0.turn()) {
      Records_menu(curr_key);
    }
    a_button.tick();
    int ch = 0;
    if (a_button.press() == true)
      ch = 1;

    delay(1);
    b_button.tick();
    if (b_button.press() == true)
      ch = 2;

    if (ch == 1 && curr_key == 0) {
      add_del_view_login(1);
      cont_to_next = true;
    }
    if (ch == 1 && curr_key == 1) {
      add_del_view_login(2);
      cont_to_next = true;
    }
    if (ch == 1 && curr_key == 2) {
      add_del_view_login(3);
      cont_to_next = true;
    }

    if (ch == 2) // Get back
      cont_to_next = true;

    delay(1);
  }
  curr_key = 0;
  main_menu(curr_key);
  return;
}

void add_del_view_login(byte actn) {
  bool cont_to_next = false;
  int sel_rcrd = 1;
  disp_cert_login(actn, sel_rcrd);
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      sel_rcrd--;
    if (enc0.right())
      sel_rcrd++;
    if (sel_rcrd > 8)
      sel_rcrd = 1;
    if (sel_rcrd < 1)
      sel_rcrd = 8;
    if (enc0.turn()) {
      disp_cert_login(actn, sel_rcrd);
    }
    delay(1);
    a_button.tick();
    int curr_key1 = 0;
    if (a_button.press()) {
      if (actn == 1)
        enter_title_for_logins(sel_rcrd);
      if (actn == 2)
        delete_login(sel_rcrd);
      if (actn == 3)
        view_title_from_login(sel_rcrd);
      cont_to_next = true;
    }
    delay(1);
    b_button.tick();
    if (b_button.press())
      cont_to_next = true;
    delay(1);
  }
}

void disp_cert_login(byte actn, int nmbr) {
  oled.clearDisplay();
  oled.setTextColor(WHITE);
  oled.setTextSize(1);
  if (actn == 1)
    disp_centered_text("Add Login", 4);
  if (actn == 2)
    disp_centered_text("Delete Login", 4);
  if (actn == 3)
    disp_centered_text("View Login", 4);

  if (actn == 2 || actn == 3)
    disp_centered_text("Login " + (String) nmbr + "/8", 16);

  if (actn == 1)
    disp_centered_text("Slot " + (String) nmbr + "/8", 16);

  clear_variables();
  String encr_t;
  EEPROM.begin(EEPROM_SIZE);
  for (int i = 0; i < 64; i++) {
    if (EEPROM.read(i + 49 + ((nmbr - 1) * 352)) < 16)
      encr_t += "0";
    encr_t += String(EEPROM.read(i + 49 + ((nmbr - 1) * 352)), HEX);
  }
  EEPROM.end();
  int next_act = 1;
  //Serial.println(encr_t);
  for (int i = 0; i < 128; i++) {
    if (encr_t.charAt(i) == 102)
      next_act *= 1;
    else
      next_act *= 0;
  }
  if (next_act != 1) {
    decrypt_with_TDES_AES_Blowfish_Serp(encr_t);
    byte res[30];
    for (int i = 0; i < 128; i += 2) {
      if (i == 0) {
        if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) != 0)
          res[i] = 16 * getNum(dec_tag.charAt(i)) + getNum(dec_tag.charAt(i + 1));
        if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) == 0)
          res[i] = 16 * getNum(dec_tag.charAt(i));
        if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) != 0)
          res[i] = getNum(dec_tag.charAt(i + 1));
        if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) == 0)
          res[i] = 0;
      } else {
        if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) != 0)
          res[i / 2] = 16 * getNum(dec_tag.charAt(i)) + getNum(dec_tag.charAt(i + 1));
        if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) == 0)
          res[i / 2] = 16 * getNum(dec_tag.charAt(i));
        if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) != 0)
          res[i / 2] = getNum(dec_tag.charAt(i + 1));
        if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) == 0)
          res[i / 2] = 0;
      }
    }
    String t_be_disp;
    for (int i = 0; i < 30; i++) {
      if (res[i] > 0 && res[i] < 127)
        t_be_disp += char(res[i]);
    }

    for (int i = 0; i < dec_st.length(); i++) {
      if (dec_st.charAt(i) > 0 && dec_st.charAt(i) < 127)
        t_be_disp += dec_st.charAt(i);
    }

    disp_centered_text(t_be_disp, 28);
  } else
    disp_centered_text("Empty", 28);
}

void enter_title_for_logins(byte slot_n) {
  clear_variables();
  oled.clearDisplay();
  oled.setTextColor(WHITE);
  oled.setCursor(0, 20);
  oled.setTextSize(1);
  oled.print("Enter title");
  curr_key = 65;
  disp();
  bool cont = true;
  bool act = true;
  while (cont == true) {
    encdr_in();
    delay(1);
    encoder_button.tick();
    if (encoder_button.hasClicks(4))
      cont = false;
    if (encoder_button.hasClicks(5)) {
      cont = false;
      act = false;
    }
    delay(1);
  }

  if (act == true) {
    oled.clearDisplay();
    oled.setTextSize(1);
    //Serial.println(encoder_input);
    randomSeed(ESP8266TrueRandom.random());
    for (int i = 0; i < 40; i++) {
      encoder_input += char(ESP8266TrueRandom.random(128, 256));
    }
    String title;
    for (int i = 0; i < 40; i++) {
      title += encoder_input.charAt(i);
    }
    enter_username_for_logins(title, slot_n);
  }
}

void enter_username_for_logins(String title, byte slot_n) {
  clear_variables();
  oled.clearDisplay();
  oled.setTextColor(WHITE);
  oled.setCursor(0, 20);
  oled.setTextSize(1);
  oled.print("Enter username");
  curr_key = 65;
  disp();
  bool cont = true;
  bool act = true;
  while (cont == true) {
    encdr_in();
    delay(1);
    encoder_button.tick();
    if (encoder_button.hasClicks(4))
      cont = false;
    if (encoder_button.hasClicks(5)) {
      cont = false;
      act = false;
    }
    delay(1);
  }

  if (act == true) {
    oled.clearDisplay();
    oled.setTextSize(1);
    //Serial.println(encoder_input);
    randomSeed(ESP8266TrueRandom.random());
    for (int i = 0; i < 70; i++) {
      encoder_input += char(ESP8266TrueRandom.random(128, 256));
    }
    String username;
    for (int i = 0; i < 70; i++) {
      username += encoder_input.charAt(i);
    }
    enter_password_for_logins(title, username, slot_n);
  }
}

void enter_password_for_logins(String title, String username, byte slot_n) {
  clear_variables();
  oled.clearDisplay();
  oled.setTextColor(WHITE);
  oled.setCursor(0, 20);
  oled.setTextSize(1);
  oled.print("Enter password");
  curr_key = 65;
  disp();
  bool cont = true;
  bool act = true;
  while (cont == true) {
    encdr_in();
    delay(1);
    encoder_button.tick();
    if (encoder_button.hasClicks(4))
      cont = false;
    if (encoder_button.hasClicks(5)) {
      cont = false;
      act = false;
    }
    delay(1);
  }

  if (act == true) {
    oled.clearDisplay();
    oled.setTextSize(1);
    //Serial.println(encoder_input);
    randomSeed(ESP8266TrueRandom.random());
    for (int i = 0; i < 40; i++) {
      encoder_input += char(ESP8266TrueRandom.random(128, 256));
    }
    String password;
    for (int i = 0; i < 40; i++) {
      password += encoder_input.charAt(i);
    }
    enter_website_for_logins(title, username, password, slot_n);
  }
}

void enter_website_for_logins(String title, String username, String password, byte slot_n) {
  clear_variables();
  oled.clearDisplay();
  oled.setTextColor(WHITE);
  oled.setCursor(0, 20);
  oled.setTextSize(1);
  oled.print("Enter website");
  curr_key = 65;
  disp();
  bool cont = true;
  bool act = true;
  while (cont == true) {
    encdr_in();
    delay(1);
    encoder_button.tick();
    if (encoder_button.hasClicks(4))
      cont = false;
    if (encoder_button.hasClicks(5)) {
      cont = false;
      act = false;
    }
    delay(1);
  }

  if (act == true) {
    oled.clearDisplay();
    oled.setTextSize(1);
    //Serial.println(encoder_input);
    randomSeed(ESP8266TrueRandom.random());
    for (int i = 0; i < 40; i++) {
      encoder_input += char(ESP8266TrueRandom.random(128, 256));
    }
    String website;
    for (int i = 0; i < 40; i++) {
      website += encoder_input.charAt(i);
    }
    enncr_and_add_login(title, username, password, website, slot_n);
  }
}

void enncr_and_add_login(String title, String username, String password, String website, byte slot_n) {
  oled.clearDisplay();
  oled.setTextSize(1);
  disp_centered_text("Adding Login", 20);
  disp_centered_text("Please wait", 30);
  disp_centered_text("for a while", 40);
  /*
  Serial.println();
  Serial.println(title);
  Serial.println(username);
  Serial.println(password);
  Serial.println(website);
  Serial.println();
  */
  encrypt_without_hash_TDES_AES_Blowfish_Serp(title);
  //Serial.println(dec_st);

  byte res[112];
  for (int i = 0; i < 128; i += 2) {
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

  EEPROM.begin(EEPROM_SIZE);
  for (int i = 0; i < 64; i++) {
    EEPROM.write(i + 49 + ((slot_n - 1) * 352), res[i]);
  }
  EEPROM.end();
  clear_variables();

  encrypt_without_hash_TDES_AES_Blowfish_Serp(username);
  //Serial.println(dec_st);

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

  EEPROM.begin(EEPROM_SIZE);
  for (int i = 0; i < 112; i++) {
    EEPROM.write(i + 113 + ((slot_n - 1) * 352), res[i]);
  }
  EEPROM.end();
  clear_variables();

  encrypt_without_hash_TDES_AES_Blowfish_Serp(password);
  //Serial.println(dec_st);

  for (int i = 0; i < 128; i += 2) {
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

  EEPROM.begin(EEPROM_SIZE);
  for (int i = 0; i < 64; i++) {
    EEPROM.write(i + 225 + ((slot_n - 1) * 352), res[i]);
  }
  EEPROM.end();

  clear_variables();

  encrypt_without_hash_TDES_AES_Blowfish_Serp(website);
  Serial.println(dec_st);

  for (int i = 0; i < 128; i += 2) {
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

  EEPROM.begin(EEPROM_SIZE);
  for (int i = 0; i < 64; i++) {
    EEPROM.write(i + 289 + ((slot_n - 1) * 352), res[i]);
  }
  EEPROM.end();
  clear_variables();

  back_keys();
  encr_hash_for_tdes_aes_blf_srp(title + username + password + website);
  //Serial.println(title + username + password + website);
  //Serial.println(dec_st);
  rest_keys();

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

  EEPROM.begin(EEPROM_SIZE);
  for (int i = 0; i < 48; i++) {
    EEPROM.write(i + 353 + ((slot_n - 1) * 352), res[i]);
  }
  EEPROM.end();
  clear_variables();
}

void delete_login(byte slot_n) {
  EEPROM.begin(EEPROM_SIZE);
  for (int i = 49; i < 401; i++) {
    EEPROM.write(i + ((slot_n - 1) * 352), 255);
  }
  EEPROM.end();
}

void view_title_from_login(byte nmbr) {
  clear_variables();
  String encr_t;
  EEPROM.begin(EEPROM_SIZE);
  for (int i = 0; i < 64; i++) {
    if (EEPROM.read(i + 49 + ((nmbr - 1) * 352)) < 16)
      encr_t += "0";
    encr_t += String(EEPROM.read(i + 49 + ((nmbr - 1) * 352)), HEX);
  }
  EEPROM.end();
  decrypt_with_TDES_AES_Blowfish_Serp(encr_t);
  byte res[30];
  for (int i = 0; i < 128; i += 2) {
    if (i == 0) {
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) != 0)
        res[i] = 16 * getNum(dec_tag.charAt(i)) + getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) == 0)
        res[i] = 16 * getNum(dec_tag.charAt(i));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) != 0)
        res[i] = getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) == 0)
        res[i] = 0;
    } else {
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) != 0)
        res[i / 2] = 16 * getNum(dec_tag.charAt(i)) + getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) == 0)
        res[i / 2] = 16 * getNum(dec_tag.charAt(i));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) != 0)
        res[i / 2] = getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) == 0)
        res[i / 2] = 0;
    }
  }
  String t_be_disp;
  String title;
  for (int i = 0; i < 30; i++) {
    if (res[i] > 0 && res[i] < 127)
      t_be_disp += char(res[i]);
    title += char(res[i]);
  }

  for (int i = 0; i < dec_st.length(); i++) {
    if (dec_st.charAt(i) > 0 && dec_st.charAt(i) < 127)
      t_be_disp += dec_st.charAt(i);
    title += dec_st.charAt(i);
  }
  oled.clearDisplay();
  disp_centered_text("Title", 4);
  disp_centered_text(t_be_disp, 16);
  //Serial.println(title);
  bool cont_to_next1 = false;
  while (cont_to_next1 == false) {
    encoder_button.tick();
    if (encoder_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
    a_button.tick();
    if (a_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
    b_button.tick();
    if (b_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
  }
  view_username_from_login(title, nmbr);
}

void view_username_from_login(String title, byte nmbr) {
  clear_variables();
  String encr_t;
  EEPROM.begin(EEPROM_SIZE);
  for (int i = 0; i < 112; i++) {
    if (EEPROM.read(i + 113 + ((nmbr - 1) * 352)) < 16)
      encr_t += "0";
    encr_t += String(EEPROM.read(i + 113 + ((nmbr - 1) * 352)), HEX);
  }
  EEPROM.end();
  decrypt_with_TDES_AES_Blowfish_Serp(encr_t);
  byte res[30];
  for (int i = 0; i < 128; i += 2) {
    if (i == 0) {
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) != 0)
        res[i] = 16 * getNum(dec_tag.charAt(i)) + getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) == 0)
        res[i] = 16 * getNum(dec_tag.charAt(i));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) != 0)
        res[i] = getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) == 0)
        res[i] = 0;
    } else {
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) != 0)
        res[i / 2] = 16 * getNum(dec_tag.charAt(i)) + getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) == 0)
        res[i / 2] = 16 * getNum(dec_tag.charAt(i));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) != 0)
        res[i / 2] = getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) == 0)
        res[i / 2] = 0;
    }
  }
  String t_be_disp;
  String username;
  for (int i = 0; i < 30; i++) {
    if (res[i] > 0 && res[i] < 127)
      t_be_disp += char(res[i]);
    username += char(res[i]);
  }

  for (int i = 0; i < dec_st.length(); i++) {
    if (dec_st.charAt(i) > 0 && dec_st.charAt(i) < 127)
      t_be_disp += dec_st.charAt(i);
    username += dec_st.charAt(i);
  }
  oled.clearDisplay();
  disp_centered_text("Username", 4);
  disp_centered_text(t_be_disp, 16);
  //Serial.println(username);
  bool cont_to_next1 = false;
  while (cont_to_next1 == false) {
    encoder_button.tick();
    if (encoder_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
    a_button.tick();
    if (a_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
    b_button.tick();
    if (b_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
  }
  view_password_from_login(title, username, nmbr);
}

void view_password_from_login(String title, String username, byte nmbr) {
  clear_variables();
  String encr_t;
  EEPROM.begin(EEPROM_SIZE);
  for (int i = 0; i < 64; i++) {
    if (EEPROM.read(i + 225 + ((nmbr - 1) * 352)) < 16)
      encr_t += "0";
    encr_t += String(EEPROM.read(i + 225 + ((nmbr - 1) * 352)), HEX);
  }
  EEPROM.end();
  decrypt_with_TDES_AES_Blowfish_Serp(encr_t);
  byte res[30];
  for (int i = 0; i < 128; i += 2) {
    if (i == 0) {
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) != 0)
        res[i] = 16 * getNum(dec_tag.charAt(i)) + getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) == 0)
        res[i] = 16 * getNum(dec_tag.charAt(i));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) != 0)
        res[i] = getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) == 0)
        res[i] = 0;
    } else {
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) != 0)
        res[i / 2] = 16 * getNum(dec_tag.charAt(i)) + getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) == 0)
        res[i / 2] = 16 * getNum(dec_tag.charAt(i));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) != 0)
        res[i / 2] = getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) == 0)
        res[i / 2] = 0;
    }
  }
  String t_be_disp;
  String password;
  for (int i = 0; i < 30; i++) {
    if (res[i] > 0 && res[i] < 127)
      t_be_disp += char(res[i]);
    password += char(res[i]);
  }

  for (int i = 0; i < dec_st.length(); i++) {
    if (dec_st.charAt(i) > 0 && dec_st.charAt(i) < 127)
      t_be_disp += dec_st.charAt(i);
    password += dec_st.charAt(i);
  }
  oled.clearDisplay();
  disp_centered_text("Password", 4);
  disp_centered_text(t_be_disp, 16);
  //Serial.println(password);
  bool cont_to_next1 = false;
  while (cont_to_next1 == false) {
    encoder_button.tick();
    if (encoder_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
    a_button.tick();
    if (a_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
    b_button.tick();
    if (b_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
  }
  view_website_from_login(title, username, password, nmbr);
}

void view_website_from_login(String title, String username, String password, byte nmbr) {
  clear_variables();
  String encr_t;
  EEPROM.begin(EEPROM_SIZE);
  for (int i = 0; i < 64; i++) {
    if (EEPROM.read(i + 289 + ((nmbr - 1) * 352)) < 16)
      encr_t += "0";
    encr_t += String(EEPROM.read(i + 289 + ((nmbr - 1) * 352)), HEX);
  }
  EEPROM.end();
  decrypt_with_TDES_AES_Blowfish_Serp(encr_t);
  byte res[30];
  for (int i = 0; i < 128; i += 2) {
    if (i == 0) {
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) != 0)
        res[i] = 16 * getNum(dec_tag.charAt(i)) + getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) == 0)
        res[i] = 16 * getNum(dec_tag.charAt(i));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) != 0)
        res[i] = getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) == 0)
        res[i] = 0;
    } else {
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) != 0)
        res[i / 2] = 16 * getNum(dec_tag.charAt(i)) + getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) == 0)
        res[i / 2] = 16 * getNum(dec_tag.charAt(i));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) != 0)
        res[i / 2] = getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) == 0)
        res[i / 2] = 0;
    }
  }
  String t_be_disp;
  String website;
  for (int i = 0; i < 30; i++) {
    if (res[i] > 0 && res[i] < 127)
      t_be_disp += char(res[i]);
    website += char(res[i]);
  }

  for (int i = 0; i < dec_st.length(); i++) {
    if (dec_st.charAt(i) > 0 && dec_st.charAt(i) < 127)
      t_be_disp += dec_st.charAt(i);
    website += dec_st.charAt(i);
  }
  oled.clearDisplay();
  disp_centered_text("Website", 4);
  disp_centered_text(t_be_disp, 16);
  //Serial.println(website);
  bool cont_to_next1 = false;
  while (cont_to_next1 == false) {
    encoder_button.tick();
    if (encoder_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
    a_button.tick();
    if (a_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
    b_button.tick();
    if (b_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
  }
  decr_hash_from_login(title, username, password, website, nmbr);
}

void decr_hash_from_login(String title, String username, String password, String website, byte nmbr) {
  clear_variables();
  String encr_t;
  EEPROM.begin(EEPROM_SIZE);
  for (int i = 0; i < 48; i++) {
    if (EEPROM.read(i + 353 + ((nmbr - 1) * 352)) < 16)
      encr_t += "0";
    encr_t += String(EEPROM.read(i + 353 + ((nmbr - 1) * 352)), HEX);
  }
  EEPROM.end();
  decrypt_with_TDES_AES_Blowfish_Serp(encr_t);
  //Serial.println(dec_tag);

  String input = title + username + password + website;
  //Serial.println(title + username + password + website);

  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  hmac.doUpdate(input_arr);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  String calc_hash;
  for (int i = 0; i < 30; i++) {
    if (authCode[i] < 16)
      calc_hash += "0";
    calc_hash += String(authCode[i], HEX);
  }

  //Serial.println(calc_hash);

  if (!dec_tag.equals(calc_hash)) {
    oled.clearDisplay();
    disp_centered_text("Integrity", 16);
    disp_centered_text("Verification", 26);
    disp_centered_text("Failed!!!", 36);
    bool cont_to_next1 = false;
    while (cont_to_next1 == false) {
      encoder_button.tick();
      if (encoder_button.press()) {
        cont_to_next1 = true;
      }
      delay(1);
      a_button.tick();
      if (a_button.press()) {
        cont_to_next1 = true;
      }
      delay(1);
      b_button.tick();
      if (b_button.press()) {
        cont_to_next1 = true;
      }
      delay(1);
    }
  }
  clear_variables();
}

void credit_cards_menu() {
  curr_key = 0;
  Records_menu(curr_key);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 2;

    if (curr_key > 2)
      curr_key = 0;

    if (enc0.turn()) {
      Records_menu(curr_key);
    }
    a_button.tick();
    int ch = 0;
    if (a_button.press() == true)
      ch = 1;

    delay(1);
    b_button.tick();
    if (b_button.press() == true)
      ch = 2;

    if (ch == 1 && curr_key == 0) {
      add_del_view_credit_card(1);
      cont_to_next = true;
    }
    if (ch == 1 && curr_key == 1) {
      add_del_view_credit_card(2);
      cont_to_next = true;
    }
    if (ch == 1 && curr_key == 2) {
      add_del_view_credit_card(3);
      cont_to_next = true;
    }

    if (ch == 2) // Get back
      cont_to_next = true;

    delay(1);
  }
  curr_key = 0;
  main_menu(curr_key);
  return;
}

void add_del_view_credit_card(byte actn) {
  bool cont_to_next = false;
  int sel_rcrd = 1;
  disp_cert_card(actn, sel_rcrd);
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      sel_rcrd--;
    if (enc0.right())
      sel_rcrd++;
    if (sel_rcrd > 4)
      sel_rcrd = 1;
    if (sel_rcrd < 1)
      sel_rcrd = 4;
    if (enc0.turn()) {
      disp_cert_card(actn, sel_rcrd);
    }
    delay(1);
    a_button.tick();
    int curr_key1 = 0;
    if (a_button.press()) {
      if (actn == 1)
        enter_title_for_credit_cards(sel_rcrd);
      if (actn == 2)
        delete_credit_card(sel_rcrd);
      if (actn == 3)
        view_title_from_credit_cards(sel_rcrd);
      cont_to_next = true;
    }
    delay(1);
    b_button.tick();
    if (b_button.press())
      cont_to_next = true;
    delay(1);
  }
}

void disp_cert_card(byte actn, int nmbr) {
  oled.clearDisplay();
  oled.setTextColor(WHITE);
  oled.setTextSize(1);
  if (actn == 1)
    disp_centered_text("Add Credit Card", 4);
  if (actn == 2)
    disp_centered_text("Delete Credit Card", 4);
  if (actn == 3)
    disp_centered_text("View Credit Card", 4);

  if (actn == 2 || actn == 3)
    disp_centered_text("Credit Card " + (String) nmbr + "/4", 16);

  if (actn == 1)
    disp_centered_text("Slot " + (String) nmbr + "/4", 16);

  clear_variables();
  String encr_t;
  EEPROM.begin(EEPROM_SIZE);
  for (int i = 0; i < 64; i++) {
    if (EEPROM.read(i + 2865 + ((nmbr - 1) * 272)) < 16)
      encr_t += "0";
    encr_t += String(EEPROM.read(i + 2865 + ((nmbr - 1) * 272)), HEX);
  }
  EEPROM.end();
  int next_act = 1;
  //Serial.println(encr_t);
  for (int i = 0; i < 128; i++) {
    if (encr_t.charAt(i) == 102)
      next_act *= 1;
    else
      next_act *= 0;
  }
  if (next_act != 1) {
    decrypt_with_TDES_AES_Blowfish_Serp(encr_t);
    byte res[30];
    for (int i = 0; i < 128; i += 2) {
      if (i == 0) {
        if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) != 0)
          res[i] = 16 * getNum(dec_tag.charAt(i)) + getNum(dec_tag.charAt(i + 1));
        if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) == 0)
          res[i] = 16 * getNum(dec_tag.charAt(i));
        if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) != 0)
          res[i] = getNum(dec_tag.charAt(i + 1));
        if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) == 0)
          res[i] = 0;
      } else {
        if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) != 0)
          res[i / 2] = 16 * getNum(dec_tag.charAt(i)) + getNum(dec_tag.charAt(i + 1));
        if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) == 0)
          res[i / 2] = 16 * getNum(dec_tag.charAt(i));
        if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) != 0)
          res[i / 2] = getNum(dec_tag.charAt(i + 1));
        if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) == 0)
          res[i / 2] = 0;
      }
    }
    String t_be_disp;
    for (int i = 0; i < 30; i++) {
      if (res[i] > 0 && res[i] < 127)
        t_be_disp += char(res[i]);
    }

    for (int i = 0; i < dec_st.length(); i++) {
      if (dec_st.charAt(i) > 0 && dec_st.charAt(i) < 127)
        t_be_disp += dec_st.charAt(i);
    }

    disp_centered_text(t_be_disp, 28);
  } else
    disp_centered_text("Empty", 28);
}

void enter_title_for_credit_cards(byte slot_n) {
  clear_variables();
  oled.clearDisplay();
  oled.setTextColor(WHITE);
  oled.setCursor(0, 20);
  oled.setTextSize(1);
  oled.print("Enter title");
  curr_key = 65;
  disp();
  bool cont = true;
  bool act = true;
  while (cont == true) {
    encdr_in();
    delay(1);
    encoder_button.tick();
    if (encoder_button.hasClicks(4))
      cont = false;
    if (encoder_button.hasClicks(5)) {
      cont = false;
      act = false;
    }
    delay(1);
  }

  if (act == true) {
    oled.clearDisplay();
    oled.setTextSize(1);
    //Serial.println(encoder_input);
    randomSeed(ESP8266TrueRandom.random());
    for (int i = 0; i < 40; i++) {
      encoder_input += char(ESP8266TrueRandom.random(128, 256));
    }
    String title;
    for (int i = 0; i < 40; i++) {
      title += encoder_input.charAt(i);
    }
    enter_cardholder_for_credit_cards(title, slot_n);
  }
}

void enter_cardholder_for_credit_cards(String title, byte slot_n) {
  clear_variables();
  oled.clearDisplay();
  oled.setTextColor(WHITE);
  oled.setCursor(0, 20);
  oled.setTextSize(1);
  oled.print("Enter cardholder name");
  curr_key = 65;
  disp();
  bool cont = true;
  bool act = true;
  while (cont == true) {
    encdr_in();
    delay(1);
    encoder_button.tick();
    if (encoder_button.hasClicks(4))
      cont = false;
    if (encoder_button.hasClicks(5)) {
      cont = false;
      act = false;
    }
    delay(1);
  }

  if (act == true) {
    oled.clearDisplay();
    oled.setTextSize(1);
    //Serial.println(encoder_input);
    randomSeed(ESP8266TrueRandom.random());
    for (int i = 0; i < 70; i++) {
      encoder_input += char(ESP8266TrueRandom.random(128, 256));
    }
    String cardholder;
    for (int i = 0; i < 70; i++) {
      cardholder += encoder_input.charAt(i);
    }
    enter_card_number_for_credit_cards(title, cardholder, slot_n);
  }
}

void enter_card_number_for_credit_cards(String title, String cardholder, byte slot_n) {
  clear_variables();
  oled.clearDisplay();
  oled.setTextColor(WHITE);
  oled.setCursor(0, 20);
  oled.setTextSize(1);
  oled.print("Enter card number");
  curr_key = 52;
  disp();
  bool cont = true;
  bool act = true;
  while (cont == true) {
    encdr_in();
    delay(1);
    encoder_button.tick();
    if (encoder_button.hasClicks(4))
      cont = false;
    if (encoder_button.hasClicks(5)) {
      cont = false;
      act = false;
    }
    delay(1);
  }

  if (act == true) {
    oled.clearDisplay();
    oled.setTextSize(1);
    //Serial.println(encoder_input);
    randomSeed(ESP8266TrueRandom.random());
    for (int i = 0; i < 20; i++) {
      encoder_input += char(ESP8266TrueRandom.random(128, 256));
    }
    String card_number;
    for (int i = 0; i < 20; i++) {
      card_number += encoder_input.charAt(i);
    }
    enter_exp_date_for_credit_cards(title, cardholder, card_number, slot_n);
  }
}

void enter_exp_date_for_credit_cards(String title, String cardholder, String card_number, byte slot_n) {
  clear_variables();
  oled.clearDisplay();
  oled.setTextColor(WHITE);
  oled.setCursor(0, 20);
  oled.setTextSize(1);
  oled.print("Enter expiration date");
  curr_key = 48;
  disp();
  bool cont = true;
  bool act = true;
  while (cont == true) {
    encdr_in();
    delay(1);
    encoder_button.tick();
    if (encoder_button.hasClicks(4))
      cont = false;
    if (encoder_button.hasClicks(5)) {
      cont = false;
      act = false;
    }
    delay(1);
  }

  if (act == true) {
    oled.clearDisplay();
    oled.setTextSize(1);
    //Serial.println(encoder_input);
    randomSeed(ESP8266TrueRandom.random());
    for (int i = 0; i < 10; i++) {
      encoder_input += char(ESP8266TrueRandom.random(128, 256));
    }
    String exp_date;
    for (int i = 0; i < 10; i++) {
      exp_date += encoder_input.charAt(i);
    }
    enter_cvn_for_credit_cards(title, cardholder, card_number, exp_date, slot_n);
  }
}

void enter_cvn_for_credit_cards(String title, String cardholder, String card_number, String exp_date, byte slot_n) {
  clear_variables();
  oled.clearDisplay();
  oled.setTextColor(WHITE);
  oled.setCursor(0, 20);
  oled.setTextSize(1);
  oled.print("Enter CVN");
  curr_key = 48;
  disp();
  bool cont = true;
  bool act = true;
  while (cont == true) {
    encdr_in();
    delay(1);
    encoder_button.tick();
    if (encoder_button.hasClicks(4))
      cont = false;
    if (encoder_button.hasClicks(5)) {
      cont = false;
      act = false;
    }
    delay(1);
  }

  if (act == true) {
    oled.clearDisplay();
    oled.setTextSize(1);
    //Serial.println(encoder_input);
    randomSeed(ESP8266TrueRandom.random());
    for (int i = 0; i < 10; i++) {
      encoder_input += char(ESP8266TrueRandom.random(128, 256));
    }
    String cvn;
    for (int i = 0; i < 10; i++) {
      cvn += encoder_input.charAt(i);
    }
    enter_pin_for_credit_cards(title, cardholder, card_number, exp_date, cvn, slot_n);
  }
}

void enter_pin_for_credit_cards(String title, String cardholder, String card_number, String exp_date, String cvn, byte slot_n) {
  clear_variables();
  oled.clearDisplay();
  oled.setTextColor(WHITE);
  oled.setCursor(0, 20);
  oled.setTextSize(1);
  oled.print("Enter PIN");
  curr_key = 48;
  disp();
  bool cont = true;
  bool act = true;
  while (cont == true) {
    encdr_in();
    delay(1);
    encoder_button.tick();
    if (encoder_button.hasClicks(4))
      cont = false;
    if (encoder_button.hasClicks(5)) {
      cont = false;
      act = false;
    }
    delay(1);
  }

  if (act == true) {
    oled.clearDisplay();
    oled.setTextSize(1);
    //Serial.println(encoder_input);
    randomSeed(ESP8266TrueRandom.random());
    for (int i = 0; i < 10; i++) {
      encoder_input += char(ESP8266TrueRandom.random(128, 256));
    }
    String pin;
    for (int i = 0; i < 10; i++) {
      pin += encoder_input.charAt(i);
    }
    enter_ZIP_code_for_credit_cards(title, cardholder, card_number, exp_date, cvn, pin, slot_n);
  }
}

void enter_ZIP_code_for_credit_cards(String title, String cardholder, String card_number, String exp_date, String cvn, String pin, byte slot_n) {
  clear_variables();
  oled.clearDisplay();
  oled.setTextColor(WHITE);
  oled.setCursor(0, 20);
  oled.setTextSize(1);
  oled.print("Enter ZIP code");
  curr_key = 48;
  disp();
  bool cont = true;
  bool act = true;
  while (cont == true) {
    encdr_in();
    delay(1);
    encoder_button.tick();
    if (encoder_button.hasClicks(4))
      cont = false;
    if (encoder_button.hasClicks(5)) {
      cont = false;
      act = false;
    }
    delay(1);
  }

  if (act == true) {
    oled.clearDisplay();
    oled.setTextSize(1);
    //Serial.println(encoder_input);
    randomSeed(ESP8266TrueRandom.random());
    for (int i = 0; i < 10; i++) {
      encoder_input += char(ESP8266TrueRandom.random(128, 256));
    }
    String zip_code;
    for (int i = 0; i < 10; i++) {
      zip_code += encoder_input.charAt(i);
    }
    enncr_and_add_credit_card(title, cardholder, card_number, exp_date, cvn, pin, zip_code, slot_n);
  }
}

void enncr_and_add_credit_card(String title, String cardholder, String card_number, String exp_date, String cvn, String pin, String zip_code, byte slot_n) {
  oled.clearDisplay();
  oled.setTextSize(1);
  disp_centered_text("Adding Credit Card", 20);
  disp_centered_text("Please wait", 30);
  disp_centered_text("for a while", 40);

  encrypt_without_hash_TDES_AES_Blowfish_Serp(title);
  //Serial.println(dec_st);

  byte res[112];
  for (int i = 0; i < 128; i += 2) {
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

  EEPROM.begin(EEPROM_SIZE);
  for (int i = 0; i < 64; i++) {
    EEPROM.write(i + 2865 + ((slot_n - 1) * 272), res[i]);
  }
  EEPROM.end();
  clear_variables();

  encrypt_without_hash_TDES_AES_Blowfish_Serp(cardholder);
  //Serial.println(dec_st);

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

  EEPROM.begin(EEPROM_SIZE);
  for (int i = 0; i < 112; i++) {
    EEPROM.write(i + 2929 + ((slot_n - 1) * 272), res[i]);
  }
  EEPROM.end();
  clear_variables();

  encrypt_without_hash_TDES_AES_Blowfish_Serp(card_number);
  //Serial.println(dec_st);

  for (int i = 0; i < 64; i += 2) {
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

  EEPROM.begin(EEPROM_SIZE);
  for (int i = 0; i < 64; i++) {
    EEPROM.write(i + 3041 + ((slot_n - 1) * 272), res[i]);
  }
  EEPROM.end();
  clear_variables();

  encrypt_without_hash_TDES_AES_Blowfish_Serp(exp_date);
  //Serial.println(dec_st);

  for (int i = 0; i < 32; i += 2) {
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

  EEPROM.begin(EEPROM_SIZE);
  for (int i = 0; i < 64; i++) {
    EEPROM.write(i + 3073 + ((slot_n - 1) * 272), res[i]);
  }
  EEPROM.end();
  clear_variables();

  encrypt_without_hash_TDES_AES_Blowfish_Serp(cvn);
  //Serial.println(dec_st);

  for (int i = 0; i < 32; i += 2) {
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

  EEPROM.begin(EEPROM_SIZE);
  for (int i = 0; i < 64; i++) {
    EEPROM.write(i + 3089 + ((slot_n - 1) * 272), res[i]);
  }
  EEPROM.end();
  clear_variables();

  encrypt_without_hash_TDES_AES_Blowfish_Serp(pin);
  //Serial.println(dec_st);

  for (int i = 0; i < 32; i += 2) {
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

  EEPROM.begin(EEPROM_SIZE);
  for (int i = 0; i < 64; i++) {
    EEPROM.write(i + 3105 + ((slot_n - 1) * 272), res[i]);
  }
  EEPROM.end();
  clear_variables();

  encrypt_without_hash_TDES_AES_Blowfish_Serp(zip_code);
  //Serial.println(dec_st);

  for (int i = 0; i < 32; i += 2) {
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

  EEPROM.begin(EEPROM_SIZE);
  for (int i = 0; i < 64; i++) {
    EEPROM.write(i + 3121 + ((slot_n - 1) * 272), res[i]);
  }
  EEPROM.end();
  clear_variables();
}

void delete_credit_card(byte slot_n) {
  EEPROM.begin(EEPROM_SIZE);
  for (int i = 2865; i < 2833; i++) {
    EEPROM.write(i + ((slot_n - 1) * 272), 255);
  }
  EEPROM.end();
}

void view_title_from_credit_cards(byte nmbr) {
  clear_variables();
  String encr_t;
  EEPROM.begin(EEPROM_SIZE);
  for (int i = 0; i < 64; i++) {
    if (EEPROM.read(i + 2865 + ((nmbr - 1) * 272)) < 16)
      encr_t += "0";
    encr_t += String(EEPROM.read(i + 2865 + ((nmbr - 1) * 272)), HEX);
  }
  EEPROM.end();
  decrypt_with_TDES_AES_Blowfish_Serp(encr_t);
  byte res[30];
  for (int i = 0; i < 128; i += 2) {
    if (i == 0) {
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) != 0)
        res[i] = 16 * getNum(dec_tag.charAt(i)) + getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) == 0)
        res[i] = 16 * getNum(dec_tag.charAt(i));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) != 0)
        res[i] = getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) == 0)
        res[i] = 0;
    } else {
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) != 0)
        res[i / 2] = 16 * getNum(dec_tag.charAt(i)) + getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) == 0)
        res[i / 2] = 16 * getNum(dec_tag.charAt(i));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) != 0)
        res[i / 2] = getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) == 0)
        res[i / 2] = 0;
    }
  }
  String t_be_disp;
  String title;
  for (int i = 0; i < 30; i++) {
    if (res[i] > 0 && res[i] < 127)
      t_be_disp += char(res[i]);
    title += char(res[i]);
  }

  for (int i = 0; i < dec_st.length(); i++) {
    if (dec_st.charAt(i) > 0 && dec_st.charAt(i) < 127)
      t_be_disp += dec_st.charAt(i);
    title += dec_st.charAt(i);
  }
  oled.clearDisplay();
  disp_centered_text("Title", 4);
  disp_centered_text(t_be_disp, 16);
  //Serial.println(title);
  bool cont_to_next1 = false;
  while (cont_to_next1 == false) {
    encoder_button.tick();
    if (encoder_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
    a_button.tick();
    if (a_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
    b_button.tick();
    if (b_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
  }
  view_cardholder_from_credit_cards(nmbr);
}

void view_cardholder_from_credit_cards(byte nmbr) {
  clear_variables();
  String encr_t;
  EEPROM.begin(EEPROM_SIZE);
  for (int i = 0; i < 112; i++) {
    if (EEPROM.read(i + 2929 + ((nmbr - 1) * 272)) < 16)
      encr_t += "0";
    encr_t += String(EEPROM.read(i + 2929 + ((nmbr - 1) * 272)), HEX);
  }
  EEPROM.end();
  decrypt_with_TDES_AES_Blowfish_Serp(encr_t);
  byte res[30];
  for (int i = 0; i < 128; i += 2) {
    if (i == 0) {
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) != 0)
        res[i] = 16 * getNum(dec_tag.charAt(i)) + getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) == 0)
        res[i] = 16 * getNum(dec_tag.charAt(i));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) != 0)
        res[i] = getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) == 0)
        res[i] = 0;
    } else {
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) != 0)
        res[i / 2] = 16 * getNum(dec_tag.charAt(i)) + getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) == 0)
        res[i / 2] = 16 * getNum(dec_tag.charAt(i));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) != 0)
        res[i / 2] = getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) == 0)
        res[i / 2] = 0;
    }
  }
  String t_be_disp;
  String cardholder;
  for (int i = 0; i < 30; i++) {
    if (res[i] > 0 && res[i] < 127)
      t_be_disp += char(res[i]);
    cardholder += char(res[i]);
  }

  for (int i = 0; i < dec_st.length(); i++) {
    if (dec_st.charAt(i) > 0 && dec_st.charAt(i) < 127)
      t_be_disp += dec_st.charAt(i);
    cardholder += dec_st.charAt(i);
  }
  oled.clearDisplay();
  disp_centered_text("Cardholder Name", 4);
  disp_centered_text(t_be_disp, 16);
  //Serial.println(cardholder);
  bool cont_to_next1 = false;
  while (cont_to_next1 == false) {
    encoder_button.tick();
    if (encoder_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
    a_button.tick();
    if (a_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
    b_button.tick();
    if (b_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
  }
  view_card_number_from_credit_cards(nmbr);
}

void view_card_number_from_credit_cards(byte nmbr) {
  clear_variables();
  String encr_t;
  EEPROM.begin(EEPROM_SIZE);
  for (int i = 0; i < 32; i++) {
    if (EEPROM.read(i + 3041 + ((nmbr - 1) * 272)) < 16)
      encr_t += "0";
    encr_t += String(EEPROM.read(i + 3041 + ((nmbr - 1) * 272)), HEX);
  }
  EEPROM.end();
  decrypt_with_TDES_AES_Blowfish_Serp(encr_t);
  byte res[20];
  for (int i = 0; i < 64; i += 2) {
    if (i == 0) {
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) != 0)
        res[i] = 16 * getNum(dec_tag.charAt(i)) + getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) == 0)
        res[i] = 16 * getNum(dec_tag.charAt(i));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) != 0)
        res[i] = getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) == 0)
        res[i] = 0;
    } else {
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) != 0)
        res[i / 2] = 16 * getNum(dec_tag.charAt(i)) + getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) == 0)
        res[i / 2] = 16 * getNum(dec_tag.charAt(i));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) != 0)
        res[i / 2] = getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) == 0)
        res[i / 2] = 0;
    }
  }
  String t_be_disp;
  String card_number;
  for (int i = 0; i < 20; i++) {
    if (res[i] > 0 && res[i] < 127)
      t_be_disp += char(res[i]);
    card_number += char(res[i]);
  }
  oled.clearDisplay();
  disp_centered_text("Card Number", 4);
  disp_centered_text(t_be_disp, 16);
  //Serial.println(card_number);
  bool cont_to_next1 = false;
  while (cont_to_next1 == false) {
    encoder_button.tick();
    if (encoder_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
    a_button.tick();
    if (a_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
    b_button.tick();
    if (b_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
  }
  view_exp_date_from_credit_cards(nmbr);
}

void view_exp_date_from_credit_cards(byte nmbr) {
  clear_variables();
  String encr_t;
  EEPROM.begin(EEPROM_SIZE);
  for (int i = 0; i < 16; i++) {
    if (EEPROM.read(i + 3073 + ((nmbr - 1) * 272)) < 16)
      encr_t += "0";
    encr_t += String(EEPROM.read(i + 3073 + ((nmbr - 1) * 272)), HEX);
  }
  EEPROM.end();
  decrypt_with_TDES_AES_Blowfish_Serp(encr_t);
  byte res[10];
  for (int i = 0; i < 32; i += 2) {
    if (i == 0) {
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) != 0)
        res[i] = 16 * getNum(dec_tag.charAt(i)) + getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) == 0)
        res[i] = 16 * getNum(dec_tag.charAt(i));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) != 0)
        res[i] = getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) == 0)
        res[i] = 0;
    } else {
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) != 0)
        res[i / 2] = 16 * getNum(dec_tag.charAt(i)) + getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) == 0)
        res[i / 2] = 16 * getNum(dec_tag.charAt(i));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) != 0)
        res[i / 2] = getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) == 0)
        res[i / 2] = 0;
    }
  }
  String t_be_disp;
  String exp_date;
  for (int i = 0; i < 10; i++) {
    if (res[i] > 0 && res[i] < 127)
      t_be_disp += char(res[i]);
    exp_date += char(res[i]);
  }

  oled.clearDisplay();
  disp_centered_text("Expiration Date", 4);
  disp_centered_text(t_be_disp, 16);
  //Serial.println(card_number);
  bool cont_to_next1 = false;
  while (cont_to_next1 == false) {
    encoder_button.tick();
    if (encoder_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
    a_button.tick();
    if (a_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
    b_button.tick();
    if (b_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
  }
  view_cvn_from_credit_cards(nmbr);
}

void view_cvn_from_credit_cards(byte nmbr) {
  clear_variables();
  String encr_t;
  EEPROM.begin(EEPROM_SIZE);
  for (int i = 0; i < 16; i++) {
    if (EEPROM.read(i + 3089 + ((nmbr - 1) * 272)) < 16)
      encr_t += "0";
    encr_t += String(EEPROM.read(i + 3089 + ((nmbr - 1) * 272)), HEX);
  }
  EEPROM.end();
  decrypt_with_TDES_AES_Blowfish_Serp(encr_t);
  byte res[10];
  for (int i = 0; i < 32; i += 2) {
    if (i == 0) {
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) != 0)
        res[i] = 16 * getNum(dec_tag.charAt(i)) + getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) == 0)
        res[i] = 16 * getNum(dec_tag.charAt(i));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) != 0)
        res[i] = getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) == 0)
        res[i] = 0;
    } else {
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) != 0)
        res[i / 2] = 16 * getNum(dec_tag.charAt(i)) + getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) == 0)
        res[i / 2] = 16 * getNum(dec_tag.charAt(i));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) != 0)
        res[i / 2] = getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) == 0)
        res[i / 2] = 0;
    }
  }
  String t_be_disp;
  String cvn;
  for (int i = 0; i < 10; i++) {
    if (res[i] > 0 && res[i] < 127)
      t_be_disp += char(res[i]);
    cvn += char(res[i]);
  }

  oled.clearDisplay();
  disp_centered_text("CVN", 4);
  disp_centered_text(t_be_disp, 16);
  //Serial.println(card_number);
  bool cont_to_next1 = false;
  while (cont_to_next1 == false) {
    encoder_button.tick();
    if (encoder_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
    a_button.tick();
    if (a_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
    b_button.tick();
    if (b_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
  }
  view_pin_from_credit_cards(nmbr);
}

void view_pin_from_credit_cards(byte nmbr) {
  clear_variables();
  String encr_t;
  EEPROM.begin(EEPROM_SIZE);
  for (int i = 0; i < 16; i++) {
    if (EEPROM.read(i + 3105 + ((nmbr - 1) * 272)) < 16)
      encr_t += "0";
    encr_t += String(EEPROM.read(i + 3105 + ((nmbr - 1) * 272)), HEX);
  }
  EEPROM.end();
  decrypt_with_TDES_AES_Blowfish_Serp(encr_t);
  byte res[10];
  for (int i = 0; i < 32; i += 2) {
    if (i == 0) {
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) != 0)
        res[i] = 16 * getNum(dec_tag.charAt(i)) + getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) == 0)
        res[i] = 16 * getNum(dec_tag.charAt(i));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) != 0)
        res[i] = getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) == 0)
        res[i] = 0;
    } else {
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) != 0)
        res[i / 2] = 16 * getNum(dec_tag.charAt(i)) + getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) == 0)
        res[i / 2] = 16 * getNum(dec_tag.charAt(i));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) != 0)
        res[i / 2] = getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) == 0)
        res[i / 2] = 0;
    }
  }
  String t_be_disp;
  String pin;
  for (int i = 0; i < 10; i++) {
    if (res[i] > 0 && res[i] < 127)
      t_be_disp += char(res[i]);
    pin += char(res[i]);
  }

  oled.clearDisplay();
  disp_centered_text("PIN", 4);
  disp_centered_text(t_be_disp, 16);
  //Serial.println(card_number);
  bool cont_to_next1 = false;
  while (cont_to_next1 == false) {
    encoder_button.tick();
    if (encoder_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
    a_button.tick();
    if (a_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
    b_button.tick();
    if (b_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
  }
  view_ZIP_code_from_credit_cards(nmbr);
}

void view_ZIP_code_from_credit_cards(byte nmbr) {
  clear_variables();
  String encr_t;
  EEPROM.begin(EEPROM_SIZE);
  for (int i = 0; i < 16; i++) {
    if (EEPROM.read(i + 3121 + ((nmbr - 1) * 272)) < 16)
      encr_t += "0";
    encr_t += String(EEPROM.read(i + 3121 + ((nmbr - 1) * 272)), HEX);
  }
  EEPROM.end();
  decrypt_with_TDES_AES_Blowfish_Serp(encr_t);
  byte res[10];
  for (int i = 0; i < 32; i += 2) {
    if (i == 0) {
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) != 0)
        res[i] = 16 * getNum(dec_tag.charAt(i)) + getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) == 0)
        res[i] = 16 * getNum(dec_tag.charAt(i));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) != 0)
        res[i] = getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) == 0)
        res[i] = 0;
    } else {
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) != 0)
        res[i / 2] = 16 * getNum(dec_tag.charAt(i)) + getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) != 0 && dec_tag.charAt(i + 1) == 0)
        res[i / 2] = 16 * getNum(dec_tag.charAt(i));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) != 0)
        res[i / 2] = getNum(dec_tag.charAt(i + 1));
      if (dec_tag.charAt(i) == 0 && dec_tag.charAt(i + 1) == 0)
        res[i / 2] = 0;
    }
  }
  String t_be_disp;
  String zip;
  for (int i = 0; i < 10; i++) {
    if (res[i] > 0 && res[i] < 127)
      t_be_disp += char(res[i]);
    zip += char(res[i]);
  }

  oled.clearDisplay();
  disp_centered_text("ZIP Code", 4);
  disp_centered_text(t_be_disp, 16);
  //Serial.println(card_number);
  bool cont_to_next1 = false;
  while (cont_to_next1 == false) {
    encoder_button.tick();
    if (encoder_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
    a_button.tick();
    if (a_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
    b_button.tick();
    if (b_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
  }
}

void encr_algorithms_menu() {
  curr_key = 0;
  Enc_algs_menu(curr_key);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 2;

    if (curr_key > 2)
      curr_key = 0;

    if (enc0.turn()) {
      Enc_algs_menu(curr_key);
    }
    a_button.tick();
    int ch = 0;
    if (a_button.press() == true)
      ch = 1;

    delay(1);
    b_button.tick();
    if (b_button.press() == true)
      ch = 2;

    if (ch == 1 && curr_key == 0) {
      TDES_AES_BLF_Serp_menu();
      cont_to_next = true;
    }
    if (ch == 1 && curr_key == 1) {
      Serpent_menu();
      cont_to_next = true;
    }
    if (ch == 1 && curr_key == 2) {
      TDES_menu();
      cont_to_next = true;
    }

    if (ch == 2) // Get back
      cont_to_next = true;

    delay(1);
  }
  curr_key = 0;
  main_menu(curr_key);
  return;
}

void TDES_AES_BLF_Serp_menu() {
  curr_key = 0;
  encrypt_something_menu(curr_key);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 2;

    if (curr_key > 2)
      curr_key = 0;

    if (enc0.turn()) {
      encrypt_something_menu(curr_key);
    }
    a_button.tick();
    int ch = 0;
    if (a_button.press() == true)
      ch = 1;

    delay(1);
    b_button.tick();
    if (b_button.press() == true)
      ch = 2;

    if (ch == 1 && curr_key == 0) {
      encr_TDES_AES_BLF_Serp();
      cont_to_next = true;
    }
    if (ch == 1 && curr_key == 1) {
      encr_TDES_AES_BLF_Serp_from_Serial();
      cont_to_next = true;
    }
    if (ch == 1 && curr_key == 2) {
      decr_blwfsh_aes_serpent_aes();
      cont_to_next = true;
    }

    if (ch == 2) // Get back
      cont_to_next = true;

    delay(1);
  }
  curr_key = 0;
  main_menu(curr_key);
  return;
}

void disp_chpr_inscr() {
  oled.clearDisplay();
  oled.setTextColor(WHITE);
  oled.setTextSize(1);
  disp_centered_text("Paste the plaintext", 20);
  disp_centered_text("to the Serial Monitor", 30);
  disp_centered_text("Press any button", 45);
  disp_centered_text("to cancel", 55);
}

void disp_plt_inscr() {
  oled.clearDisplay();
  oled.setTextColor(WHITE);
  oled.setTextSize(1);
  disp_centered_text("Paste the ciphertext", 20);
  disp_centered_text("to the Serial Monitor", 30);
  disp_centered_text("Press any button", 45);
  disp_centered_text("to cancel", 55);
}

void disp_plt_on_oled() {
  oled.clearDisplay();
  oled.setTextColor(WHITE);
  oled.setTextSize(1);
  disp_centered_text("Plaintext", 6);
  disp_centered_text(dec_st, 16);
}

void disp_int_v_fld() {
  oled.clearDisplay();
  oled.setTextColor(WHITE);
  oled.setTextSize(1);
  disp_centered_text("Integrity", 16);
  disp_centered_text("Verification", 26);
  disp_centered_text("Failed!!!", 36);
}

void encr_TDES_AES_BLF_Serp() {
  clear_variables();
  oled.clearDisplay();
  oled.setTextColor(WHITE);
  oled.setCursor(0, 20);
  oled.setTextSize(1);
  oled.print("Enter text to encrypt");
  curr_key = 65;
  disp();

  bool cont = true;
  bool act = true;
  while (cont == true) {
    encdr_in();
    delay(1);
    encoder_button.tick();
    if (encoder_button.hasClicks(4))
      cont = false;
    if (encoder_button.hasClicks(5)) {
      cont = false;
      act = false;
    }
    delay(1);
  }

  if (act == true) {
    encrypt_with_TDES_AES_Blowfish_Serp(encoder_input);
    Serial.println("\nCiphertext");
    Serial.println(dec_st);
  }
  clear_variables();
  curr_key = 0;
  main_menu(curr_key);
  return;
}

void encr_TDES_AES_BLF_Serp_from_Serial() {
  disp_chpr_inscr();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    Serial.println("\nPaste the plaintext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true) {
        break;
      }
    }
    if (canc_op == false) {
      String plt = Serial.readString();
      encrypt_with_TDES_AES_Blowfish_Serp(plt);
      Serial.println("\nCiphertext");
      Serial.println(dec_st);
    }
    clear_variables();
    return;
  }
}

void decr_blwfsh_aes_serpent_aes() {
  disp_plt_inscr();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    Serial.println("\nPaste the ciphertext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true) {
        break;
      }
    }
    if (canc_op == true)
      break;
    String ct = Serial.readString();
    decrypt_with_TDES_AES_Blowfish_Serp(ct);
    //Serial.println("Plaintext:");
    //Serial.println(dec_st);
    bool plt_integr = verify_integrity();
    disp_plt_on_oled();
    clear_variables();
    bool cont_to_next = false;
    while (cont_to_next == false) {
      encoder_button.tick();
      if (encoder_button.press()) {
        cont_to_next = true;
      }
      delay(1);
      a_button.tick();
      if (a_button.press()) {
        cont_to_next = true;
      }
      delay(1);
      b_button.tick();
      if (b_button.press()) {
        cont_to_next = true;
      }
      delay(1);
    }
    if (plt_integr == false) {
      disp_int_v_fld();
      bool cont_to_next1 = false;
      while (cont_to_next1 == false) {
        encoder_button.tick();
        if (encoder_button.press()) {
          cont_to_next1 = true;
        }
        delay(1);
        a_button.tick();
        if (a_button.press()) {
          cont_to_next1 = true;
        }
        delay(1);
        b_button.tick();
        if (b_button.press()) {
          cont_to_next1 = true;
        }
        delay(1);
      }
    }
    clear_variables();
    return;
  }
}

void Serpent_menu() {
  curr_key = 0;
  encrypt_something_menu(curr_key);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 2;

    if (curr_key > 2)
      curr_key = 0;

    if (enc0.turn()) {
      encrypt_something_menu(curr_key);
    }
    a_button.tick();
    int ch = 0;
    if (a_button.press() == true)
      ch = 1;

    delay(1);
    b_button.tick();
    if (b_button.press() == true)
      ch = 2;

    if (ch == 1 && curr_key == 0) {
      encr_serpent_only_with_hmac();
      cont_to_next = true;
    }
    if (ch == 1 && curr_key == 1) {
      encr_serpent_only_with_hmac_from_Serial();
      cont_to_next = true;
    }
    if (ch == 1 && curr_key == 2) {
      decr_serpent_only_with_hmac();
      cont_to_next = true;
    }

    if (ch == 2) // Get back
      cont_to_next = true;

    delay(1);
  }
  curr_key = 0;
  main_menu(curr_key);
  return;
}

void encr_serpent_only_with_hmac() {
  clear_variables();
  oled.clearDisplay();
  oled.setTextColor(WHITE);
  oled.setCursor(0, 20);
  oled.setTextSize(1);
  oled.print("Enter text to encrypt");
  curr_key = 65;
  disp();

  bool cont = true;
  bool act = true;
  while (cont == true) {
    encdr_in();
    delay(1);
    encoder_button.tick();
    if (encoder_button.hasClicks(4))
      cont = false;
    if (encoder_button.hasClicks(5)) {
      cont = false;
      act = false;
    }
    delay(1);
  }

  if (act == true) {
    Serial.println("\nCiphertext");
    encrypt_with_seprent_only(encoder_input);
    Serial.println();
  }
  clear_variables();
  curr_key = 0;
  main_menu(curr_key);
  return;
}

void encr_serpent_only_with_hmac_from_Serial() {
  disp_chpr_inscr();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    Serial.println("\nPaste the plaintext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true) {
        break;
      }
    }
    if (canc_op == false) {
      String plt = Serial.readString();
      Serial.println("\nCiphertext");
      encrypt_with_seprent_only(plt);
      Serial.println();
    }
    clear_variables();
    return;
  }
}

void decr_serpent_only_with_hmac() {
  disp_plt_inscr();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    Serial.println("\nPaste the ciphertext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true) {
        break;
      }
    }
    if (canc_op == true)
      break;
    String ct = Serial.readString();
    decrypt_with_serpent_only(ct);
    //Serial.println("Plaintext:");
    //Serial.println(dec_st);
    bool plt_integr = verify_integrity_thirty_two();
    disp_plt_on_oled();
    clear_variables();
    bool cont_to_next = false;
    while (cont_to_next == false) {
      encoder_button.tick();
      if (encoder_button.press()) {
        cont_to_next = true;
      }
      delay(1);
      a_button.tick();
      if (a_button.press()) {
        cont_to_next = true;
      }
      delay(1);
      b_button.tick();
      if (b_button.press()) {
        cont_to_next = true;
      }
      delay(1);
    }
    if (plt_integr == false) {
      disp_int_v_fld();
      bool cont_to_next1 = false;
      while (cont_to_next1 == false) {
        encoder_button.tick();
        if (encoder_button.press()) {
          cont_to_next1 = true;
        }
        delay(1);
        a_button.tick();
        if (a_button.press()) {
          cont_to_next1 = true;
        }
        delay(1);
        b_button.tick();
        if (b_button.press()) {
          cont_to_next1 = true;
        }
        delay(1);
      }
    }
    clear_variables();
    return;
  }
}

void TDES_menu() {
  curr_key = 0;
  encrypt_something_menu(curr_key);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 2;

    if (curr_key > 2)
      curr_key = 0;

    if (enc0.turn()) {
      encrypt_something_menu(curr_key);
    }
    a_button.tick();
    int ch = 0;
    if (a_button.press() == true)
      ch = 1;

    delay(1);
    b_button.tick();
    if (b_button.press() == true)
      ch = 2;

    if (ch == 1 && curr_key == 0) {
      encr_tdes_only_with_hmac();
      cont_to_next = true;
    }
    if (ch == 1 && curr_key == 1) {
      encr_tdes_only_with_hmac_from_Serial();
      cont_to_next = true;
    }
    if (ch == 1 && curr_key == 2) {
      decr_tdes_only_with_hmac();
      cont_to_next = true;
    }

    if (ch == 2) // Get back
      cont_to_next = true;

    delay(1);
  }
  curr_key = 0;
  main_menu(curr_key);
  return;
}

void encr_tdes_only_with_hmac() {
  clear_variables();
  oled.clearDisplay();
  oled.setTextColor(WHITE);
  oled.setCursor(0, 20);
  oled.setTextSize(1);
  oled.print("Enter text to encrypt");
  curr_key = 65;
  disp();

  bool cont = true;
  bool act = true;
  while (cont == true) {
    encdr_in();
    delay(1);
    encoder_button.tick();
    if (encoder_button.hasClicks(4))
      cont = false;
    if (encoder_button.hasClicks(5)) {
      cont = false;
      act = false;
    }
    delay(1);
  }

  if (act == true) {
    Serial.println("\nCiphertext");
    encrypt_with_tdes_only(encoder_input);
    Serial.println();
  }
  clear_variables();
  curr_key = 0;
  main_menu(curr_key);
  return;
}

void encr_tdes_only_with_hmac_from_Serial() {
  disp_chpr_inscr();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    Serial.println("\nPaste the plaintext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true) {
        break;
      }
    }
    if (canc_op == false) {
      String plt = Serial.readString();
      Serial.println("\nCiphertext");
      encrypt_with_tdes_only(plt);
      Serial.println();
    }
    clear_variables();
    return;
  }
}

void decr_tdes_only_with_hmac() {
  disp_plt_inscr();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    Serial.println("\nPaste the ciphertext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true) {
        break;
      }
    }
    if (canc_op == true)
      break;
    String ct = Serial.readString();
    decrypt_with_tdes_only(ct);
    //Serial.println("Plaintext:");
    //Serial.println(dec_st);
    disp_plt_on_oled();
    clear_variables();
    bool cont_to_next = false;
    while (cont_to_next == false) {
      encoder_button.tick();
      if (encoder_button.press()) {
        cont_to_next = true;
      }
      delay(1);
      a_button.tick();
      if (a_button.press()) {
        cont_to_next = true;
      }
      delay(1);
      b_button.tick();
      if (b_button.press()) {
        cont_to_next = true;
      }
      delay(1);
    }
    clear_variables();
    return;
  }
}

void encrypt_something_menu(int curr_pos) {
  oled.clearDisplay();
  if (curr_pos == 0) {
    option_encr();
  }
  if (curr_pos == 1) {
    option_encr_from_Serial();

  }
  if (curr_pos == 2) {
    option_decr();
  }
  return;
}

void option_encr() {
  oled.setTextColor(WHITE);
  oled.setTextSize(1);
  disp_centered_text("->Encrypt<-", 8);
  disp_centered_text("Encr from Serial", 18);
  disp_centered_text("Decrypt", 28);
}

void option_encr_from_Serial() {
  oled.setTextColor(WHITE);
  oled.setTextSize(1);
  disp_centered_text("Encrypt", 8);
  disp_centered_text("->Encr from Serial<-", 18);
  disp_centered_text("Decrypt", 28);
}

void option_decr() {
  oled.setTextColor(WHITE);
  oled.setTextSize(1);
  disp_centered_text("Encrypt", 8);
  disp_centered_text("Encr from Serial", 18);
  disp_centered_text("->Decrypt<-", 28);
}

void hash_functions_menu() {
  curr_key = 0;
  h_funcs_menu(curr_key);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 1;

    if (curr_key > 1)
      curr_key = 0;

    if (enc0.turn()) {
      h_funcs_menu(curr_key);
    }
    a_button.tick();
    int ch = 0;
    if (a_button.press() == true)
      ch = 1;

    delay(1);
    b_button.tick();
    if (b_button.press() == true)
      ch = 2;

    if (ch == 1 && curr_key == 0) {
      hash_string_with_sha(false);
      cont_to_next = true;
    }
    if (ch == 1 && curr_key == 1) {
      hash_string_with_sha(true);
      cont_to_next = true;
    }

    if (ch == 2) // Get back
      cont_to_next = true;

    delay(1);
  }
  curr_key = 0;
  main_menu(curr_key);
  return;
}

void hash_string_with_sha(bool vrsn) {
  clear_variables();
  oled.clearDisplay();
  oled.setTextColor(WHITE);
  oled.setCursor(0, 20);
  oled.setTextSize(1);
  oled.print("Enter string to hash");
  curr_key = 65;
  disp();

  bool cont = true;
  bool act = true;
  while (cont == true) {
    encdr_in();
    delay(1);
    encoder_button.tick();
    if (encoder_button.hasClicks(4))
      cont = false;
    if (encoder_button.hasClicks(5)) {
      cont = false;
      act = false;
    }
    delay(1);
  }

  if (act == true) {
    if (vrsn == false)
      hash_with_sha256();
    else
      hash_with_sha512();
  }
  clear_variables();
  curr_key = 0;
  main_menu(curr_key);
  return;
}

void hash_with_sha256() {
  int str_len = encoder_input.length() + 1;
  char keyb_inp_arr[str_len];
  encoder_input.toCharArray(keyb_inp_arr, str_len);
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
  oled.clearDisplay();
  oled.setTextColor(WHITE);
  oled.setTextSize(1);
  disp_centered_text("Resulted hash", 6);
  disp_centered_text(res_hash, 16);
  bool cont_to_next1 = false;
  while (cont_to_next1 == false) {
    encoder_button.tick();
    if (encoder_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
    a_button.tick();
    if (a_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
    b_button.tick();
    if (b_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
  }
}

void hash_with_sha512() {
  int str_len = encoder_input.length() + 1;
  char keyb_inp_arr[str_len];
  encoder_input.toCharArray(keyb_inp_arr, str_len);
  std::string str = "";
  if (str_len > 1) {
    for (int i = 0; i < str_len - 1; i++) {
      str += keyb_inp_arr[i];
    }
  }
  String h = sha512(str).c_str();
  oled.clearDisplay();
  oled.setTextColor(WHITE);
  oled.setTextSize(1);
  disp_centered_text("Resulted hash", 0);
  disp_centered_text(h, 8);
  bool cont_to_next1 = false;
  while (cont_to_next1 == false) {
    encoder_button.tick();
    if (encoder_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
    a_button.tick();
    if (a_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
    b_button.tick();
    if (b_button.press()) {
      cont_to_next1 = true;
    }
    delay(1);
  }
}

void setup() {
  /*
  EEPROM.begin(EEPROM_SIZE);
  EEPROM.write(0, 255);
  EEPROM.end();
  */
  m = 2;
  Serial.begin(115200);
  oled.begin(SSD1306_SWITCHCAPVCC, 0x3C);
  display_midbar_icon();
  oled.setTextColor(WHITE);
  oled.setTextSize(2);
  disp_centered_text("Midbar", 20);
  oled.setTextSize(1);
  disp_centered_text("Quad-click", 40);
  disp_centered_text("the encoder button", 48);
  disp_centered_text("to continue", 56);
  while (!encoder_button.hasClicks(4)) {
    encoder_button.tick();
    delay(1);
  }
  cont_to_inl();
}

void loop() {
  back_keys();
  delayMicroseconds(400);
  enc0.tick();
  if (enc0.left())
    curr_key--;
  if (enc0.right())
    curr_key++;

  if (curr_key < 0)
    curr_key = 3;

  if (curr_key > 3)
    curr_key = 0;

  if (enc0.turn()) {
    main_menu(curr_key);
  }

  delayMicroseconds(400);

  a_button.tick();
  bool ch = false;
  if (a_button.press() == true)
    ch = true;

  if (ch == true && curr_key == 0)
    logins_menu();

  if (ch == true && curr_key == 1)
    credit_cards_menu();

  if (ch == true && curr_key == 2)
    encr_algorithms_menu();

  if (ch == true && curr_key == 3)
    hash_functions_menu();
}
