/*
Midbar
Distributed under the MIT License
© Copyright Maxim Bortnikov 2023
For more information please visit
https://sourceforge.net/projects/midbar/
https://github.com/Northstrix/Midbar
Required libraries:
https://github.com/zhouyangchao/AES
https://github.com/peterferrie/serpent
https://github.com/ddokkaebi/Blowfish
https://github.com/Northstrix/DES_and_3DES_Library_for_MCUs
https://github.com/ulwanski/sha512
https://github.com/Bodmer/TFT_eSPI
https://github.com/intrbiz/arduino-crypto
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/techpaul/PS2KeyMap
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/adafruit/Adafruit-ST7735-Library
https://github.com/Chris--A/Keypad
*/
// !!! Before uploading this sketch -
// Switch the partition scheme to the
// "Huge APP (3MB No OTA/1MB SPIFFS)" !!!
#include <SPI.h>
#include <FS.h>
#include "SPIFFS.h"
#include "DES.h"
#include "aes.h"
#include "blowfish.h"
#include "serpent.h"
#include "Crypto.h"
#include "sha512.h"
#include <TFT_eSPI.h> // Hardware-specific library
#include "midbaricon.h"
#include <PS2KeyAdvanced.h>
#include <PS2KeyMap.h>
#include <Wire.h>
#include <esp_now.h>
#include <WiFi.h>

#define DATAPIN 16
#define IRQPIN 5
#define TYPE_DELAY 72

TFT_eSPI tft = TFT_eSPI();       // Invoke custom library
TFT_eSprite mvng_bc = TFT_eSprite(&tft);

#define MAX_NUM_OF_RECS 500
#define DELAY_FOR_SLOTS 24

DES des;
Blowfish blowfish;
PS2KeyAdvanced keyboard;
PS2KeyMap keymap;
RNG random_number;

int m;
int clb_m;
String dec_st;
String dec_tag;
byte tmp_st[8];
int pass_to_serp[16];
int decract;
byte array_for_CBC_mode[10];
String input_from_the_ps2_keyboard;
int chosen_lock_screen;
int read_keyboard_delay = 60;
int curr_key;
int curr_pos;
int prsd_key;
uint16_t code;
int k;
bool finish_input;
bool act;
bool decrypt_tag;
bool rec_d;
byte data_from_keyboard;
byte sdown = 90;
uint16_t colors[5] = { // Purple, Yellow, Green, Shade of Blue N1, Shade of Blue N2
  0xb81c, 0xfde0, 0x87a0, 0x041c, 0x051b
};
const uint16_t current_inact_clr = colors[1];
const uint16_t five_six_five_red_color = 0xf940;
String succs_ver_inscr = "Integrity Verified Successfully!";
String faild_ver_inscr = "Integrity Verification Failed!";
bool display_moving_background = true;
bool display_pattern_while_adding_and_printing_record = true;

uint8_t broadcastAddress[] = {0x94, 0xE6, 0x86, 0x37, 0xFF, 0xD8}; // Receiver's MAC address

// Keys (Below)

byte read_cards[16] = {
0xb6,0x32,0x3c,0xc3,0xcb,0x22,0x3c,0x6b,
0x0c,0x02,0xb2,0x90,0xd9,0x19,0xcf,0xe9
};
String kderalgs = "G87a7AfFR72zW6OsH4uqg0Zmq";
int numofkincr = 439;
byte hmackey[] = {"79NE5zg28sTbb24r0uMNi2TTOC6hXX11mWHB7M4i9f02393a7T95835kIAlGgx0Ly9fcQVW2GvbrSNysAcJKp1Q1VC7BqAEAHyrfVqK0vdTgBYjU5Fkf950NwLTX0IrN"};
byte des_key[] = {
0x69,0xba,0x5f,0xe5,0x2b,0x40,0xcd,0x6d,
0x8a,0xd9,0xa7,0x93,0x66,0xbc,0xc6,0x47,
0xfe,0x08,0xae,0xd3,0xea,0x2e,0xe3,0xef
};
uint8_t AES_key[32] = {
0xcf,0xca,0x65,0x0b,
0x1d,0x5c,0x1f,0xa4,
0xbb,0xae,0x99,0xdb,
0xdf,0xc1,0x64,0x8c,
0x49,0x9d,0xc0,0x3c,
0xa6,0xb0,0xe8,0xad,
0xe9,0xf5,0xb6,0x9f,
0x4b,0xbd,0x90,0xdb
};
unsigned char Blwfsh_key[] = {
0x53,0xba,0xf0,0xdb,
0xfe,0x09,0xef,0x10,
0x87,0xdf,0x36,0x2c,
0x3d,0xdb,0x1c,0x9a,
0x17,0x45,0xa0,0x3f,
0xdc,0x31,0x74,0xfa
};
uint8_t serp_key[32] = {
0x85,0x97,0xe9,0x12,
0xdd,0xcc,0x65,0xd8,
0x72,0x5f,0x04,0xce,
0x04,0x4c,0x6a,0x85,
0x4a,0x9a,0x41,0xbc,
0x31,0x24,0x6b,0xae,
0xae,0xcc,0xdd,0x6a,
0x6f,0x9c,0x13,0x21
};
uint8_t second_AES_key[32] = {
0x96,0xe7,0xc6,0x6d,
0x48,0xe2,0xce,0x6a,
0xfa,0xec,0x3f,0xc1,
0xea,0xaa,0x71,0xeb,
0x22,0x89,0xa4,0x58,
0x7b,0x90,0xee,0x5a,
0x47,0xbe,0xbf,0x36,
0xef,0xa2,0xfb,0xb6
};
byte hmackey_for_session_key[] = {"R0ON6M2yc442UAWF1H0Ghp1LrLkYe5hvbzL8V985ka77h6qGBrjNV4F1dYipFL33u5d8g1241bqMvZFayFhTY34lZfMjg1588fGFYpR53UU6h4s9fzbV1p"};
uint8_t projection_key[32] = {
0x90,0xa8,0x45,0x8b,
0xb0,0x9e,0x17,0xba,
0xb6,0xcb,0x0c,0x60,
0xe7,0x17,0x0e,0xa6,
0xfb,0x9f,0x89,0xc0,
0xac,0x8a,0x62,0x77,
0xcd,0x5c,0x6f,0x7b,
0xb7,0x32,0xe8,0x5e
};
uint8_t proj_serp_key[32] = {
0xeb,0x44,0x8d,0xed,
0x32,0x25,0xd0,0xda,
0xa1,0x54,0xf4,0x46,
0xcb,0xec,0xe5,0x1a,
0xef,0x2c,0xfa,0xd2,
0x1c,0xb9,0x11,0x2c,
0x7f,0x83,0xe9,0xe3,
0x02,0x75,0x58,0x3f
};

// Keys (Above)

esp_now_peer_info_t peerInfo;

void OnDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
  Serial.print("\r\nLast Packet Send Status:\t");
  Serial.println(status == ESP_NOW_SEND_SUCCESS ? "Delivery Success" : "Delivery Fail");
}

byte back_des_key[24];
uint8_t back_serp_key[32];
unsigned char back_Blwfsh_key[16];
uint8_t back_AES_key[32];
uint8_t back_s_AES_key[32];

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

void back_second_AES_key() {
  for (int i = 0; i < 32; i++) {
    back_s_AES_key[i] = second_AES_key[i];
  }
}

void rest_second_AES_key() {
  for (int i = 0; i < 32; i++) {
    second_AES_key[i] = back_s_AES_key[i];
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

void incr_second_AES_key() {
  if (second_AES_key[0] == 255) {
    second_AES_key[0] = 0;
    if (second_AES_key[1] == 255) {
      second_AES_key[1] = 0;
      if (second_AES_key[2] == 255) {
        second_AES_key[2] = 0;
        if (second_AES_key[3] == 255) {
          second_AES_key[3] = 0;
          if (second_AES_key[4] == 255) {
            second_AES_key[4] = 0;
            if (second_AES_key[5] == 255) {
              second_AES_key[5] = 0;
              if (second_AES_key[6] == 255) {
                second_AES_key[6] = 0;
                if (second_AES_key[7] == 255) {
                  second_AES_key[7] = 0;
                  if (second_AES_key[8] == 255) {
                    second_AES_key[8] = 0;
                    if (second_AES_key[9] == 255) {
                      second_AES_key[9] = 0;
                      if (second_AES_key[10] == 255) {
                        second_AES_key[10] = 0;
                        if (second_AES_key[11] == 255) {
                          second_AES_key[11] = 0;
                          if (second_AES_key[12] == 255) {
                            second_AES_key[12] = 0;
                            if (second_AES_key[13] == 255) {
                              second_AES_key[13] = 0;
                              if (second_AES_key[14] == 255) {
                                second_AES_key[14] = 0;
                                if (second_AES_key[15] == 255) {
                                  second_AES_key[15] = 0;
                                } else {
                                  second_AES_key[15]++;
                                }
                              } else {
                                second_AES_key[14]++;
                              }
                            } else {
                              second_AES_key[13]++;
                            }
                          } else {
                            second_AES_key[12]++;
                          }
                        } else {
                          second_AES_key[11]++;
                        }
                      } else {
                        second_AES_key[10]++;
                      }
                    } else {
                      second_AES_key[9]++;
                    }
                  } else {
                    second_AES_key[8]++;
                  }
                } else {
                  second_AES_key[7]++;
                }
              } else {
                second_AES_key[6]++;
              }
            } else {
              second_AES_key[5]++;
            }
          } else {
            second_AES_key[4]++;
          }
        } else {
          second_AES_key[3]++;
        }
      } else {
        second_AES_key[2]++;
      }
    } else {
      second_AES_key[1]++;
    }
  } else {
    second_AES_key[0]++;
  }
}

int generate_random_number() {
  return random_number.get();
}

void type_on_virtual_keyboard(String data_to_type){
  int lng = data_to_type.length();
  for (int i = 0; i < lng; i++){
    Wire.beginTransmission(4);
    Wire.write(byte(data_to_type.charAt(i)));
    Wire.endTransmission();
    delay(TYPE_DELAY);
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
  back_second_AES_key();
}

void rest_keys() {
  rest_3des_k();
  rest_AES_k();
  rest_Bl_k();
  rest_serp_k();
  rest_second_AES_key();
}

void clear_variables() {
  input_from_the_ps2_keyboard = "";
  dec_st = "";
  dec_tag = "";
  decract = 0;
  return;
}

// 3DES + AES + Blowfish + Serpent in CBC Mode(Below)

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

  for (int i = 0; i < 8; i++) {
    res[i] ^= array_for_CBC_mode[i];
  }

  for (int i = 0; i < 2; i++) {
    res2[i] ^= array_for_CBC_mode[i + 8];
  }

  encrypt_with_tdes(res, res2);
}

void encrypt_iv_for_tdes_aes_blwfsh_serp() {
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

  for (int i = 0; i < 10; i++) {
    array_for_CBC_mode[i] = generate_random_number();
  }

  for (int i = 0; i < 8; i++) {
    res[i] = array_for_CBC_mode[i];
  }

  for (int i = 0; i < 2; i++) {
    res2[i] = array_for_CBC_mode[i + 8];
  }

  encrypt_with_tdes(res, res2);
}

void encrypt_with_tdes(byte res[], byte res2[]) {

  for (int i = 2; i < 8; i++) {
    res2[i] = generate_random_number();
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
  set_aes_key( & ctx, AES_key, AES_key_bit[m]);
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
      if (decract > 0) {
        if (i < 10) {
          array_for_CBC_mode[i] = byte(int(ct2.b[i]));
        }
      }
      if (ct2.b[i] < 16)
        dec_st += "0";
      dec_st += String(ct2.b[i], HEX);
    }
    decract++;
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
  byte prev_res[] = {
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

  for (int i = 0; i < 32; i += 2) {
    if (i + p - 32 > ct_len - 1) {
      br = true;
      break;
    }
    if (i == 0) {
      if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] != 0)
        prev_res[i] = 16 * getNum(ct[i + p - 32]) + getNum(ct[i + p - 32 + 1]);
      if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] == 0)
        prev_res[i] = 16 * getNum(ct[i + p - 32]);
      if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] != 0)
        prev_res[i] = getNum(ct[i + p - 32 + 1]);
      if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] == 0)
        prev_res[i] = 0;
    } else {
      if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] != 0)
        prev_res[i / 2] = 16 * getNum(ct[i + p - 32]) + getNum(ct[i + p - 32 + 1]);
      if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] == 0)
        prev_res[i / 2] = 16 * getNum(ct[i + p - 32]);
      if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] != 0)
        prev_res[i / 2] = getNum(ct[i + p - 32 + 1]);
      if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] == 0)
        prev_res[i / 2] = 0;
    }
  }

  if (br == false) {
    if (decract > 10) {
      for (int i = 0; i < 10; i++) {
        array_for_CBC_mode[i] = prev_res[i];
      }
    }
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
    set_aes_key( & ctx, AES_key, AES_key_bit[m]);
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
      for (int i = 0; i < 8; i++) {
        out[i] ^= array_for_CBC_mode[i];
      }

      for (int i = 0; i < 2; i++) {
        out2[i] ^= array_for_CBC_mode[i + 8];
      }

      if (decrypt_tag == false) {

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
    }

    if (decract == -1) {
      for (i = 0; i < 8; ++i) {
        array_for_CBC_mode[i] = out[i];
      }

      for (i = 0; i < 2; ++i) {
        array_for_CBC_mode[i + 8] = out2[i];;
      }
    }
    decract++;
  }
}

void encr_hash_for_tdes_aes_blf_srp(String input) {
  back_keys();
  clear_variables();
  encrypt_iv_for_tdes_aes_blwfsh_serp();
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
  rest_keys();
}

void encrypt_with_TDES_AES_Blowfish_Serp(String input) {
  back_keys();
  clear_variables();
  encrypt_iv_for_tdes_aes_blwfsh_serp();
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
  decrypt_tag = false;
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  decract = -1;
  while (ct_len > ext) {
    split_for_decryption(ct_array, ct_len, 0 + ext);
    ext += 32;
    decract += 10;
  }
  rest_keys();
}

void decrypt_tag_with_TDES_AES_Blowfish_Serp(String ct) {
  back_keys();
  clear_variables();
  decrypt_tag = true;
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  decract = -1;
  while (ct_len > ext) {
    split_for_decryption(ct_array, ct_len, 0 + ext);
    ext += 32;
    decract += 10;
  }
  rest_keys();
}

void encrypt_string_with_tdes_aes_blf_srp(String input) {
  encrypt_with_TDES_AES_Blowfish_Serp(input);
  String td_aes_bl_srp_ciphertext = dec_st;
  encr_hash_for_tdes_aes_blf_srp(input);
  dec_st += td_aes_bl_srp_ciphertext;
}

void decrypt_string_with_TDES_AES_Blowfish_Serp(String ct) {
  back_keys();
  clear_variables();
  decrypt_tag = true;
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  decract = -1;
  for (int i = 0; i < 128; i += 32) {
    split_for_decryption(ct_array, ct_len, 0 + ext);
    ext += 32;
    decract += 10;
  }
  rest_keys();

  back_keys();
  dec_st = "";
  decrypt_tag = false;
  int ct_len1 = ct.length() + 1;
  char ct_array1[ct_len1];
  ct.toCharArray(ct_array1, ct_len1);
  ext = 128;
  decract = -1;
  while (ct_len1 > ext) {
    split_for_decryption(ct_array1, ct_len1, 0 + ext);
    ext += 32;
    decract += 10;
  }
  rest_keys();
}

// 3DES + AES + Blowfish + Serpent in CBC Mode (Above)

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
  Serial.println(dec_st);
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

void press_any_key_to_continue() {
  rec_d = false;
  delay(2);
  while (rec_d == false) {
    delay(4);
    get_key_from_ps_keyb();
  }
  delay(12);
  data_from_keyboard = 0;
}

void get_key_from_ps_keyb(){
   code = keyboard.available();
   if (code > 0) {
     code = keyboard.read();
     //Serial.print("Value ");
     //Serial.print(code, HEX);
     if (code == 277) { // Leftwards Arrow
       data_from_keyboard = 129;
       rec_d = true;
     }
     if (code == 278) { // Rightwards Arrow
       data_from_keyboard = 130;
       rec_d = true;
     }
     if (code == 279) { // Upwards Arrow
       data_from_keyboard = 131;
       rec_d = true;
     }
     if (code == 280) { // Downwards Arrow
       data_from_keyboard = 132;
       rec_d = true;
     }
     code = keymap.remapKey(code);
     if (code > 0) {
       if ((code & 0xFF)) {
         if ((code & 0xFF) == 27) { // Esc
           data_from_keyboard = 27;
           rec_d = true;
         } else if ((code & 0xFF) == 13) { // Enter
            data_from_keyboard = 13;
            rec_d = true;
         } else if ((code & 0xFF) == 8) { // Backspace
           data_from_keyboard = 8;
           rec_d = true;
         } else {
           data_from_keyboard = code & 0xFF;
           rec_d = true;
         }
       }
   }
  }
}

byte get_PS2_keyboard_input() {
  byte data_from_cntrl_and_keyb;
  while (rec_d == false) {
    delay(4);
    get_key_from_ps_keyb();
  }
  if (rec_d == true) {
    data_from_cntrl_and_keyb = data_from_keyboard;
    rec_d = false;
  }
  return data_from_cntrl_and_keyb;
}

byte get_PS2_keyboard_input_mvn_bcg() {
  byte data_from_cntrl_and_keyb;
  while (rec_d == false) {
    mvn_bcg();
    delayMicroseconds(400);
    get_key_from_ps_keyb();
  }
  if (rec_d == true) {
    data_from_cntrl_and_keyb = data_from_keyboard;
    rec_d = false;
  }
  return data_from_cntrl_and_keyb;
}

void set_stuff_for_input(String blue_inscr) {
  act = true;
  curr_key = 65;
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  tft.setCursor(2, 0);
  tft.print("Char'");
  tft.setCursor(74, 0);
  tft.print("'");
  disp();
  tft.setCursor(0, 24);
  tft.setTextSize(2);
  tft.setTextColor(current_inact_clr);
  tft.print(blue_inscr);
  tft.fillRect(312, 0, 8, 240, current_inact_clr);
  tft.setTextColor(0x07e0);
  tft.setCursor(216, 0);
  tft.print("ASCII:");

}

void check_bounds_and_change_char() {
  if (curr_key < 32)
    curr_key = 126;

  if (curr_key > 126)
    curr_key = 32;
  curr_key = input_from_the_ps2_keyboard.charAt(input_from_the_ps2_keyboard.length() - 1);
}

void disp() {
  //gfx->fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  tft.fillRect(62, 0, 10, 16, 0x0000);
  tft.setCursor(62, 0);
  tft.print(char(curr_key));
  tft.fillRect(288, 0, 22, 14, 0x0000);
  tft.setCursor(288, 0);
  String hexstr;
  if (curr_key < 16)
    hexstr += 0;
  hexstr += String(curr_key, HEX);
  hexstr.toUpperCase();
  tft.setTextColor(0x07e0);
  tft.print(hexstr);
  tft.setTextColor(0xffff);
  tft.setTextSize(2);
  tft.setCursor(0, 48);
  tft.print(input_from_the_ps2_keyboard);
}

void disp_stars() {
  //gfx->fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  tft.fillRect(62, 0, 10, 16, 0x0000);
  tft.setCursor(62, 0);
  tft.print(char(curr_key));
  tft.fillRect(288, 0, 22, 14, 0x0000);
  tft.setCursor(288, 0);
  String hexstr;
  if (curr_key < 16)
    hexstr += 0;
  hexstr += String(curr_key, HEX);
  hexstr.toUpperCase();
  tft.setTextColor(0x07e0);
  tft.print(hexstr);
  int plnt = input_from_the_ps2_keyboard.length();
  String stars = "";
  for (int i = 0; i < plnt; i++) {
    stars += "*";
  }
  tft.setTextColor(0xffff);
  tft.setTextSize(2);
  tft.setCursor(0, 48);
  tft.print(stars);
}

void get_to_ps2_keyboard_input_tab() {
  finish_input = false;
  rec_d = false;
  byte inp_frm_cntr_ps2_kbrd = 0;
  while (finish_input == false) {
    inp_frm_cntr_ps2_kbrd = get_PS2_keyboard_input();
    if (inp_frm_cntr_ps2_kbrd > 0) {
      if (inp_frm_cntr_ps2_kbrd > 31 && inp_frm_cntr_ps2_kbrd < 127) {
        curr_key = inp_frm_cntr_ps2_kbrd;
        input_from_the_ps2_keyboard += char(curr_key);
        //Serial.println(input_from_the_ps2_keyboard);
        disp();
      }

      if (inp_frm_cntr_ps2_kbrd == 27) {
        act = false;
        finish_input = true;
      }

      if (inp_frm_cntr_ps2_kbrd == 13) {
        finish_input = true;
      }

      if (inp_frm_cntr_ps2_kbrd == 130) {
        curr_key++;
        disp();
        if (curr_key < 32)
          curr_key = 126;

        if (curr_key > 126)
          curr_key = 32;
      }

      if (inp_frm_cntr_ps2_kbrd == 129) {
        curr_key--;
        disp();
        if (curr_key < 32)
          curr_key = 126;

        if (curr_key > 126)
          curr_key = 32;
      }

      if (inp_frm_cntr_ps2_kbrd == 131 || inp_frm_cntr_ps2_kbrd == 133) {
        input_from_the_ps2_keyboard += char(curr_key);
        //Serial.println(input_from_the_ps2_keyboard);
        disp();
      }

      if (inp_frm_cntr_ps2_kbrd == 132 || inp_frm_cntr_ps2_kbrd == 8) {
        if (input_from_the_ps2_keyboard.length() > 0)
          input_from_the_ps2_keyboard.remove(input_from_the_ps2_keyboard.length() - 1, 1);
        //Serial.println(input_from_the_ps2_keyboard);
        tft.fillRect(0, 48, 312, 192, 0x0000);
        //Serial.println(input_from_the_ps2_keyboard);
        disp();

      }
      //Serial.println(inp_frm_cntr_ps2_kbrd);
      inp_frm_cntr_ps2_kbrd = 0;
    }
    delayMicroseconds(400);
  }
}

void get_to_starred_ps2_keyboard_input_tab() {
  finish_input = false;
  rec_d = false;
  byte inp_frm_cntr_ps2_kbrd = 0;
  while (finish_input == false) {
    inp_frm_cntr_ps2_kbrd = get_PS2_keyboard_input();
    if (inp_frm_cntr_ps2_kbrd > 0) {
      if (inp_frm_cntr_ps2_kbrd > 31 && inp_frm_cntr_ps2_kbrd < 127) {
        curr_key = inp_frm_cntr_ps2_kbrd;
        input_from_the_ps2_keyboard += char(curr_key);
        //Serial.println(input_from_the_ps2_keyboard);
        disp_stars();
      }

      if (inp_frm_cntr_ps2_kbrd == 27) {
        act = false;
        finish_input = true;
      }

      if (inp_frm_cntr_ps2_kbrd == 13) {
        finish_input = true;
      }

      if (inp_frm_cntr_ps2_kbrd == 130) {
        curr_key++;
        disp_stars();
        if (curr_key < 32)
          curr_key = 126;

        if (curr_key > 126)
          curr_key = 32;
      }

      if (inp_frm_cntr_ps2_kbrd == 129) {
        curr_key--;
        disp_stars();
        if (curr_key < 32)
          curr_key = 126;

        if (curr_key > 126)
          curr_key = 32;
      }

      if (inp_frm_cntr_ps2_kbrd == 131 || inp_frm_cntr_ps2_kbrd == 133) {
        input_from_the_ps2_keyboard += char(curr_key);
        //Serial.println(input_from_the_ps2_keyboard);
        disp_stars();
      }

      if (inp_frm_cntr_ps2_kbrd == 132 || inp_frm_cntr_ps2_kbrd == 8) {
        if (input_from_the_ps2_keyboard.length() > 0)
          input_from_the_ps2_keyboard.remove(input_from_the_ps2_keyboard.length() - 1, 1);
        //Serial.println(input_from_the_ps2_keyboard);
        tft.fillRect(0, 48, 312, 192, 0x0000);
        //Serial.println(input_from_the_ps2_keyboard);
        disp_stars();

      }
      //Serial.println(inp_frm_cntr_ps2_kbrd);
      inp_frm_cntr_ps2_kbrd = 0;
    }
    delayMicroseconds(400);
  }
}

void disp_centered_text(String text, int h) {
  if (text.length() < 27)
    tft.drawCentreString(text, 160, h, 1);
  else{
    tft.setCursor(0, h);
    tft.println(text);
  }
}

void disp_centered_text_b_w(String text, int h) {
  tft.setTextColor(0x0882);
  tft.drawCentreString(text, 160, h - 1, 1);
  tft.drawCentreString(text, 160, h + 1, 1);
  tft.drawCentreString(text, 159, h, 1);
  tft.drawCentreString(text, 161, h, 1);
  tft.setTextColor(0xf7de);
  tft.drawCentreString(text, 160, h, 1);
}

void disp_text_b_w(String text, int h) {
  tft.setTextColor(0x0882);
  tft.setCursor(5, h - 1);
  tft.print(text);
  tft.setCursor(5, h + 1);
  tft.print(text);
  tft.setCursor(4, h);
  tft.print(text);
  tft.setCursor(6, h);
  tft.print(text);
  tft.setTextColor(0xf7de);
  tft.setCursor(5, h);
  tft.print(text);
}

// Functions that work with files in SPIFFS (Below)

void write_to_file_with_overwrite(fs::FS &fs, String filename, String content) {
   //Serial.printf("Writing file: %s\r\n", filename);

   File file = fs.open(filename, FILE_WRITE);
   if(!file){
      //Serial.println("− failed to open file for writing");
      return;
   }
   if(file.print(content)){
      //Serial.println("− file written");
   }else {
      //Serial.println("− frite failed");
   }
}

String read_file(fs::FS &fs, String filename) {
  String file_content;
   //Serial.printf("Reading file: %s\r\n", filename);

   File file = fs.open(filename);
   if(!file || file.isDirectory()){
       //Serial.println("− failed to open file for reading");
       return "-1";
   }

   //Serial.println("− read from file:");
   while(file.available()){
      file_content += char(file.read());
   }
   return file_content;
}

void delete_file(fs::FS &fs, String filename){
   //Serial.printf("Deleting file: %s\r\n", filename);
   if(fs.remove(filename)){
      //Serial.println("− file deleted");
   } else {
      //Serial.println("− delete failed");
   }
}

void typing_inscription(){
  display_background_while_adding_record();
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  disp_text_b_w("Typing...", 5);
  disp_text_b_w("Please wait for a while.", 17);
}

// Functions for Logins (Below)

void select_login(byte what_to_do_with_it) {
  // 0 - Add login
  // 1 - Edit login
  // 2 - Delete login
  // 3 - View login
  delay(DELAY_FOR_SLOTS);
  curr_key = 1;

  header_for_select_login(what_to_do_with_it);
  display_title_from_login_without_integrity_verification();
  bool continue_to_next = false;
  while (continue_to_next == false) {
    byte input_data = get_PS2_keyboard_input();
    if (input_data > 0) {

      if (input_data == 130)
        curr_key++;

      if (input_data == 129)
        curr_key--;

      if (curr_key < 1)
        curr_key = MAX_NUM_OF_RECS;

      if (curr_key > MAX_NUM_OF_RECS)
        curr_key = 1;

      if (input_data == 13 || input_data == 133) { // Enter
        int chsn_slot = curr_key;
        if (what_to_do_with_it == 0 && continue_to_next == false) {
          continue_to_next = true;
          add_login_from_nint_controller(chsn_slot);
        }
        if (what_to_do_with_it == 1 && continue_to_next == false) {
          continue_to_next = true;
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          edit_login_from_nint_controller(chsn_slot);
        }
        if (what_to_do_with_it == 2 && continue_to_next == false) {
          continue_to_next = true;
          delete_login(chsn_slot);
        }
        if (what_to_do_with_it == 3 && continue_to_next == false) {
          continue_to_next = true;
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          view_login(chsn_slot);
        }
        if (what_to_do_with_it == 4 && continue_to_next == false) {
          continue_to_next = true;
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          type_login(chsn_slot);
        }
        continue_to_next = true;
        break;
      }

      if (input_data == 8 || input_data == 27) {
        call_main_menu();
        continue_to_next = true;
        break;
      }
      delay(DELAY_FOR_SLOTS);
      header_for_select_login(what_to_do_with_it);
      display_title_from_login_without_integrity_verification();
    }
    delayMicroseconds(500);
  }
  return;
}

void header_for_select_login(byte what_to_do_with_it) {
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  if (what_to_do_with_it == 0) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add Login to Slot " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Edit Login " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 2) {
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Delete Login " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation_for_del();
  }
  if (what_to_do_with_it == 3) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View Login " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 4) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Type Login " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
}

void display_title_from_login_without_integrity_verification() {
  tft.setTextSize(2);
  String encrypted_title = read_file(SPIFFS, "/L" + String(curr_key) + "_ttl");
  if (encrypted_title == "-1") {
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 35);
  } else {
    clear_variables();
    decrypt_tag = false;
    decrypt_with_TDES_AES_Blowfish_Serp(encrypted_title);
    tft.setTextColor(0xffff);
    disp_centered_text(dec_st, 35);
  }
}

void add_login_from_nint_controller(int chsn_slot) {
  enter_title_for_login(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void enter_title_for_login(int chsn_slot) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Title");
  get_to_ps2_keyboard_input_tab();
  if (act == true) {
    enter_username_for_login(chsn_slot, input_from_the_ps2_keyboard);
  }
  return;
}

void enter_username_for_login(int chsn_slot, String entered_title) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Username");
  get_to_ps2_keyboard_input_tab();
  if (act == true) {
    enter_password_for_login(chsn_slot, entered_title, input_from_the_ps2_keyboard);
  }
  return;
}

void enter_password_for_login(int chsn_slot, String entered_title, String entered_username) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Password");
  get_to_ps2_keyboard_input_tab();
  if (act == true) {
    enter_website_for_login(chsn_slot, entered_title, entered_username, input_from_the_ps2_keyboard);
  }
  return;
}

void enter_website_for_login(int chsn_slot, String entered_title, String entered_username, String entered_password) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Website");
  get_to_ps2_keyboard_input_tab();
  if (act == true) {
    write_login_to_flash(chsn_slot, entered_title, entered_username, entered_password, input_from_the_ps2_keyboard);
  }
  return;
}

void write_login_to_flash(int chsn_slot, String entered_title, String entered_username, String entered_password, String entered_website) {
  /*
  Serial.println();
  Serial.println(chsn_slot);
  Serial.println(entered_title);
  Serial.println(entered_username);
  Serial.println(entered_password);
  Serial.println(entered_website);
  */
  display_background_while_adding_record();
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  disp_text_b_w("Adding Login To The Slot N" + String(chsn_slot) + "...", 5);
  disp_text_b_w("Please wait for a while.", 17);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_title);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite(SPIFFS, "/L" + String(chsn_slot) + "_ttl", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_username);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite(SPIFFS, "/L" + String(chsn_slot) + "_usn", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_password);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite(SPIFFS, "/L" + String(chsn_slot) + "_psw", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_website);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite(SPIFFS, "/L" + String(chsn_slot) + "_wbs", dec_st);
  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(entered_title + entered_username + entered_password + entered_website);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite(SPIFFS, "/L" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void update_login_and_tag(int chsn_slot, String new_password) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Editing Login In The Slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");

  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(new_password);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite(SPIFFS, "/L" + String(chsn_slot) + "_psw", dec_st);

  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/L" + String(chsn_slot) + "_ttl"));
  String decrypted_title = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/L" + String(chsn_slot) + "_usn"));
  String decrypted_username = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/L" + String(chsn_slot) + "_wbs"));
  String decrypted_website = dec_st;

  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(decrypted_title + decrypted_username + new_password + decrypted_website);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite(SPIFFS, "/L" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void edit_login_from_nint_controller(int chsn_slot) {
  if (read_file(SPIFFS, "/L" + String(chsn_slot) + "_psw") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    tft.setTextSize(1);
    disp_centered_text("Press any key to return to the main menu", 232);
    press_any_button_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/L" + String(chsn_slot) + "_psw"));
    String old_password = dec_st;
    act = true;
    clear_variables();
    set_stuff_for_input("Edit Password");
    input_from_the_ps2_keyboard = old_password;
    disp();
    get_to_ps2_keyboard_input_tab();
    if (act == true) {
      update_login_and_tag(chsn_slot, input_from_the_ps2_keyboard);
    }
  }
  return;
}

void delete_login(int chsn_slot) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Deleting Login From The Slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  delete_file(SPIFFS, "/L" + String(chsn_slot) + "_tag");
  delete_file(SPIFFS, "/L" + String(chsn_slot) + "_ttl");
  delete_file(SPIFFS, "/L" + String(chsn_slot) + "_usn");
  delete_file(SPIFFS, "/L" + String(chsn_slot) + "_psw");
  delete_file(SPIFFS, "/L" + String(chsn_slot) + "_wbs");
  clear_variables();
  call_main_menu();
  return;
}

void view_login(int chsn_slot) {
  if (read_file(SPIFFS, "/L" + String(chsn_slot) + "_ttl") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    tft.setTextSize(1);
    disp_centered_text("Press any key to return to the main menu", 232);
    press_any_button_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/L" + String(chsn_slot) + "_ttl"));
    String decrypted_title = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/L" + String(chsn_slot) + "_usn"));
    String decrypted_username = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/L" + String(chsn_slot) + "_psw"));
    String decrypted_password = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/L" + String(chsn_slot) + "_wbs"));
    String decrypted_website = dec_st;
    clear_variables();
    decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/L" + String(chsn_slot) + "_tag"));
    dec_st = decrypted_title + decrypted_username + decrypted_password + decrypted_website;
    bool login_integrity = verify_integrity();

    if (login_integrity == true) {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setCursor(0, 5);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Username:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_username);
      tft.setTextColor(current_inact_clr);
      tft.print("Password:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_password);
      tft.setTextColor(current_inact_clr);
      tft.print("Website:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_website);
      tft.setTextSize(1);
      tft.fillRect(0, 230, 320, 14, 0x0000);
      tft.fillRect(312, 0, 8, 240, current_inact_clr);
      disp_centered_text(succs_ver_inscr, 232);
    } else {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setCursor(0, 5);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Username:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_username);
      tft.setTextColor(current_inact_clr);
      tft.print("Password:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_password);
      tft.setTextColor(current_inact_clr);
      tft.print("Website:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_website);
      tft.setTextSize(1);
      tft.fillRect(0, 230, 320, 14, 0x0000);
      tft.fillRect(312, 0, 8, 240, five_six_five_red_color);
      disp_centered_text(faild_ver_inscr, 232);
    }
    act = false;
    up_or_encdr_bttn_to_print();
    if (act == true) {
      Serial.println();
      Serial.print("Title:\"");
      Serial.print(decrypted_title);
      Serial.println("\"");
      Serial.print("Username:\"");
      Serial.print(decrypted_username);
      Serial.println("\"");
      Serial.print("Password:\"");
      Serial.print(decrypted_password);
      Serial.println("\"");
      Serial.print("Website:\"");
      Serial.print(decrypted_website);
      Serial.println("\"");
      if (login_integrity == true) {
        Serial.println("Integrity Verified Successfully!\n");
      } else {
        Serial.println("Integrity Verification Failed!!!\n");
      }
    }
  }
}

void type_login(int chsn_slot) {
  if (read_file(SPIFFS, "/L" + String(chsn_slot) + "_ttl") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    disp_centered_text("Press any key to return to the main menu", 232);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/L" + String(chsn_slot) + "_ttl"));
    String decrypted_title = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/L" + String(chsn_slot) + "_usn"));
    String decrypted_username = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/L" + String(chsn_slot) + "_psw"));
    String decrypted_password = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/L" + String(chsn_slot) + "_wbs"));
    String decrypted_website = dec_st;
    clear_variables();
    decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/L" + String(chsn_slot) + "_tag"));
    dec_st = decrypted_title + decrypted_username + decrypted_password + decrypted_website;
    bool login_integrity = verify_integrity();

    if (login_integrity == true) {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 65);
      
      disp_centered_text("to type \"Website\"", 85);
      act = false;
      up_or_encdr_bttn_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(decrypted_website);
      }
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 65);
      
      disp_centered_text("to type \"Username\"", 85);
      act = false;
      up_or_encdr_bttn_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(decrypted_username);
      }
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 65);
      
      disp_centered_text("to type \"Password\"", 85);
      act = false;
      up_or_encdr_bttn_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(decrypted_password);
      }
    } else {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setTextColor(five_six_five_red_color);
      disp_centered_text("Integrity", 65);
      disp_centered_text("Verification", 85);
      disp_centered_text("Failed!!!", 105);
      tft.setTextSize(1);
      tft.setTextColor(0xffff);
      disp_centered_text("Press any key to return to the main menu", 232);
      press_any_key_to_continue();
    }
  }
}

// Functions for Logins (Above)

// Functions for Credit Cards (Below)

void select_credit_card(byte what_to_do_with_it) {
  // 0 - Add credit_card
  // 1 - Edit credit_card
  // 2 - Delete credit_card
  // 3 - View credit_card
  delay(DELAY_FOR_SLOTS);
  curr_key = 1;

  header_for_select_credit_card(what_to_do_with_it);
  display_title_from_credit_card_without_integrity_verification();
  bool continue_to_next = false;
  while (continue_to_next == false) {
    byte input_data = get_PS2_keyboard_input();
    if (input_data > 0) {

      if (input_data == 130)
        curr_key++;

      if (input_data == 129)
        curr_key--;

      if (curr_key < 1)
        curr_key = MAX_NUM_OF_RECS;

      if (curr_key > MAX_NUM_OF_RECS)
        curr_key = 1;

      if (input_data == 13 || input_data == 133) { // Enter
        int chsn_slot = curr_key;
        if (what_to_do_with_it == 0 && continue_to_next == false) {
          continue_to_next = true;
          add_credit_card_from_nint_controller(chsn_slot);
        }
        if (what_to_do_with_it == 1 && continue_to_next == false) {
          continue_to_next = true;
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          edit_credit_card_from_nint_controller(chsn_slot);
        }
        if (what_to_do_with_it == 2 && continue_to_next == false) {
          continue_to_next = true;
          delete_credit_card(chsn_slot);
        }
        if (what_to_do_with_it == 3 && continue_to_next == false) {
          continue_to_next = true;
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          view_credit_card(chsn_slot);
        }
        if (what_to_do_with_it == 4 && continue_to_next == false) {
          continue_to_next = true;
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          type_credit_card(chsn_slot);
        }
        continue_to_next = true;
        break;
      }

      if (input_data == 8 || input_data == 27) {
        call_main_menu();
        continue_to_next = true;
        break;
      }
      delay(DELAY_FOR_SLOTS);
      header_for_select_credit_card(what_to_do_with_it);
      display_title_from_credit_card_without_integrity_verification();
    }
    delayMicroseconds(500);
  }
  return;
}

void header_for_select_credit_card(byte what_to_do_with_it) {
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  if (what_to_do_with_it == 0) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add Card to Slot " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Edit Credit Card " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 2) {
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Delete Credit Card " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation_for_del();
  }
  if (what_to_do_with_it == 3) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View Credit Card " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 4) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Type Credit Card " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
}

void display_title_from_credit_card_without_integrity_verification() {
  tft.setTextSize(2);
  String encrypted_title = read_file(SPIFFS, "/C" + String(curr_key) + "_ttl");
  if (encrypted_title == "-1") {
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 35);
  } else {
    clear_variables();
    decrypt_tag = false;
    decrypt_with_TDES_AES_Blowfish_Serp(encrypted_title);
    tft.setTextColor(0xffff);
    disp_centered_text(dec_st, 35);
  }
}

void add_credit_card_from_nint_controller(int chsn_slot) {
  enter_title_for_credit_card(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void enter_title_for_credit_card(int chsn_slot) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Title");
  get_to_ps2_keyboard_input_tab();
  if (act == true) {
    enter_cardholder_for_credit_card(chsn_slot, input_from_the_ps2_keyboard);
  }
  return;
}

void enter_cardholder_for_credit_card(int chsn_slot, String entered_title) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Cardholder Name");
  get_to_ps2_keyboard_input_tab();
  if (act == true) {
    enter_card_number_for_credit_card(chsn_slot, entered_title, input_from_the_ps2_keyboard);
  }
  return;
}

void enter_card_number_for_credit_card(int chsn_slot, String entered_title, String entered_cardholder) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Card Number");
  get_to_ps2_keyboard_input_tab();
  if (act == true) {
    enter_expiry_for_credit_card(chsn_slot, entered_title, entered_cardholder, input_from_the_ps2_keyboard);
  }
  return;
}

void enter_expiry_for_credit_card(int chsn_slot, String entered_title, String entered_cardholder, String entered_card_number) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Expiration Date");
  get_to_ps2_keyboard_input_tab();
  if (act == true) {
    enter_cvn_for_credit_card(chsn_slot, entered_title, entered_cardholder, entered_card_number, input_from_the_ps2_keyboard);
  }
  return;
}

void enter_cvn_for_credit_card(int chsn_slot, String entered_title, String entered_cardholder, String entered_card_number, String entered_expiry) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter CVN");
  get_to_ps2_keyboard_input_tab();
  if (act == true) {
    enter_pin_for_credit_card(chsn_slot, entered_title, entered_cardholder, entered_card_number, entered_expiry, input_from_the_ps2_keyboard);
  }
  return;
}

void enter_pin_for_credit_card(int chsn_slot, String entered_title, String entered_cardholder, String entered_card_number, String entered_expiry, String entered_cvn) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter PIN");
  get_to_ps2_keyboard_input_tab();
  if (act == true) {
    enter_zip_code_for_credit_card(chsn_slot, entered_title, entered_cardholder, entered_card_number, entered_expiry, entered_cvn, input_from_the_ps2_keyboard);
  }
  return;
}

void enter_zip_code_for_credit_card(int chsn_slot, String entered_title, String entered_cardholder, String entered_card_number, String entered_expiry, String entered_cvn, String entered_pin) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter ZIP Code");
  get_to_ps2_keyboard_input_tab();
  if (act == true) {
    write_credit_card_to_flash(chsn_slot, entered_title, entered_cardholder, entered_card_number, entered_expiry, entered_cvn, entered_pin, input_from_the_ps2_keyboard);
  }
  return;
}

void write_credit_card_to_flash(int chsn_slot, String entered_title, String entered_cardholder, String entered_card_number, String entered_expiry, String entered_cvn, String entered_pin, String entered_zip_code) {
  /*
  Serial.println();
  Serial.println(chsn_slot);
  Serial.println(entered_title);
  Serial.println(entered_cardholder);
  Serial.println(entered_card_number);
  Serial.println(entered_expiry);
  */
  display_background_while_adding_record();
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  disp_text_b_w("Adding Credit Card To The Slot N" + String(chsn_slot) + "...", 5);
  disp_text_b_w("Please wait for a while.", 17);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_title);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite(SPIFFS, "/C" + String(chsn_slot) + "_ttl", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_cardholder);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite(SPIFFS, "/C" + String(chsn_slot) + "_hld", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_card_number);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite(SPIFFS, "/C" + String(chsn_slot) + "_nmr", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_expiry);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite(SPIFFS, "/C" + String(chsn_slot) + "_exp", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_cvn);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite(SPIFFS, "/C" + String(chsn_slot) + "_cvn", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_pin);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite(SPIFFS, "/C" + String(chsn_slot) + "_pin", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_zip_code);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite(SPIFFS, "/C" + String(chsn_slot) + "_zip", dec_st);
  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(entered_title + entered_cardholder + entered_card_number + entered_expiry + entered_cvn + entered_pin + entered_zip_code);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite(SPIFFS, "/C" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void update_credit_card_and_tag(int chsn_slot, String new_pin) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Editing Credit Card In The Slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(new_pin);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite(SPIFFS, "/C" + String(chsn_slot) + "_pin", dec_st);
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/C" + String(chsn_slot) + "_ttl"));
  String decrypted_title = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/C" + String(chsn_slot) + "_hld"));
  String decrypted_cardholder = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/C" + String(chsn_slot) + "_nmr"));
  String decrypted_card_number = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/C" + String(chsn_slot) + "_exp"));
  String decrypted_expiry = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/C" + String(chsn_slot) + "_cvn"));
  String decrypted_cvn = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/C" + String(chsn_slot) + "_zip"));
  String decrypted_zip_code = dec_st;
  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(decrypted_title + decrypted_cardholder + decrypted_card_number + decrypted_expiry + decrypted_cvn + new_pin + decrypted_zip_code);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite(SPIFFS, "/C" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void edit_credit_card_from_nint_controller(int chsn_slot) {
  if (read_file(SPIFFS, "/C" + String(chsn_slot) + "_pin") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    tft.setTextSize(1);
    disp_centered_text("Press any key to return to the main menu", 232);
    press_any_button_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/C" + String(chsn_slot) + "_pin"));
    String old_pin = dec_st;
    act = true;
    clear_variables();
    set_stuff_for_input("Edit PIN");
    input_from_the_ps2_keyboard = old_pin;
    disp();
    get_to_ps2_keyboard_input_tab();
    if (act == true) {
      update_credit_card_and_tag(chsn_slot, input_from_the_ps2_keyboard);
    }
  }
  return;
}

void delete_credit_card(int chsn_slot) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Deleting Credit Card From The Slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  delete_file(SPIFFS, "/C" + String(chsn_slot) + "_tag");
  delete_file(SPIFFS, "/C" + String(chsn_slot) + "_ttl");
  delete_file(SPIFFS, "/C" + String(chsn_slot) + "_hld");
  delete_file(SPIFFS, "/C" + String(chsn_slot) + "_nmr");
  delete_file(SPIFFS, "/C" + String(chsn_slot) + "_exp");
  delete_file(SPIFFS, "/C" + String(chsn_slot) + "_cvn");
  delete_file(SPIFFS, "/C" + String(chsn_slot) + "_pin");
  delete_file(SPIFFS, "/C" + String(chsn_slot) + "_zip");
  clear_variables();
  call_main_menu();
  return;
}

void view_credit_card(int chsn_slot) {
  if (read_file(SPIFFS, "/C" + String(chsn_slot) + "_ttl") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    tft.setTextSize(1);
    disp_centered_text("Press any key to return to the main menu", 232);
    press_any_button_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/C" + String(chsn_slot) + "_ttl"));
    String decrypted_title = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/C" + String(chsn_slot) + "_hld"));
    String decrypted_cardholder = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/C" + String(chsn_slot) + "_nmr"));
    String decrypted_card_number = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/C" + String(chsn_slot) + "_exp"));
    String decrypted_expiry = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/C" + String(chsn_slot) + "_cvn"));
    String decrypted_cvn = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/C" + String(chsn_slot) + "_pin"));
    String decrypted_pin = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/C" + String(chsn_slot) + "_zip"));
    String decrypted_zip_code = dec_st;
    decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/C" + String(chsn_slot) + "_tag"));
    dec_st = decrypted_title + decrypted_cardholder + decrypted_card_number + decrypted_expiry + decrypted_cvn + decrypted_pin + decrypted_zip_code;
    bool credit_card_integrity = verify_integrity();

    if (credit_card_integrity == true) {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setCursor(0, 5);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Cardholder Name:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_cardholder);
      tft.setTextColor(current_inact_clr);
      tft.print("Card Number:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_card_number);
      tft.setTextColor(current_inact_clr);
      tft.print("Expiration Date:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_expiry);
      tft.setTextColor(current_inact_clr);
      tft.print("CVN:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_cvn);
      tft.setTextColor(current_inact_clr);
      tft.print("PIN:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_pin);
      tft.setTextColor(current_inact_clr);
      tft.print("ZIP Code:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_zip_code);
      tft.setTextSize(1);
      tft.fillRect(0, 230, 320, 14, 0x0000);
      tft.fillRect(312, 0, 8, 240, current_inact_clr);
      disp_centered_text(succs_ver_inscr, 232);
    } else {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setCursor(0, 5);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Cardholder Name:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_cardholder);
      tft.setTextColor(current_inact_clr);
      tft.print("Card Number:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_card_number);
      tft.setTextColor(current_inact_clr);
      tft.print("Expiration Date:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_expiry);
      tft.setTextColor(current_inact_clr);
      tft.print("CVN:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_cvn);
      tft.setTextColor(current_inact_clr);
      tft.print("PIN:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_pin);
      tft.setTextColor(current_inact_clr);
      tft.print("ZIP Code:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_zip_code);
      tft.setTextSize(1);
      tft.fillRect(0, 230, 320, 14, 0x0000);
      tft.fillRect(312, 0, 8, 240, five_six_five_red_color);
      disp_centered_text(faild_ver_inscr, 232);
    }
    act = false;
    up_or_encdr_bttn_to_print();
    if (act == true) {
      Serial.println();
      Serial.print("Title:\"");
      Serial.print(decrypted_title);
      Serial.println("\"");
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
      Serial.print(decrypted_zip_code);
      Serial.println("\"");
      if (credit_card_integrity == true) {
        Serial.println("Integrity Verified Successfully!\n");
      } else {
        Serial.println("Integrity Verification Failed!!!\n");
      }
    }
  }
}

void type_credit_card(int chsn_slot) {
  if (read_file(SPIFFS, "/C" + String(chsn_slot) + "_ttl") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    disp_centered_text("Press any key to return to the main menu", 232);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/C" + String(chsn_slot) + "_ttl"));
    String decrypted_title = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/C" + String(chsn_slot) + "_hld"));
    String decrypted_cardholder = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/C" + String(chsn_slot) + "_nmr"));
    String decrypted_card_number = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/C" + String(chsn_slot) + "_exp"));
    String decrypted_expiry = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/C" + String(chsn_slot) + "_cvn"));
    String decrypted_cvn = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/C" + String(chsn_slot) + "_pin"));
    String decrypted_pin = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/C" + String(chsn_slot) + "_zip"));
    String decrypted_zip_code = dec_st;
    decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/C" + String(chsn_slot) + "_tag"));
    dec_st = decrypted_title + decrypted_cardholder + decrypted_card_number + decrypted_expiry + decrypted_cvn + decrypted_pin + decrypted_zip_code;
    bool credit_card_integrity = verify_integrity();

    if (credit_card_integrity == true) {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 65);
      
      disp_centered_text("to type \"Cardholder Name\"", 85);
      act = false;
      up_or_encdr_bttn_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(decrypted_cardholder);
      }
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 65);
      
      disp_centered_text("to type \"Card Number\"", 85);
      act = false;
      up_or_encdr_bttn_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(decrypted_card_number);
      }
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 65);
      
      disp_centered_text("to type \"Expiration Date\"", 85);
      act = false;
      up_or_encdr_bttn_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(decrypted_expiry);
      }
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 65);
      
      disp_centered_text("to type \"CVN\"", 85);
      act = false;
      up_or_encdr_bttn_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(decrypted_cvn);
      }
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 65);
      
      disp_centered_text("to type \"PIN\"", 85);
      act = false;
      up_or_encdr_bttn_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(decrypted_pin);
      }
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 65);
      
      disp_centered_text("to type \"ZIP Code\"", 85);
      act = false;
      up_or_encdr_bttn_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(decrypted_zip_code);
      }
    } else {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setTextColor(five_six_five_red_color);
      disp_centered_text("Integrity", 65);
      disp_centered_text("Verification", 85);
      disp_centered_text("Failed!!!", 105);
      tft.setTextSize(1);
      tft.setTextColor(0xffff);
      disp_centered_text("Press any key to return to the main menu", 232);
      press_any_key_to_continue();
    }
  }
}

// Functions for Credit Cards (Above)

// Functions for Notes (Below)

void select_note(byte what_to_do_with_it) {
  // 0 - Add note
  // 1 - Edit note
  // 2 - Delete note
  // 3 - View note
  delay(DELAY_FOR_SLOTS);
  curr_key = 1;

  header_for_select_note(what_to_do_with_it);
  display_title_from_note_without_integrity_verification();
  bool continue_to_next = false;
  while (continue_to_next == false) {
    byte input_data = get_PS2_keyboard_input();
    if (input_data > 0) {

      if (input_data == 130)
        curr_key++;

      if (input_data == 129)
        curr_key--;

      if (curr_key < 1)
        curr_key = MAX_NUM_OF_RECS;

      if (curr_key > MAX_NUM_OF_RECS)
        curr_key = 1;

      if (input_data == 13 || input_data == 133) { // Enter
        int chsn_slot = curr_key;
        if (what_to_do_with_it == 0 && continue_to_next == false) {
          continue_to_next = true;
          add_note_from_nint_controller(chsn_slot);
        }
        if (what_to_do_with_it == 1 && continue_to_next == false) {
          continue_to_next = true;
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          edit_note_from_nint_controller(chsn_slot);
        }
        if (what_to_do_with_it == 2 && continue_to_next == false) {
          continue_to_next = true;
          delete_note(chsn_slot);
        }
        if (what_to_do_with_it == 3 && continue_to_next == false) {
          continue_to_next = true;
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          view_note(chsn_slot);
        }
        if (what_to_do_with_it == 4 && continue_to_next == false) {
          continue_to_next = true;
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          type_note(chsn_slot);
        }
        continue_to_next = true;
        break;
      }

      if (input_data == 8 || input_data == 27) {
        call_main_menu();
        continue_to_next = true;
        break;
      }
      delay(DELAY_FOR_SLOTS);
      header_for_select_note(what_to_do_with_it);
      display_title_from_note_without_integrity_verification();
    }
    delayMicroseconds(500);
  }
  return;
}

void header_for_select_note(byte what_to_do_with_it) {
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  if (what_to_do_with_it == 0) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add Note to Slot " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Edit Note " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 2) {
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Delete Note " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation_for_del();
  }
  if (what_to_do_with_it == 3) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View Note " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 4) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Type Note " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
}

void display_title_from_note_without_integrity_verification() {
  tft.setTextSize(2);
  String encrypted_title = read_file(SPIFFS, "/N" + String(curr_key) + "_ttl");
  if (encrypted_title == "-1") {
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 35);
  } else {
    clear_variables();
    decrypt_tag = false;
    decrypt_with_TDES_AES_Blowfish_Serp(encrypted_title);
    tft.setTextColor(0xffff);
    disp_centered_text(dec_st, 35);
  }
}

void add_note_from_nint_controller(int chsn_slot) {
  enter_title_for_note(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void enter_title_for_note(int chsn_slot) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Title");
  get_to_ps2_keyboard_input_tab();
  if (act == true) {
    enter_content_for_note(chsn_slot, input_from_the_ps2_keyboard);
  }
  return;
}

void enter_content_for_note(int chsn_slot, String entered_title) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Content");
  get_to_ps2_keyboard_input_tab();
  if (act == true) {
    write_note_to_flash(chsn_slot, entered_title, input_from_the_ps2_keyboard);
  }
  return;
}

void write_note_to_flash(int chsn_slot, String entered_title, String entered_content) {
  display_background_while_adding_record();
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  disp_text_b_w("Adding Note To The Slot N" + String(chsn_slot) + "...", 5);
  disp_text_b_w("Please wait for a while.", 17);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_title);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite(SPIFFS, "/N" + String(chsn_slot) + "_ttl", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_content);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite(SPIFFS, "/N" + String(chsn_slot) + "_cnt", dec_st);
  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(entered_title + entered_content);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite(SPIFFS, "/N" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void update_note_and_tag(int chsn_slot, String new_content) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Editing Note In The Slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");

  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(new_content);
  write_to_file_with_overwrite(SPIFFS, "/N" + String(chsn_slot) + "_cnt", dec_st);

  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/N" + String(chsn_slot) + "_ttl"));
  String decrypted_title = dec_st;

  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(decrypted_title + new_content);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite(SPIFFS, "/N" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void edit_note_from_nint_controller(int chsn_slot) {
  if (read_file(SPIFFS, "/N" + String(chsn_slot) + "_cnt") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    tft.setTextSize(1);
    disp_centered_text("Press any key to return to the main menu", 232);
    press_any_button_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/N" + String(chsn_slot) + "_cnt"));
    String old_password = dec_st;
    act = true;
    clear_variables();
    set_stuff_for_input("Edit Note");
    input_from_the_ps2_keyboard = old_password;
    disp();
    get_to_ps2_keyboard_input_tab();
    if (act == true) {
      update_note_and_tag(chsn_slot, input_from_the_ps2_keyboard);
    }
  }
  return;
}

void delete_note(int chsn_slot) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Deleting Note From The Slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  delete_file(SPIFFS, "/N" + String(chsn_slot) + "_tag");
  delete_file(SPIFFS, "/N" + String(chsn_slot) + "_ttl");
  delete_file(SPIFFS, "/N" + String(chsn_slot) + "_cnt");
  clear_variables();
  call_main_menu();
  return;
}

void view_note(int chsn_slot) {
  if (read_file(SPIFFS, "/N" + String(chsn_slot) + "_ttl") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    tft.setTextSize(1);
    disp_centered_text("Press any key to return to the main menu", 232);
    press_any_button_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/N" + String(chsn_slot) + "_ttl"));
    String decrypted_title = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/N" + String(chsn_slot) + "_cnt"));
    String decrypted_content = dec_st;
    clear_variables();
    decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/N" + String(chsn_slot) + "_tag"));
    dec_st = decrypted_title + decrypted_content;
    bool login_integrity = verify_integrity();

    if (login_integrity == true) {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setCursor(0, 5);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Content:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_content);
      tft.setTextSize(1);
      tft.fillRect(0, 230, 320, 14, 0x0000);
      tft.fillRect(312, 0, 8, 240, current_inact_clr);
      disp_centered_text(succs_ver_inscr, 232);
    } else {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setCursor(0, 5);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Content:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_content);
      tft.setTextSize(1);
      tft.fillRect(0, 230, 320, 14, 0x0000);
      tft.fillRect(312, 0, 8, 240, five_six_five_red_color);
      disp_centered_text(faild_ver_inscr, 232);
    }
    act = false;
    up_or_encdr_bttn_to_print();
    if (act == true) {
      Serial.println();
      Serial.print("Title:\"");
      Serial.print(decrypted_title);
      Serial.println("\"");
      Serial.print("Content:\"");
      Serial.print(decrypted_content);
      Serial.println("\"");
      if (login_integrity == true) {
        Serial.println("Integrity Verified Successfully!\n");
      } else {
        Serial.println("Integrity Verification Failed!!!\n");
      }
    }
  }
}

void type_note(int chsn_slot) {
  if (read_file(SPIFFS, "/N" + String(chsn_slot) + "_ttl") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    disp_centered_text("Press any key to return to the main menu", 232);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/N" + String(chsn_slot) + "_ttl"));
    String decrypted_title = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/N" + String(chsn_slot) + "_cnt"));
    String decrypted_content = dec_st;
    clear_variables();
    decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/N" + String(chsn_slot) + "_tag"));
    dec_st = decrypted_title + decrypted_content;
    bool note_integrity = verify_integrity();

    if (note_integrity == true) {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 65);
      
      disp_centered_text("to type \"Note\"", 85);
      act = false;
      up_or_encdr_bttn_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(decrypted_content);
      }
    } else {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setTextColor(five_six_five_red_color);
      disp_centered_text("Integrity", 65);
      disp_centered_text("Verification", 85);
      disp_centered_text("Failed!!!", 105);
      tft.setTextSize(1);
      tft.setTextColor(0xffff);
      disp_centered_text("Press any key to return to the main menu", 232);
      press_any_key_to_continue();
    }
  }
}

// Functions for Notes (Above)

// Functions for Phone Numbers (Below)

void select_phone_number(byte what_to_do_with_it) {
  // 0 - Add phone_number
  // 1 - Edit phone_number
  // 2 - Delete phone_number
  // 3 - View phone_number
  delay(DELAY_FOR_SLOTS);
  curr_key = 1;

  header_for_select_phone_number(what_to_do_with_it);
  display_title_from_phone_number_without_integrity_verification();
  bool continue_to_next = false;
  while (continue_to_next == false) {
    byte input_data = get_PS2_keyboard_input();
    if (input_data > 0) {

      if (input_data == 130)
        curr_key++;

      if (input_data == 129)
        curr_key--;

      if (curr_key < 1)
        curr_key = MAX_NUM_OF_RECS;

      if (curr_key > MAX_NUM_OF_RECS)
        curr_key = 1;

      if (input_data == 13 || input_data == 133) { // Enter
        int chsn_slot = curr_key;
        if (what_to_do_with_it == 0 && continue_to_next == false) {
          continue_to_next = true;
          add_phone_number_from_nint_controller(chsn_slot);
        }
        if (what_to_do_with_it == 1 && continue_to_next == false) {
          continue_to_next = true;
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          edit_phone_number_from_nint_controller(chsn_slot);
        }
        if (what_to_do_with_it == 2 && continue_to_next == false) {
          continue_to_next = true;
          delete_phone_number(chsn_slot);
        }
        if (what_to_do_with_it == 3 && continue_to_next == false) {
          continue_to_next = true;
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          view_phone_number(chsn_slot);
        }
        if (what_to_do_with_it == 4 && continue_to_next == false) {
          continue_to_next = true;
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          type_phone_number(chsn_slot);
        }
        continue_to_next = true;
        break;
      }

      if (input_data == 8 || input_data == 27) {
        call_main_menu();
        continue_to_next = true;
        break;
      }
      delay(DELAY_FOR_SLOTS);
      header_for_select_phone_number(what_to_do_with_it);
      display_title_from_phone_number_without_integrity_verification();
    }
    delayMicroseconds(500);
  }
  return;
}

void header_for_select_phone_number(byte what_to_do_with_it) {
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  if (what_to_do_with_it == 0) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add Phone to Slot " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Edit Phone Number " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 2) {
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Delete Phone " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation_for_del();
  }
  if (what_to_do_with_it == 3) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View Phone Number " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 4) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Type Phone Number " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
}

void display_title_from_phone_number_without_integrity_verification() {
  tft.setTextSize(2);
  String encrypted_title = read_file(SPIFFS, "/P" + String(curr_key) + "_ttl");
  if (encrypted_title == "-1") {
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 35);
  } else {
    clear_variables();
    decrypt_tag = false;
    decrypt_with_TDES_AES_Blowfish_Serp(encrypted_title);
    tft.setTextColor(0xffff);
    disp_centered_text(dec_st, 35);
  }
}

void add_phone_number_from_nint_controller(int chsn_slot) {
  enter_title_for_phone_number(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void enter_title_for_phone_number(int chsn_slot) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Title");
  get_to_ps2_keyboard_input_tab();
  if (act == true) {
    enter_phone_number_for_phone_number(chsn_slot, input_from_the_ps2_keyboard);
  }
  return;
}

void enter_phone_number_for_phone_number(int chsn_slot, String entered_title) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Phone Number");
  get_to_ps2_keyboard_input_tab();
  if (act == true) {
    write_phone_number_to_flash(chsn_slot, entered_title, input_from_the_ps2_keyboard);
  }
  return;
}

void write_phone_number_to_flash(int chsn_slot, String entered_title, String entered_phone_number) {
  display_background_while_adding_record();
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  disp_text_b_w("Adding Phone Number To The Slot N" + String(chsn_slot) + "...", 5);
  disp_text_b_w("Please wait for a while.", 17);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_title);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite(SPIFFS, "/P" + String(chsn_slot) + "_ttl", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_phone_number);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite(SPIFFS, "/P" + String(chsn_slot) + "_cnt", dec_st);
  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(entered_title + entered_phone_number);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite(SPIFFS, "/P" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void update_phone_number_and_tag(int chsn_slot, String new_phone_number) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Editing Phone Number In The Slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");

  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(new_phone_number);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite(SPIFFS, "/P" + String(chsn_slot) + "_cnt", dec_st);

  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/P" + String(chsn_slot) + "_ttl"));
  String decrypted_title = dec_st;

  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(decrypted_title + new_phone_number);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite(SPIFFS, "/P" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void edit_phone_number_from_nint_controller(int chsn_slot) {
  if (read_file(SPIFFS, "/P" + String(chsn_slot) + "_cnt") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    tft.setTextSize(1);
    disp_centered_text("Press any key to return to the main menu", 232);
    press_any_button_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/P" + String(chsn_slot) + "_cnt"));
    String old_password = dec_st;
    act = true;
    clear_variables();
    set_stuff_for_input("Edit Phone Number");
    input_from_the_ps2_keyboard = old_password;
    disp();
    get_to_ps2_keyboard_input_tab();
    if (act == true) {
      update_phone_number_and_tag(chsn_slot, input_from_the_ps2_keyboard);
    }
  }
  return;
}

void delete_phone_number(int chsn_slot) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Deleting Phone Number From The Slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  delete_file(SPIFFS, "/P" + String(chsn_slot) + "_tag");
  delete_file(SPIFFS, "/P" + String(chsn_slot) + "_ttl");
  delete_file(SPIFFS, "/P" + String(chsn_slot) + "_cnt");
  clear_variables();
  call_main_menu();
  return;
}

void view_phone_number(int chsn_slot) {
  if (read_file(SPIFFS, "/P" + String(chsn_slot) + "_ttl") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    tft.setTextSize(1);
    disp_centered_text("Press any key to return to the main menu", 232);
    press_any_button_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/P" + String(chsn_slot) + "_ttl"));
    String decrypted_title = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/P" + String(chsn_slot) + "_cnt"));
    String decrypted_phone_number = dec_st;
    clear_variables();
    decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/P" + String(chsn_slot) + "_tag"));
    dec_st = decrypted_title + decrypted_phone_number;
    bool login_integrity = verify_integrity();

    if (login_integrity == true) {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setCursor(0, 5);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Phone Number:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_phone_number);
      tft.setTextSize(1);
      tft.fillRect(0, 230, 320, 14, 0x0000);
      tft.fillRect(312, 0, 8, 240, current_inact_clr);
      disp_centered_text(succs_ver_inscr, 232);
    } else {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setCursor(0, 5);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Phone Number:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_phone_number);
      tft.setTextSize(1);
      tft.fillRect(0, 230, 320, 14, 0x0000);
      tft.fillRect(312, 0, 8, 240, five_six_five_red_color);
      disp_centered_text(faild_ver_inscr, 232);
    }
    act = false;
    up_or_encdr_bttn_to_print();
    if (act == true) {
      Serial.println();
      Serial.print("Title:\"");
      Serial.print(decrypted_title);
      Serial.println("\"");
      Serial.print("Phone Number:\"");
      Serial.print(decrypted_phone_number);
      Serial.println("\"");
      if (login_integrity == true) {
        Serial.println("Integrity Verified Successfully!\n");
      } else {
        Serial.println("Integrity Verification Failed!!!\n");
      }
    }
  }
}

void type_phone_number(int chsn_slot) {
  if (read_file(SPIFFS, "/P" + String(chsn_slot) + "_ttl") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    disp_centered_text("Press any key to return to the main menu", 232);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/P" + String(chsn_slot) + "_ttl"));
    String decrypted_title = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/P" + String(chsn_slot) + "_cnt"));
    String decrypted_phone_number = dec_st;
    clear_variables();
    decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/P" + String(chsn_slot) + "_tag"));
    dec_st = decrypted_title + decrypted_phone_number;
    bool phone_number_integrity = verify_integrity();

    if (phone_number_integrity == true) {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 65);
      disp_centered_text("to type \"Phone Number\"", 85);
      act = false;
      up_or_encdr_bttn_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(decrypted_phone_number);
      }
    } else {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setTextColor(five_six_five_red_color);
      disp_centered_text("Integrity", 65);
      disp_centered_text("Verification", 85);
      disp_centered_text("Failed!!!", 105);
      tft.setTextSize(1);
      tft.setTextColor(0xffff);
      disp_centered_text("Press any key to return to the main menu", 232);
      press_any_key_to_continue();
    }
  }
}

// Functions for Phone Number (Above)

// Functions that work with files in SPIFFS (Above)

void press_any_button_to_continue() {
  bool break_the_loop = false;
  while (break_the_loop == false) {
    byte input_data = get_PS2_keyboard_input();
    if (input_data > 0) {
      break_the_loop = true;
    }
    delay(read_keyboard_delay);
  }
}

void mvn_bcg(){
  if (display_moving_background == true) {
    if (chosen_lock_screen == 0) {
      for (int i = 0; i < 306; i++) {
        for (int j = 0; j < 77; j++) {
          if (mdb_icon[i][j] == 1)
            mvng_bc.drawPixel(i, j, Atlanta[(i + 7 + k) % 320][j + 57]);
        }
      }
    }
    if (chosen_lock_screen == 1) {
      for (int i = 0; i < 306; i++) {
        for (int j = 0; j < 77; j++) {
          if (mdb_icon[i][j] == 1)
            mvng_bc.drawPixel(i, j, Buildings[(i + 7 + k) % 320][j + 57]);
        }
      }
    }

    if (chosen_lock_screen == 2) {
      for (int i = 0; i < 306; i++) {
        for (int j = 0; j < 77; j++) {
          if (mdb_icon[i][j] == 1)
            mvng_bc.drawPixel(i, j, Dallas[(i + 7 + k) % 320][j + 57]);
        }
      }
    }

    if (chosen_lock_screen == 3) {
      for (int i = 0; i < 306; i++) {
        for (int j = 0; j < 77; j++) {
          if (mdb_icon[i][j] == 1)
            mvng_bc.drawPixel(i, j, Doha[(i + 7 + k) % 320][j + 57]);
        }
      }
    }

    if (chosen_lock_screen == 4) {
      for (int i = 0; i < 306; i++) {
        for (int j = 0; j < 77; j++) {
          if (mdb_icon[i][j] == 1)
            mvng_bc.drawPixel(i, j, Haifa[(i + 7 + k) % 320][j + 57]);
        }
      }
    }

    if (chosen_lock_screen == 5) {
      for (int i = 0; i < 306; i++) {
        for (int j = 0; j < 77; j++) {
          if (mdb_icon[i][j] == 1)
            mvng_bc.drawPixel(i, j, Jakarta[(i + 7 + k) % 320][j + 57]);
        }
      }
    }

    if (chosen_lock_screen == 6) {
      for (int i = 0; i < 306; i++) {
        for (int j = 0; j < 77; j++) {
          if (mdb_icon[i][j] == 1)
            mvng_bc.drawPixel(i, j, Jerusalem[(i + 7 + k) % 320][j + 57]);
        }
      }
    }

    if (chosen_lock_screen == 7) {
      for (int i = 0; i < 306; i++) {
        for (int j = 0; j < 77; j++) {
          if (mdb_icon[i][j] == 1)
            mvng_bc.drawPixel(i, j, London[(i + 7 + k) % 320][j + 57]);
        }
      }
    }

    if (chosen_lock_screen == 8) {
      for (int i = 0; i < 306; i++) {
        for (int j = 0; j < 77; j++) {
          if (mdb_icon[i][j] == 1)
            mvng_bc.drawPixel(i, j, Los_Angeles[(i + 7 + k) % 320][j + 57]);
        }
      }
    }

    if (chosen_lock_screen == 9) {
      for (int i = 0; i < 306; i++) {
        for (int j = 0; j < 77; j++) {
          if (mdb_icon[i][j] == 1)
            mvng_bc.drawPixel(i, j, Miami[(i + 7 + k) % 320][j + 57]);
        }
      }
    }

    if (chosen_lock_screen == 10) {
      for (int i = 0; i < 306; i++) {
        for (int j = 0; j < 77; j++) {
          if (mdb_icon[i][j] == 1)
            mvng_bc.drawPixel(i, j, Milan[(i + 7 + k) % 320][j + 57]);
        }
      }
    }

    if (chosen_lock_screen == 11) {
      for (int i = 0; i < 306; i++) {
        for (int j = 0; j < 77; j++) {
          if (mdb_icon[i][j] == 1)
            mvng_bc.drawPixel(i, j, Pittsburgh[(i + 7 + k) % 320][j + 57]);
        }
      }
    }

    if (chosen_lock_screen == 12) {
      for (int i = 0; i < 306; i++) {
        for (int j = 0; j < 77; j++) {
          if (mdb_icon[i][j] == 1)
            mvng_bc.drawPixel(i, j, Riyadh[(i + 7 + k) % 320][j + 57]);
        }
      }
    }

    if (chosen_lock_screen == 13) {
      for (int i = 0; i < 306; i++) {
        for (int j = 0; j < 77; j++) {
          if (mdb_icon[i][j] == 1)
            mvng_bc.drawPixel(i, j, Singapore[(i + 7 + k) % 320][j + 57]);
        }
      }
    }

    if (chosen_lock_screen == 14) {
      for (int i = 0; i < 306; i++) {
        for (int j = 0; j < 77; j++) {
          if (mdb_icon[i][j] == 1)
            mvng_bc.drawPixel(i, j, Tel_Aviv[(i + 7 + k) % 320][j + 57]);
        }
      }
    }

    mvng_bc.pushSprite(7, 82, TFT_TRANSPARENT);
    k++;
  }
}

void show_moving_background() {
  mvng_bc.createSprite(306, 77);
  mvng_bc.setColorDepth(16);
  mvng_bc.fillSprite(TFT_TRANSPARENT);
  bool break_the_loop = false;
  while (break_the_loop == false) {
    byte input_data = get_PS2_keyboard_input_mvn_bcg();
    if (input_data > 0) {
      break_the_loop = true;
    }
  }
}

void up_or_encdr_bttn_to_print() {
  bool break_the_loop = false;
  while (break_the_loop == false) {
    byte input_data = get_PS2_keyboard_input();
    if (input_data > 0) {

      if (input_data == 131 || input_data == 133) {
        act = true;
        break_the_loop = true;
      } else
        break_the_loop = true;
    }
    delayMicroseconds(read_keyboard_delay);
  }
}

void draw_full_height_pattern(){
  tft.fillScreen(65434);
  for (int i = 0; i < 120; i++) {
    for (int j = 0; j < 238; j++) {
      tft.drawPixel(i + 40, j + 1, half_pattern[i][j]);
    }
  }
  for (int i = 0; i < 120; i++) {
    for (int j = 0; j < 238; j++) {
      tft.drawPixel(i + 160, j + 1, half_pattern[119 - i][j]);
    }
  } 
}

void display_background_while_adding_record(){
  if (display_pattern_while_adding_and_printing_record == true){
    byte chosen_pattern = generate_random_number() % 4;
    if (chosen_pattern == 0){
      for (int n = 0; n < 240; n += 80) { // Columns
        for (int m = 0; m < 320; m += 80) { // Rows
          for (int i = 0; i < 80; i++) {
            for (int j = 0; j < 80; j++) {
              tft.drawPixel(i + m, j + n, pattern[i][j]);
            }
          }
        }
      }
    }
    if (chosen_pattern == 1){
      for (int n = 0; n < 240; n += 80) { // Columns
        for (int m = 0; m < 320; m += 80) { // Rows
          for (int i = 0; i < 80; i++) {
            for (int j = 0; j < 80; j++) {
              tft.drawPixel(i + m, j + n, pattern1[i][j]);
            }
          }
        }
      }
    }
    if (chosen_pattern == 2){
      for (int n = 0; n < 240; n += 80) { // Columns
        for (int m = 0; m < 320; m += 80) { // Rows
          for (int i = 0; i < 80; i++) {
            for (int j = 0; j < 80; j++) {
              tft.drawPixel(i + m, j + n, pattern2[i][j]);
            }
          }
        }
      }
    }
    if (chosen_pattern == 3){
      draw_full_height_pattern();
    }
  }
  else
    display_background_while_adding_record();
}

void display_lock_screen() {
  chosen_lock_screen = esp_random() % 15;

  if (chosen_lock_screen == 0){
    for (int i = 0; i < 320; i++){
      for (int j = 0; j < 190; j++){
        tft.drawPixel(i, j + 25, Atlanta[i][j]);
      }
    }
  }
  
  if (chosen_lock_screen == 1){
    for (int i = 0; i < 320; i++){
      for (int j = 0; j < 190; j++){
        tft.drawPixel(i, j + 25, Buildings[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 2){
    for (int i = 0; i < 320; i++){
      for (int j = 0; j < 190; j++){
        tft.drawPixel(i, j + 25, Dallas[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 3){
    for (int i = 0; i < 320; i++){
      for (int j = 0; j < 190; j++){
        tft.drawPixel(i, j + 25, Doha[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 4){
    for (int i = 0; i < 320; i++){
      for (int j = 0; j < 190; j++){
        tft.drawPixel(i, j + 25, Haifa[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 5){
    for (int i = 0; i < 320; i++){
      for (int j = 0; j < 190; j++){
        tft.drawPixel(i, j + 25, Jakarta[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 6){
    for (int i = 0; i < 320; i++){
      for (int j = 0; j < 190; j++){
        tft.drawPixel(i, j + 25, Jerusalem[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 7){
    for (int i = 0; i < 320; i++){
      for (int j = 0; j < 190; j++){
        tft.drawPixel(i, j + 25, London[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 8){
    for (int i = 0; i < 320; i++){
      for (int j = 0; j < 190; j++){
        tft.drawPixel(i, j + 25, Los_Angeles[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 9){
    for (int i = 0; i < 320; i++){
      for (int j = 0; j < 190; j++){
        tft.drawPixel(i, j + 25, Miami[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 10){
    for (int i = 0; i < 320; i++){
      for (int j = 0; j < 190; j++){
        tft.drawPixel(i, j + 25, Milan[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 11){
    for (int i = 0; i < 320; i++){
      for (int j = 0; j < 190; j++){
        tft.drawPixel(i, j + 25, Pittsburgh[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 12){
    for (int i = 0; i < 320; i++){
      for (int j = 0; j < 190; j++){
        tft.drawPixel(i, j + 25, Riyadh[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 13){
    for (int i = 0; i < 320; i++){
      for (int j = 0; j < 190; j++){
        tft.drawPixel(i, j + 25, Singapore[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 14){
    for (int i = 0; i < 320; i++){
      for (int j = 0; j < 190; j++){
        tft.drawPixel(i, j + 25, Tel_Aviv[i][j]);
      }
    }
  }

}

void continue_to_unlock() {
  if (read_file(SPIFFS, "/mpass").equals("-1"))
    set_pass();
  else
    unlock_midbar();
  return;
}

void set_pass() {
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setTextSize(1);
  set_stuff_for_input("Set Master Password");
  get_to_ps2_keyboard_input_tab();
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  draw_47px_midbar_inscription();
  tft.setTextColor(0xffff);
  disp_centered_text("Setting Master Password", 75);
  disp_centered_text("Please wait", 95);
  disp_centered_text("for a while", 115);
  //Serial.println(input_from_the_ps2_keyboard);
  String bck = input_from_the_ps2_keyboard;
  modify_keys();
  input_from_the_ps2_keyboard = bck;
  set_psswd();
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  draw_47px_midbar_inscription();
  tft.setTextColor(0xffff);
  disp_centered_text("Master Password Set", 75);
  disp_centered_text("Successfully", 95);
  disp_centered_text("Press Any Key", 115);
  disp_centered_text("To Continue", 135);
  press_any_key_to_continue();
  call_main_menu();
  return;
}

void set_psswd() {
  int str_len = input_from_the_ps2_keyboard.length() + 1;
  char input_arr[str_len];
  input_from_the_ps2_keyboard.toCharArray(input_arr, str_len);
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
    if (i == ((numofkincr * 2) / 3)) {
      for (int j = 0; j < 8; j++) {
        h += String(read_cards[j], HEX);
      }
    }
    if (i == numofkincr) {
      for (int j = 0; j < 8; j++) {
        h += String(read_cards[j + 8], HEX);
      }
    }
    if (i == ((numofkincr * 3) / 2)) {
      for (int j = 0; j < 16; j++) {
        h += String(read_cards[j], HEX);
      }
    }
  }
  //Serial.println();
  //Serial.println(h);
  back_keys();
  dec_st = "";
  encr_hash_for_tdes_aes_blf_srp(h);
  rest_keys();
  //Serial.println(dec_st);

  write_to_file_with_overwrite(SPIFFS, "/mpass", dec_st);
}

void modify_keys() {
  input_from_the_ps2_keyboard += kderalgs;
  int str_len = input_from_the_ps2_keyboard.length() + 1;
  char input_arr[str_len];
  input_from_the_ps2_keyboard.toCharArray(input_arr, str_len);
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
    if (i == numofkincr / 2) {
      for (int j = 0; j < 16; j++) {
        h += String(read_cards[j], HEX);
      }
    }
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
  for (int i = 0; i < 5; i++) {
    second_AES_key[i] = ((int(res[i + 31]) * int(res[i + 11])) + int(res[50])) % 256;
  }
}

void unlock_midbar() {
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  set_stuff_for_input("Enter Master Password");
  get_to_starred_ps2_keyboard_input_tab();
  tft.fillScreen(0x0000);
  draw_47px_midbar_inscription();
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  disp_centered_text("Unlocking Midbar", 75);
  disp_centered_text("Please wait", 95);
  disp_centered_text("for a while", 115);
  //Serial.println(input_from_the_ps2_keyboard);
  String bck = input_from_the_ps2_keyboard;
  modify_keys();
  input_from_the_ps2_keyboard = bck;
  bool next_act = hash_psswd();
  clear_variables();
  tft.fillScreen(0x0000);
  draw_47px_midbar_inscription();
  if (next_act == true) {
    tft.setTextSize(2);
    disp_centered_text("Midbar Unlocked", 75);
    disp_centered_text("Successfully", 95);
    disp_centered_text("Press Any Key", 115);
    disp_centered_text("To Continue", 135);
    press_any_key_to_continue();
    call_main_menu();
    return;
  } else {
    tft.setTextSize(2);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Wrong Password!", 75);
    tft.setTextColor(0xffff);
    disp_centered_text("Please reboot", 110);
    disp_centered_text("the device", 130);
    disp_centered_text("and try again", 150);
    for (;;)
      delay(1000);
  }
}

bool hash_psswd() {
  int str_len = input_from_the_ps2_keyboard.length() + 1;
  char input_arr[str_len];
  input_from_the_ps2_keyboard.toCharArray(input_arr, str_len);
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
    if (i == ((numofkincr * 2) / 3)) {
      for (int j = 0; j < 8; j++) {
        h += String(read_cards[j], HEX);
      }
    }
    if (i == numofkincr) {
      for (int j = 0; j < 8; j++) {
        h += String(read_cards[j + 8], HEX);
      }
    }
    if (i == ((numofkincr * 3) / 2)) {
      for (int j = 0; j < 16; j++) {
        h += String(read_cards[j], HEX);
      }
    }
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
  //Serial.println(read_file(SPIFFS, "/mpass"));
  decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file(SPIFFS, "/mpass"));
  //Serial.println(dec_tag);
  return dec_tag.equals(res_hash);
}

// Menu (below)

void disp_paste_smth_inscr(String what_to_pst) {
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setTextSize(1);
  disp_centered_text("Paste", 10);
  disp_centered_text(what_to_pst, 20);
  disp_centered_text("To The Serial Terminal", 30);
  tft.setTextColor(five_six_five_red_color);
  disp_centered_text("Press Any Button", 110);
  disp_centered_text("To Cancel", 120);
}

void disp_button_designation() {
  tft.setTextSize(1);
  tft.setTextColor(0x07e0);
  tft.setCursor(0, 232);
  tft.print(" Enter - Continue                       ");
  tft.setTextColor(five_six_five_red_color);
  tft.print("Esc - Cancel");
}

void disp_button_designation_for_del() {
  tft.setTextSize(1);
  tft.setTextColor(five_six_five_red_color);
  tft.setCursor(0, 232);
  tft.print(" Enter - Continue                       ");
  tft.setTextColor(0x07e0);
  tft.print("Esc - Cancel");
}

void draw_47px_midbar_inscription() {
  for (int i = 0; i < 192; i++) {
    for (int j = 0; j < 47; j++) {
      if (midbar_inscr_47px_high[i][j] == 1)
        tft.drawPixel(i + 64, j + 5, current_inact_clr);
    }
  }
}

void call_main_menu() {
  rec_d = false;
  tft.fillScreen(0x0000);
  draw_47px_midbar_inscription();
  curr_pos = 0;
  main_menu();
}

void main_menu() {
  tft.setTextSize(2);
  byte sdown = 60;
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("Logins", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Credit Cards", sdown + 30);
    disp_centered_text("Notes", sdown + 50);
    disp_centered_text("Phone Numbers", sdown + 70);
    disp_centered_text("Hash Functions", sdown + 90);
    disp_centered_text("Other Options", sdown + 110);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Credit Cards", sdown + 30);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Notes", sdown + 50);
    disp_centered_text("Phone Numbers", sdown + 70);
    disp_centered_text("Hash Functions", sdown + 90);
    disp_centered_text("Other Options", sdown + 110);
  }
  if (curr_pos == 2) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    disp_centered_text("Credit Cards", sdown + 30);
    tft.setTextColor(0xffff);
    disp_centered_text("Notes", sdown + 50);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Phone Numbers", sdown + 70);
    disp_centered_text("Hash Functions", sdown + 90);
    disp_centered_text("Other Options", sdown + 110);
  }
  if (curr_pos == 3) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    disp_centered_text("Credit Cards", sdown + 30);
    disp_centered_text("Notes", sdown + 50);
    tft.setTextColor(0xffff);
    disp_centered_text("Phone Numbers", sdown + 70);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Hash Functions", sdown + 90);
    disp_centered_text("Other Options", sdown + 110);
  }
  if (curr_pos == 4) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    disp_centered_text("Credit Cards", sdown + 30);
    disp_centered_text("Notes", sdown + 50);
    disp_centered_text("Phone Numbers", sdown + 70);
    tft.setTextColor(0xffff);
    disp_centered_text("Hash Functions", sdown + 90);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Other Options", sdown + 110);
  }
  if (curr_pos == 5) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    disp_centered_text("Credit Cards", sdown + 30);
    disp_centered_text("Notes", sdown + 50);
    disp_centered_text("Phone Numbers", sdown + 70);
    disp_centered_text("Hash Functions", sdown + 90);
    tft.setTextColor(0xffff);
    disp_centered_text("Other Options", sdown + 110);
  }
}

void action_for_data_in_flash_menu(int curr_pos) {
  tft.setTextSize(2);
  byte sdown = 60;
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("Add", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Edit", sdown + 30);
    disp_centered_text("Delete", sdown + 50);
    disp_centered_text("View", sdown + 70);
    disp_centered_text("Type", sdown + 90);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Edit", sdown + 30);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Delete", sdown + 50);
    disp_centered_text("View", sdown + 70);
    disp_centered_text("Type", sdown + 90);
  }
  if (curr_pos == 2) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add", sdown + 10);
    disp_centered_text("Edit", sdown + 30);
    tft.setTextColor(0xffff);
    disp_centered_text("Delete", sdown + 50);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View", sdown + 70);
    disp_centered_text("Type", sdown + 90);
  }
  if (curr_pos == 3) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add", sdown + 10);
    disp_centered_text("Edit", sdown + 30);
    disp_centered_text("Delete", sdown + 50);
    tft.setTextColor(0xffff);
    disp_centered_text("View", sdown + 70);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Type", sdown + 90);
  }
  if (curr_pos == 4) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add", sdown + 10);
    disp_centered_text("Edit", sdown + 30);
    disp_centered_text("Delete", sdown + 50);
    disp_centered_text("View", sdown + 70);
    tft.setTextColor(0xffff);
    disp_centered_text("Type", sdown + 90);
  }
}

void action_for_data_in_flash(String menu_title, byte record_type) {
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(current_inact_clr);
  disp_centered_text(menu_title, 10);
  curr_key = 0;

  action_for_data_in_flash_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    byte input_data = get_PS2_keyboard_input();
    if (input_data > 0) {

      if (input_data == 129 || input_data == 131)
        curr_key--;

      if (input_data == 130 || input_data == 132)
        curr_key++;

      if (curr_key < 0)
        curr_key = 4;

      if (curr_key > 4)
        curr_key = 0;

      if (input_data == 13 || input_data == 133) {
        if (curr_key == 0) {
          if (record_type == 0)
            select_login(0);
          if (record_type == 1)
            select_credit_card(0);
          if (record_type == 2)
            select_note(0);
          if (record_type == 3)
            select_phone_number(0);
          cont_to_next = true;
        }

        if (curr_key == 1 && cont_to_next == false) {
          if (record_type == 0)
            select_login(1);
          if (record_type == 1)
            select_credit_card(1);
          if (record_type == 2)
            select_note(1);
          if (record_type == 3)
            select_phone_number(1);
          cont_to_next = true;
        }

        if (curr_key == 2 && cont_to_next == false) {
          if (record_type == 0)
            select_login(2);
          if (record_type == 1)
            select_credit_card(2);
          if (record_type == 2)
            select_note(2);
          if (record_type == 3)
            select_phone_number(2);
          cont_to_next = true;
        }

        if (curr_key == 3 && cont_to_next == false) {
          if (record_type == 0)
            select_login(3);
          if (record_type == 1)
            select_credit_card(3);
          if (record_type == 2)
            select_note(3);
          if (record_type == 3)
            select_phone_number(3);
          cont_to_next = true;
        }

        if (curr_key == 4 && cont_to_next == false) {
          if (record_type == 0)
            select_login(4);
          if (record_type == 1)
            select_credit_card(4);
          if (record_type == 2)
            select_note(4);
          if (record_type == 3)
            select_phone_number(4);
          cont_to_next = true;
        }
      }
      
      if (input_data == 8 || input_data == 27) {
        cont_to_next = true;
      }
      action_for_data_in_flash_menu(curr_key);

    }
  }
  call_main_menu();
}

void hash_functions_menu(int curr_pos) {
  tft.setTextSize(2);
  byte sdown = 60;
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("SHA-256", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("SHA-512", sdown + 30);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("SHA-256", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("SHA-512", sdown + 30);
  }
}

void hash_functions() {
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(current_inact_clr);
  disp_centered_text("Hash Functions", 10);
  curr_key = 0;
  hash_functions_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    byte input_data = get_PS2_keyboard_input();
    if (input_data > 0) {
      if (input_data == 129 || input_data == 131)
        curr_key--;

      if (input_data == 130 || input_data == 132)
        curr_key++;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if (input_data == 13 || input_data == 133) {
        if (curr_key == 0) {
          hash_string_with_sha(false);
          cont_to_next = true;
        }

        if (curr_key == 1 && cont_to_next == false) {
          hash_string_with_sha(true);
          cont_to_next = true;
        }
      }
      if (input_data == 8 || input_data == 27) {
        cont_to_next = true;
      }
      hash_functions_menu(curr_key);

    }
  }
  call_main_menu();
}

void other_options_menu(int curr_pos) {
  tft.setTextSize(2);
  byte sdown = 60;
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("Send Password", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Factory Reset", sdown + 30);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Send Password", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Factory Reset", sdown + 30);
  }
}

void other_options() {
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(current_inact_clr);
  disp_centered_text("Other Options", 10);
  curr_key = 0;
  other_options_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    byte input_data = get_PS2_keyboard_input();
    if (input_data > 0) {
      if (input_data == 129 || input_data == 131)
        curr_key--;

      if (input_data == 130 || input_data == 132)
        curr_key++;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if (input_data == 13 || input_data == 133) {
        if (curr_key == 0) {
          send_password_to_receiver();
          cont_to_next = true;
        }

        if (curr_key == 1 && cont_to_next == false) {
          Factory_Reset();
          cont_to_next = true;
        }
      }
      if (input_data == 8 || input_data == 27) {
        cont_to_next = true;
      }
      other_options_menu(curr_key);

    }
  }
  call_main_menu();
}

// Menu (Above)

void Factory_Reset() {
  tft.fillScreen(0x0000);
  tft.setTextColor(five_six_five_red_color);
  disp_centered_text("Factory Reset", 10);
  delay(500);
  disp_centered_text("Attention!!!", 50);
  tft.setTextColor(0xffff);
  delay(500);
  disp_centered_text("All your data", 90);
  delay(500);
  disp_centered_text("will be lost!", 110);
  delay(500);
  tft.setTextColor(0x1557);
  disp_centered_text("Are you sure you want", 150);
  disp_centered_text("to continue?", 170);
  tft.setTextSize(1);
  delay(5000);
  disp_button_designation_for_del();
  finish_input = false;
  while (finish_input == false) {
    byte input_data = get_PS2_keyboard_input();
    if (input_data == 13 || input_data == 133) {
      perform_factory_reset();
      finish_input = true;
    }

    if (input_data == 8 || input_data == 27) {
      finish_input = true;
    }
    delayMicroseconds(read_keyboard_delay);
  }
  clear_variables();
  call_main_menu();
  return;
}

void perform_factory_reset() {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Performing Factory Reset...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  delay(1000);
  delete_file(SPIFFS, "/mpass");
  for (int i = 0; i < MAX_NUM_OF_RECS; i++) {
    delete_file(SPIFFS, "/L" + String(i + 1) + "_tag");
    delete_file(SPIFFS, "/L" + String(i + 1) + "_ttl");
    delete_file(SPIFFS, "/L" + String(i + 1) + "_usn");
    delete_file(SPIFFS, "/L" + String(i + 1) + "_psw");
    delete_file(SPIFFS, "/L" + String(i + 1) + "_wbs");
    delete_file(SPIFFS, "/C" + String(i + 1) + "_tag");
    delete_file(SPIFFS, "/C" + String(i + 1) + "_ttl");
    delete_file(SPIFFS, "/C" + String(i + 1) + "_hld");
    delete_file(SPIFFS, "/C" + String(i + 1) + "_nmr");
    delete_file(SPIFFS, "/C" + String(i + 1) + "_exp");
    delete_file(SPIFFS, "/C" + String(i + 1) + "_cvn");
    delete_file(SPIFFS, "/C" + String(i + 1) + "_pin");
    delete_file(SPIFFS, "/C" + String(i + 1) + "_zip");
    delete_file(SPIFFS, "/N" + String(i + 1) + "_tag");
    delete_file(SPIFFS, "/N" + String(i + 1) + "_ttl");
    delete_file(SPIFFS, "/N" + String(i + 1) + "_cnt");
    delete_file(SPIFFS, "/P" + String(i + 1) + "_tag");
    delete_file(SPIFFS, "/P" + String(i + 1) + "_ttl");
    delete_file(SPIFFS, "/P" + String(i + 1) + "_cnt");
    tft.fillRect(0, 10, 160, 10, 0x0000);
    tft.setCursor(0, 10);
    tft.print("Progress " + String((float(i + 1) / float(MAX_NUM_OF_RECS)) * 100) + "%");
  }
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  disp_centered_text("DONE!", 10);
  disp_centered_text("Please Reboot", 30);
  disp_centered_text("The Device", 40);
  delay(1000);
  for (;;) {}
}

void hash_string_with_sha(bool vrsn) {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setTextSize(1);
  set_stuff_for_input("Enter string to hash:");
  get_to_ps2_keyboard_input_tab();
  if (act == true) {
    if (vrsn == false)
      hash_with_sha256();
    else
      hash_with_sha512();
  }
  clear_variables();
  curr_key = 0;
  call_main_menu();
  return;
}

void hash_with_sha256() {
  int str_len = input_from_the_ps2_keyboard.length() + 1;
  char keyb_inp_arr[str_len];
  input_from_the_ps2_keyboard.toCharArray(keyb_inp_arr, str_len);
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
  tft.setTextColor(current_inact_clr);
  tft.setTextSize(2);
  disp_centered_text("Resulted hash", 10);
  tft.fillRect(312, 0, 8, 240, current_inact_clr);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 30);
  tft.println(res_hash);
  press_any_button_to_continue();
}

void hash_with_sha512() {
  int str_len = input_from_the_ps2_keyboard.length() + 1;
  char keyb_inp_arr[str_len];
  input_from_the_ps2_keyboard.toCharArray(keyb_inp_arr, str_len);
  std::string str = "";
  if (str_len > 1) {
    for (int i = 0; i < str_len - 1; i++) {
      str += keyb_inp_arr[i];
    }
  }
  String h = sha512(str).c_str();
  tft.fillScreen(0x0000);
  tft.setTextColor(current_inact_clr);
  tft.setTextSize(2);
  disp_centered_text("Resulted hash", 10);
  tft.fillRect(312, 0, 8, 240, current_inact_clr);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 30);
  tft.println(h);
  press_any_button_to_continue();
}

// Password Projection (Below)

char temp_st_for_pp[16];
bool send_setup;
bool n;
typedef struct struct_message {
  char l_srp[16];
  char r_srp[16];
  bool n;
} struct_message;

struct_message myData;

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

void send_password_to_receiver(){
  if (send_setup == false)
    key_setup_for_send_feature();
  send_password();
}

void key_setup_for_send_feature(){
   tft.fillScreen(0x0000);
   tft.setTextSize(2);
   tft.setTextColor(0xffff);
   disp_centered_text("Type this key", 10);
   disp_centered_text("on the keypad", 30);

  int rnd_len = 64 + esp_random()%75;
  char rnd_input[rnd_len];
  for(int i = 0; i < rnd_len; i++){
    rnd_input[i] = char(esp_random() % 256);
  }
  
  int rnd_key_len = 50 + esp_random()%40;
  byte rnd_key[rnd_key_len];
  for(int i = 0; i < rnd_key_len; i++){
    rnd_key[i] = byte(esp_random() % 256);
  }
  
  SHA256HMAC hmac(rnd_key, sizeof(rnd_key));
  hmac.doUpdate(rnd_input);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  String to_kda;
  for (byte i=10; i < 20; i++)
  {
      if (authCode[i]<0x10) { to_kda += '0'; }
      to_kda += String(authCode[i], HEX);
      to_kda += ' ';
  }
  to_kda.remove(to_kda.length() -1, 1);
  for (int i = 0; i < to_kda.length(); i++){
    if (to_kda.charAt(i) == 'a')
      to_kda[i] = 'A';
    if (to_kda.charAt(i) == 'b')
      to_kda[i] = 'B';
    if (to_kda.charAt(i) == 'c')
      to_kda[i] = 'C';
    if (to_kda.charAt(i) == 'd')
      to_kda[i] = 'D';
    if (to_kda.charAt(i) == 'e')
      to_kda[i] = 'E';
    if (to_kda.charAt(i) == 'f')
      to_kda[i] = 'F';
  }
   
   String hghprt;
   String lwrprt;
   for (int i = 0; i < 14; i++){
     hghprt += to_kda.charAt(i);
   }

   for (int i = 0; i < 14; i++){
     lwrprt += to_kda.charAt(i + 15);
   }

   tft.setTextColor(0x155b);
   disp_centered_text(hghprt, 70);
   disp_centered_text(lwrprt, 90);
   
   derive_session_keys(to_kda);
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
   send_setup = true;
   tft.setTextColor(0xffff);
   disp_centered_text("Verification Numbers", 140);
   tft.setTextColor(0x155b);
   String vrnms = String(int(ct2.b[7])) + "  " + String(int(ct2.b[6])) + "  " + String(int(ct2.b[15]));
   disp_centered_text(vrnms, 170);
   
    tft.setTextColor(0xffff);
    tft.setTextSize(1);
    tft.drawCentreString("Press any button to continue", 160, 232, 1);
    press_any_key_to_continue();
}

void send_password() {
  n = false;
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter Password to Send");
  get_to_ps2_keyboard_input_tab();
  if (act == true) {
    proj_pass(input_from_the_ps2_keyboard);
  }
  clear_variables();
  call_main_menu();
  return;
}

void proj_pass(String input){
      int str_len = input.length() + 1;
      char char_array[str_len];
      input.toCharArray(char_array, str_len);
      int p = 0;
      while( str_len > p+1){
        split_by_eight_for_pass_proj(char_array, p, str_len);
        p+=8;
      }
    input_from_the_ps2_keyboard = "";
    call_main_menu();
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
      res[i] = esp_random() % 256;
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
  set_aes_key(&ctx, projection_key, key_bit[2]);
  aes_encrypt_block(&ctx, cipher_text, text);
  /*
  for (int i = 0; i < 16; i++) {
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
    L_half[i] = esp_random() % 256;
    R_half[i] = esp_random() % 256;
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
  
  for (b=0; b<1; b++) {
    hex2binproj(key);
  
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
    /*
    for (int i=0; i<16; i++) {
      if(ct2.b[i]<16)
        Serial.print("0");
      Serial.print(ct2.b[i],HEX);
    }
    */
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
     incr_proj_serp_key();
     incr_proj_serp_key();
     n = true;
     delayMicroseconds(240);
    }
  }
}

// Password Projection (Above)

void setup(void) {
  rec_d = false;
  k = 0;
  Wire.begin();
  tft.begin();
  tft.setRotation(1);
  tft.fillScreen(0x0000);
  display_lock_screen();
  tft.setTextSize(2);
  Serial.begin(115200);
  keyboard.begin(DATAPIN, IRQPIN);
  keyboard.setNoBreak(1);
  keyboard.setNoRepeat(1);
  keymap.selectMap((char * )"US");
  if (SPIFFS.begin(true)) {} else {
    Serial.println("An Error has occurred while mounting SPIFFS");
    return;
  }
  WiFi.mode(WIFI_STA);
  // Init ESP-NOW
  if (esp_now_init() != ESP_OK) {
    Serial.println("Error initializing ESP-NOW");
    return;
  }
  esp_now_register_send_cb(OnDataSent);
  // Register peer
  memcpy(peerInfo.peer_addr, broadcastAddress, 6);
  peerInfo.channel = 0;  
  peerInfo.encrypt = false;
  // Add peer        
  if (esp_now_add_peer(&peerInfo) == ESP_OK){

  }
  else{
    Serial.println("Failed to add peer");
    return;
  }

  for (int i = 0; i < 306; i++) {
    for (int j = 0; j < 77; j++) {
      if (mdb_per[i][j] == 1)
        tft.drawPixel(i + 7, j + 82, 0xf7de);
    }
  }
  m = 2; // Set AES to 256-bit mode
  clb_m = 4;
  tft.setTextSize(2);
  tft.setTextColor(0xf7de);
  disp_centered_text("Midbar ESP32 V6.0", 4);
  disp_centered_text("Press Any Key", 220);
  if (display_moving_background == true)
    show_moving_background();
  else
    press_any_button_to_continue();
  continue_to_unlock();
}

void loop() {
  byte input_data = get_PS2_keyboard_input();

  if (input_data == 13 || input_data == 133) { //Enter
    if (curr_pos == 0) {
      action_for_data_in_flash("Logins Menu", curr_pos);
    }
    if (curr_pos == 1) {
      action_for_data_in_flash("Credit Cards Menu", curr_pos);
    }
    if (curr_pos == 2) {
      action_for_data_in_flash("Notes Menu", curr_pos);
    }
    if (curr_pos == 3) {
      action_for_data_in_flash("Phone Numbers Menu", curr_pos);
    }
    if (curr_pos == 4) {
      hash_functions();
    }
    if (curr_pos == 5) {
      other_options();
    }
  }

  if (input_data == 130 || input_data == 132) {
    curr_pos++;
    if (curr_pos > 5)
      curr_pos = 0;
    main_menu();
  }

  if (input_data == 129 || input_data == 131) {
    curr_pos--;
    if (curr_pos < 0)
      curr_pos = 5;
    main_menu();
  }
}
