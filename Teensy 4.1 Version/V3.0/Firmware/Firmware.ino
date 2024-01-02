/*
Midbar
Distributed under the MIT License
© Copyright Maxim Bortnikov 2024
For more information please visit
https://sourceforge.net/projects/midbar/
https://github.com/Northstrix/Midbar
Required libraries:
https://github.com/zhouyangchao/AES
https://github.com/peterferrie/serpent
https://github.com/ddokkaebi/Blowfish
https://github.com/Northstrix/DES_and_3DES_Library_for_MCUs
https://github.com/ulwanski/sha512
https://github.com/adafruit/Adafruit-ST7735-Library
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/intrbiz/arduino-crypto
*/
#include <SD.h>
#include <SPI.h>
#include <EEPROM.h>
#include "DES.h"
#include "aes.h"
#include "blowfish.h"
#include "serpent.h"
#include "Crypto.h"
#include "midbaricon.h"
#include "sha512.h"
#include "USBHost_t36.h"
#include "custom_hebrew_font.h"
#include <Adafruit_GFX.h>
#include <Adafruit_ST7735.h>
#define TFT_CS1    39                                                        // TFT CS  pin is connected to Teensy pin 39
#define TFT_RST1   40                                                        // TFT RST pin is connected to Teensy pin 40
#define TFT_DC1    41                                                        // TFT DC  pin is connected to Teensy pin 41
                                                                             // SCK (CLK) ---> Teensy pin 13
                                                                             // MOSI(DIN) ---> Teensy pin 11
Adafruit_ST7735 tft = Adafruit_ST7735(TFT_CS1, TFT_DC1, TFT_RST1);

#define MAX_NUM_OF_RECS 999
#define DELAY_FOR_SLOTS 24
#define SHOW_KEYBOARD_DATA
#define TYPE_DELAY 17
// Max. number of chars for each filed for the logins stored in EEPROM
#define MAX_NUM_OF_CHARS_FOR_USERNAME 52
#define MAX_NUM_OF_CHARS_FOR_PASSWORD 52
#define MAX_NUM_OF_CHARS_FOR_WEBSITE 56
// You can repartition the field sizes as long as the sum of all three values is 160

// Max. number of chars for each filed for the credit cards stored in EEPROM
#define MAX_NUM_OF_CHARS_FOR_CARDHOLDER 39
#define MAX_NUM_OF_CHARS_FOR_CARD_NUMBER 20
#define MAX_NUM_OF_CHARS_FOR_EXPIRATION_DATE 16
#define MAX_NUM_OF_CHARS_FOR_CVN 3
#define MAX_NUM_OF_CHARS_FOR_PIN 8
#define MAX_NUM_OF_CHARS_FOR_ZIP_CODE 10
// You can repartition the field sizes as long as the sum of all values is 96
DES des;
Blowfish blowfish;

const int chipSelect = BUILTIN_SDCARD;
int m;
int clb_m;
String dec_st;
String dec_tag;
byte tmp_st[8];
int pass_to_serp[16];
int decract;
byte array_for_CBC_mode[16];
String keyboard_input;
int curr_key;
int prsd_key;
bool usb_keyb_inp;
bool finish_input;
bool act;
bool decrypt_tag;
uint16_t colors[4] = { // Purple, Yellow, Green, Blue
  0xb81c, 0xfde0, 0x87a0, 0x041c
};
const uint16_t current_inact_clr = colors[3];
const uint16_t stripe_on_the_right_and_oth_opts_color = colors[0];
const uint16_t five_six_five_red_color = 0xf940;
bool sd_mnt;
byte sdown = 36;
#define letter_spacing_pxls 6
#define regular_shift_down 16
#define shift_down_for_mem 12
String succs_ver_inscr = "Integrity Verif Success!";
String faild_ver_inscr = "Integrity Verif Failed!";

byte custm_key_hmack_key[32];
uint8_t custom_serp_in_cbc_key[32];

#define TRNG_ENT_COUNT 16

static uint32_t rng_index;

USBHost myusb;
USBHub hub1(myusb);
KeyboardController keyboard1(myusb);

USBHIDParser hid1(myusb);
USBHIDParser hid2(myusb);
USBHIDParser hid3(myusb);

uint8_t keyboard_modifiers = 0;  // try to keep a reasonable value
#ifdef KEYBOARD_INTERFACE
uint8_t keyboard_last_leds = 0;
#endif

// Keys (Below)

byte read_cards[16] = {
0x96,0x2a,0xe5,0x74,0xfb,0xed,0x85,0xf8,
0x1d,0xff,0xe5,0x8e,0xd6,0x30,0x4c,0x9e
};
String kderalgs = "l7J639NSHQ929JmZyr77RyB";
int numofkincr = 761;
byte hmackey[] = {"Ulfw2lromjoGd50TWAS7cCN06ylhc2lxDFazZ4AqDvGU72Zj6O22Pc1d4HDm4n7Y5c5uo6807dMr33gnvUF5mxn3Yk9B6FlpO1YrA1HZ3Pc6N9J2Lhq"};
byte des_key[] = {
0x8e,0xc5,0xbb,0x34,0xe6,0x0e,0xdc,0xce,
0x0d,0xe0,0xad,0x5a,0xad,0x22,0xb2,0xcb,
0xb7,0x42,0x0b,0xdc,0xf4,0xfe,0x7b,0x2d
};
uint8_t AES_key[32] = {
0xe7,0x23,0x85,0xb3,
0x8f,0xff,0x8e,0x6a,
0xe8,0xa8,0x7a,0xf9,
0xb3,0x21,0x5a,0xd2,
0x3a,0xb0,0xc6,0x4e,
0x96,0x7b,0x76,0xda,
0xad,0x9b,0x18,0xa4,
0xe8,0x22,0xdd,0xe1
};
unsigned char Blwfsh_key[] = {
0xac,0x1c,0x86,0x26,
0x04,0x23,0xab,0x22,
0x36,0xbc,0x4b,0xca,
0x5b,0xb3,0xce,0xce,
0x32,0x33,0x82,0x49,
0x1f,0x5a,0xfa,0xf6
};
uint8_t serp_key[32] = {
0x91,0x10,0xb2,0xcc,
0xb1,0x1f,0xce,0xed,
0xf0,0xc4,0xe4,0xcd,
0xf4,0xcf,0x6e,0x95,
0x67,0x00,0x35,0xbd,
0xd8,0x1f,0xe3,0xb8,
0x08,0xea,0xd1,0xeb,
0x2f,0x3d,0xa5,0x61
};
uint8_t second_AES_key[32] = {
0xca,0xe7,0xb4,0xfd,
0xfd,0xda,0x7d,0x9e,
0x3e,0x5a,0x12,0xbb,
0x8a,0x96,0xda,0x3a,
0x80,0x81,0x1d,0x66,
0x0e,0xfd,0xb4,0x5e,
0xba,0xbb,0xfd,0x95,
0xe8,0x1b,0xa7,0x9f
};

// Keys (Above)

uint8_t serp_book_key[32];
String previous_book_segment;
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

/*
// Old key incrementation function (before refactoring)
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
*/
void incr_serp_key() {
  for (int i = 15; i >= 0; i--) {
    if (serp_key[i] == 255) {
      serp_key[i] = 0;
    } else {
      serp_key[i]++;
      break;
    }
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

void trng_init() {
  CCM_CCGR6 |= CCM_CCGR6_TRNG(CCM_CCGR_ON);
  TRNG_MCTL = TRNG_MCTL_RST_DEF | TRNG_MCTL_PRGM; // reset to program mode
  TRNG_MCTL = TRNG_MCTL_SAMP_MODE(2); // start run mode, vonneumann
  TRNG_ENT15; // discard any stale data, start gen cycle
}

unsigned int trng_word() {
  return (unsigned int) gen_random_value() ^ gen_random_value();
}

uint32_t gen_random_value(){
  uint32_t r;
  while ((TRNG_MCTL & TRNG_MCTL_ENT_VAL) == 0 &
    (TRNG_MCTL & TRNG_MCTL_ERR) == 0); // wait for entropy ready
  r = * ( & TRNG_ENT0 + rng_index++);
  if (rng_index >= TRNG_ENT_COUNT) rng_index = 0;
  return r;
}

int get_offset(String text_to_print){
  int shift_right = 160;
  for (int s = 0; s < text_to_print.length(); s++){ // Traverse the string

    if (text_to_print.charAt(s) == 'b'){ // Bet
      shift_right -= sizeof(Bet)/sizeof(Bet[0]);
      shift_right -= letter_spacing_pxls;
    }

    if (text_to_print.charAt(s) == 'd'){ // Dalet
      shift_right -= sizeof(Dalet)/sizeof(Dalet[0]);
      shift_right -= letter_spacing_pxls;
    }

    if (text_to_print.charAt(s) == 'M'){ // Mem
      shift_right -= sizeof(Mem)/sizeof(Mem[0]);
      shift_right -= letter_spacing_pxls;
    }

    if (text_to_print.charAt(s) == 'r'){ // Resh
      shift_right -= sizeof(Resh)/sizeof(Resh[0]);
      shift_right -= letter_spacing_pxls;
    }

  }
  shift_right += letter_spacing_pxls;
  return shift_right / 2;
}

void print_centered_custom_hebrew_font(String text_to_print, int y, uint16_t font_colors[], int how_many_colors){
  print_custom_multi_colored_hebrew_font(text_to_print, y, get_offset(text_to_print), font_colors, how_many_colors);
}

void print_custom_multi_colored_hebrew_font(String text_to_print, int y, int offset_from_the_right, uint16_t font_colors[], int how_many_colors){
  int shift_right = 160 - offset_from_the_right;
  for (int s = 0; s < text_to_print.length(); s++){ // Traverse the string

    if (text_to_print.charAt(s) == 'b'){ // Bet
      shift_right -= sizeof(Bet)/sizeof(Bet[0]);
      for (int i = 0; i < 22; i++) {
        for (int j = 0; j < 24; j++) {
          if (Bet[i][j] == 0)
            tft.drawPixel(i + shift_right, j + y + regular_shift_down, font_colors[s % how_many_colors]);
        }
      }
      shift_right -= letter_spacing_pxls;
    }

    if (text_to_print.charAt(s) == 'd'){ // Dalet
      shift_right -= sizeof(Dalet)/sizeof(Dalet[0]);
      for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 24; j++) {
          if (Dalet[i][j] == 0)
            tft.drawPixel(i + shift_right, j + y + regular_shift_down, font_colors[s % how_many_colors]);
        }
      }
      shift_right -= letter_spacing_pxls;
    }

    if (text_to_print.charAt(s) == 'M'){ // Mem
      shift_right -= sizeof(Mem)/sizeof(Mem[0]);
      for (int i = 0; i < 18; i++) {
        for (int j = 0; j < 29; j++) {
          if (Mem[i][j] == 0)
            tft.drawPixel(i + shift_right, j + y + shift_down_for_mem, font_colors[s % how_many_colors]);
        }
      }
      shift_right -= letter_spacing_pxls;
    }

    if (text_to_print.charAt(s) == 'r'){ // Resh
      shift_right -= sizeof(Resh)/sizeof(Resh[0]);
      for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 24; j++) {
          if (Resh[i][j] == 0)
            tft.drawPixel(i + shift_right, j + y + regular_shift_down, font_colors[s % how_many_colors]);
        }
      }
      shift_right -= letter_spacing_pxls;
    }
  }
}

void type_on_virtual_keyboard(String data_to_type){
  int lng = data_to_type.length();
  for (int i = 0; i < lng; i++){
    if (i % 4 == 0){
      tft.setTextColor(0x09E5);
      tft.setCursor(39, 3);
      tft.print(".");
    }
    else if (i % 4 == 1){
      tft.setCursor(39, 3);
      tft.print("..");
    }
    else if (i % 4 == 2){
      tft.setCursor(39, 3);
      tft.print("...");
    }
    else if (i % 4 == 3){
      tft.setCursor(39, 3);
      tft.setTextColor(59031);
      tft.print("...");
    }
    Keyboard.print(data_to_type.charAt(i));
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
  keyboard_input = "";
  dec_st = "";
  dec_tag = "";
  decract = 0;
  return;
}

// 3DES + AES + Blowfish + Serpent in CBC Mode(Below) (10 - 16)

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
    array_for_CBC_mode[i] = trng_word() % 256;
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
    res2[i] = trng_word() % 256;
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

// 3DES + AES + Blowfish + Serpent in CBC Mode (Above) (10 - 16)

// 3DES + AES + Blowfish + Serpent in CBC Mode(Below) (16 - 16)

void split_by_sixteen(char plntxt[], int k, int str_len) {
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
  byte res2[] = {
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
    res[i] = byte(plntxt[i + k]);
  }

  for (int i = 0; i < 8; i++) {
    if (i + 8 + k > str_len - 1)
      break;
    res2[i] = byte(plntxt[i + 8 + k]);
  }

  for (int i = 0; i < 8; i++) {
    res[i] ^= array_for_CBC_mode[i];
  }

  for (int i = 0; i < 8; i++) {
    res2[i] ^= array_for_CBC_mode[i + 8];
  }

  encrypt_with_tdes_fl(res, res2);
}

void encrypt_iv_for_tdes_aes_blwfsh_serp_fl() {
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
  byte res2[] = {
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
    array_for_CBC_mode[i] = trng_word() % 256;
  }

  for (int i = 0; i < 8; i++) {
    res[i] = array_for_CBC_mode[i];
  }

  for (int i = 0; i < 8; i++) {
    res2[i] = array_for_CBC_mode[i + 8];
  }

  encrypt_with_tdes_fl(res, res2);
}

void encrypt_with_tdes_fl(byte res[], byte res2[]) {
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

  encrypt_with_AES_fl(t_aes);
}

void encrypt_with_AES_fl(char t_enc[]) {
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
  encrypt_with_Blowfish_fl(first_eight, false);
  encrypt_with_Blowfish_fl(second_eight, true);
  encrypt_with_serpent_fl();
}

void encrypt_with_Blowfish_fl(unsigned char inp[], bool lrside) {
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

void encrypt_with_serpent_fl() {
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
        array_for_CBC_mode[i] = byte(int(ct2.b[i]));
      }
      if (ct2.b[i] < 16)
        dec_st += "0";
      dec_st += String(ct2.b[i], HEX);
    }
    decract++;
  }
}

void split_for_decryption_fl(char ct[], int ct_len, int p) {
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
      for (int i = 0; i < 16; i++) {
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
      for (int i = 0; i < 8; i++) {
        out[i] ^= array_for_CBC_mode[i];
      }

      for (int i = 0; i < 8; i++) {
        out2[i] ^= array_for_CBC_mode[i + 8];
      }

      if (decrypt_tag == false) {

        for (i = 0; i < 8; ++i) {
          if (out[i] > 0)
            dec_st += char(out[i]);
        }

        for (i = 0; i < 8; ++i) {
          if (out2[i] > 0)
            dec_st += char(out2[i]);
        }

      } else {
        for (i = 0; i < 8; ++i) {
          if (out[i] < 0x10)
            dec_tag += "0";
          dec_tag += String(out[i], HEX);
        }

        for (i = 0; i < 8; ++i) {
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

      for (i = 0; i < 8; ++i) {
        array_for_CBC_mode[i + 8] = out2[i];;
      }
    }
    decract++;
  }
}

void encr_hash_for_tdes_aes_blf_srp_fl(String input) {
  back_keys();
  clear_variables();
  encrypt_iv_for_tdes_aes_blwfsh_serp_fl();
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

  for (int i = 0; i < 2; i++) {
    split_by_sixteen(hmacchar, p, 100);
    p += 16;
  }
  rest_keys();
}

void encrypt_with_TDES_AES_Blowfish_Serp_fl(String input) {
  back_keys();
  clear_variables();
  encrypt_iv_for_tdes_aes_blwfsh_serp_fl();
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  int p = 0;
  while (str_len > p + 1) {
    split_by_sixteen(input_arr, p, str_len);
    p += 16;
  }
  rest_keys();
}

void decrypt_with_TDES_AES_Blowfish_Serp_fl(String ct) {
  back_keys();
  clear_variables();
  decrypt_tag = false;
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  decract = -1;
  while (ct_len > ext) {
    split_for_decryption_fl(ct_array, ct_len, 0 + ext);
    ext += 32;
    decract += 10;
  }
  rest_keys();
}

void decrypt_tag_with_TDES_AES_Blowfish_Serp_fl(String ct) {
  back_keys();
  clear_variables();
  decrypt_tag = true;
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  decract = -1;
  while (ct_len > ext) {
    split_for_decryption_fl(ct_array, ct_len, 0 + ext);
    ext += 32;
    decract += 10;
  }
  rest_keys();
}

void encrypt_string_with_tdes_aes_blf_srp_fl(String input) {
  encrypt_with_TDES_AES_Blowfish_Serp_fl(input);
  String td_aes_bl_srp_ciphertext = dec_st;
  encr_hash_for_tdes_aes_blf_srp_fl(input);
  dec_st += td_aes_bl_srp_ciphertext;
}

void decrypt_string_with_TDES_AES_Blowfish_Serp_fl(String ct) {
  back_keys();
  clear_variables();
  decrypt_tag = true;
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  decract = -1;
  for (int i = 0; i < 128; i += 32) {
    split_for_decryption_fl(ct_array, ct_len, 0 + ext);
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
    split_for_decryption_fl(ct_array1, ct_len1, 0 + ext);
    ext += 32;
    decract += 10;
  }
  rest_keys();
}

bool verify_integrity_32bytes() {
  int str_lentg = dec_st.length() + 1;
  char char_arraytg[str_lentg];
  dec_st.toCharArray(char_arraytg, str_lentg);
  SHA256HMAC hmac(custm_key_hmack_key, sizeof(custm_key_hmack_key));
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
  /*
  Serial.println(dec_st);
  Serial.println(dec_tag);
  Serial.println(res_hash);
  */
  return dec_tag.equals(res_hash);
}

// 3DES + AES + Blowfish + Serpent in CBC Mode (Above) (16 - 16)

// Blowfish + AES + Serpent + AES (Below)

void split_by_eight_bl_aes_serp_aes(char plntxt[], int k, int str_len) {
  char plt_data[] = {
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
    plt_data[i] = plntxt[i + k];
  }
  /*
  Serial.println("\nInput");
  for (int i = 0; i < 8; i++){
    Serial.print(plt_data[i]);
    Serial.print(" ");
  }
  */
  unsigned char t_encr[8];
  for (int i = 0; i < 8; i++) {
    t_encr[i] = (unsigned char) plt_data[i];
  }
  /*
  Serial.println("\nChar");
  for (int i = 0; i < 8; i++){
    Serial.print(t_encr[i]);
    Serial.print(" ");
  }
  */
  blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
  blowfish.Encrypt(t_encr, t_encr, sizeof(t_encr));
  char encr_for_aes[16];
  for (int i = 0; i < 8; i++) {
    encr_for_aes[i] = char(int(t_encr[i]));
  }
  /*
  Serial.println("\nEncrypted");
  for (int i = 0; i < 8; i++){
    Serial.print(t_encr[i]);
    Serial.print(" ");
  }
  */
  for (int i = 8; i < 16; i++) {
    encr_for_aes[i] = trng_word() % 256;
  }
  /*
  Serial.println("\nFor AES");
  for (int i = 0; i < 16; i++){
    Serial.print(int(encr_for_aes[i]));
    Serial.print(" ");
  }
  Serial.println();
  */
  encr_AES_bl_aes_serp_aes(encr_for_aes);
}

void encr_AES_bl_aes_serp_aes(char t_enc[]) {
  uint8_t text[16];
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
  uint32_t key_bit[3] = {
    128,
    192,
    256
  };
  aes_context ctx;
  aes_set_key( & ctx, AES_key, key_bit[m]);
  aes_encrypt_block( & ctx, cipher_text, text);
  /*
  for (int i = 0; i < 16; i++) {
    Serial.printf("%02x", cipher_text[i]);
  }
  */
  char L_half[16];
  for (int i = 0; i < 8; i++) {
    L_half[i] = cipher_text[i];
  }
  char R_half[16];
  for (int i = 0; i < 8; i++) {
    R_half[i] = cipher_text[i + 8];
  }
  for (int i = 8; i < 16; i++) {
    L_half[i] = trng_word() % 256;
    R_half[i] = trng_word() % 256;
  }
  serp_enc_bl_aes_serp_aes(L_half);
  serp_enc_bl_aes_serp_aes(R_half);
}

void serp_enc_bl_aes_serp_aes(char res[]) {
  int tmp_s[16];
  for (int i = 0; i < 16; i++) {
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
  uint32_t * p;

  for (b = 0; b < 1; b++) {
    hex2bin(key);

    // set key
    memset( & skey, 0, sizeof(skey));
    p = (uint32_t * ) & skey.x[0][0];

    serpent_setkey( & skey, key);

    for (int i = 0; i < 16; i++) {
      ct2.b[i] = tmp_s[i];
    }
    serpent_encrypt(ct2.b, & skey, SERPENT_ENCRYPT);
    encr_sec_AES_bl_aes_serp_aes(ct2.b);
  }
}

void encr_sec_AES_bl_aes_serp_aes(byte t_enc[]) {
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
  uint32_t second_key_bit[3] = {
    128,
    192,
    256
  };
  int i = 0;
  aes_context ctx;
  aes_set_key( & ctx, second_AES_key, second_key_bit[m]);
  aes_encrypt_block( & ctx, cipher_text, text);
  /*
  for (i = 0; i < 16; i++) {
    Serial.printf("%02x", cipher_text[i]);
  }
  */
  for (int i = 0; i < 16; i++) {
    if (cipher_text[i] < 16)
      dec_st += "0";
    dec_st += String(cipher_text[i], HEX);
  }
}

void split_dec_bl_aes_serp_aes(char ct[], int ct_len, int p, bool ch, bool add_r) {
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
    if (add_r == true) {
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
      for (int i = 0; i < 16; i++) {
        int c = int(res[i]);
        cipher_text[i] = c;
      }
      uint32_t second_key_bit[3] = {
        128,
        192,
        256
      };
      int i = 0;
      aes_context ctx;
      aes_set_key( & ctx, second_AES_key, second_key_bit[m]);
      aes_decrypt_block( & ctx, ret_text, cipher_text);
      for (i = 0; i < 16; i++) {
        res[i] = (char) ret_text[i];
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
    if (ch == false) {
      for (int i = 0; i < 8; i++) {
        tmp_st[i] = char(ct2.b[i]);
      }
    }
    if (ch == true) {
      decr_AES_and_Blowfish_bl_aes_serp_aes(ct2.b);
    }
  }
}

void decr_AES_and_Blowfish_bl_aes_serp_aes(byte sh[]) {
  uint8_t ret_text[16];
  for (int i = 0; i < 8; i++) {
    ret_text[i] = tmp_st[i];
  }
  for (int i = 0; i < 8; i++) {
    ret_text[i + 8] = sh[i];
  }
  uint8_t cipher_text[16] = {
    0
  };
  for (int i = 0; i < 16; i++) {
    int c = int(ret_text[i]);
    cipher_text[i] = c;
  }
  uint32_t key_bit[3] = {
    128,
    192,
    256
  };
  int i = 0;
  aes_context ctx;
  aes_set_key( & ctx, AES_key, key_bit[m]);
  aes_decrypt_block( & ctx, ret_text, cipher_text);
  /*
  Serial.println("\nDec by AES");
  for (int i = 0; i < 16; i++){\
    Serial.print(int(ret_text[i]));
    Serial.print(" ");
  }
  Serial.println();
  */
  unsigned char dbl[8];
  for (int i = 0; i < 8; i++) {
    dbl[i] = (unsigned char) int(ret_text[i]);
  }
  /*
  Serial.println("\nConv for blowfish");
  for (int i = 0; i < 8; i++){\
    Serial.print(dbl[i]);
    Serial.print(" ");
  }
  Serial.println();
  */
  blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
  blowfish.Decrypt(dbl, dbl, sizeof(dbl));
  /*
  Serial.println("\nDecr by blowfish");
  for (int i = 0; i < 8; i++){\
    Serial.print(int(dbl[i]));
    Serial.print(" ");
  }
  Serial.println();
  */
  if (decract < 4) {
    for (int i = 0; i < 8; i++) {
      if (dbl[i] < 0x10)
        dec_tag += 0;
      dec_tag += String(dbl[i], HEX);
    }
  } else {
    for (i = 0; i < 8; ++i) {
      dec_st += (char(dbl[i]));
    }
  }
  decract++;
}

void encr_hash_for_blwfsh_aes_serpent_aes(String input) {
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
    incr_Blwfsh_key();
    incr_AES_key();
    incr_serp_key();
    incr_second_AES_key();
    split_by_eight_bl_aes_serp_aes(hmacchar, p, 100);
    p += 8;
  }
}

void encrypt_with_blwfsh_aes_serpent_aes(String input) {
  back_keys();
  clear_variables();
  encr_hash_for_blwfsh_aes_serpent_aes(input);
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  int p = 0;
  while (str_len > p + 1) {
    incr_Blwfsh_key();
    incr_AES_key();
    incr_serp_key();
    incr_second_AES_key();
    split_by_eight_bl_aes_serp_aes(input_arr, p, str_len);
    p += 8;
  }
  rest_keys();
}

void decrypt_with_blwfsh_aes_serpent_aes(String ct) {
  back_keys();
  clear_variables();
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  int count = 0;
  bool ch = false;
  while (ct_len > ext) {
    if (count % 2 == 1 && count != 0)
      ch = true;
    else {
      ch = false;
      incr_Blwfsh_key();
      incr_AES_key();
      incr_serp_key();
      incr_second_AES_key();
    }
    split_dec_bl_aes_serp_aes(ct_array, ct_len, 0 + ext, ch, true);
    ext += 32;
    count++;
  }
  rest_keys();
}

// Blowfish + AES + Serpent + AES (Above)

// AES + Serpent + AES (Below)

void split_by_eight_for_aes_serp_aes(char plntxt[], int k, int str_len) {
  char plt_data[] = {
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
    plt_data[i] = plntxt[i + k];
  }
  char t_encr[16];
  for (int i = 0; i < 8; i++) {
    t_encr[i] = plt_data[i];
  }
  for (int i = 8; i < 16; i++) {
    t_encr[i] = trng_word() % 256;
  }
  encr_AES_for_aes_serp_aes(t_encr);
}

void encr_AES_for_aes_serp_aes(char t_enc[]) {
  uint8_t text[16];
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
  uint32_t key_bit[3] = {
    128,
    192,
    256
  };
  aes_context ctx;
  aes_set_key( & ctx, AES_key, key_bit[m]);
  aes_encrypt_block( & ctx, cipher_text, text);
  /*
  for (int i = 0; i < 16; i++) {
    Serial.printf("%02x", cipher_text[i]);
  }
  */
  char L_half[16];
  for (int i = 0; i < 8; i++) {
    L_half[i] = cipher_text[i];
  }
  char R_half[16];
  for (int i = 0; i < 8; i++) {
    R_half[i] = cipher_text[i + 8];
  }
  for (int i = 8; i < 16; i++) {
    L_half[i] = trng_word() % 256;
    R_half[i] = trng_word() % 256;
  }
  enc_serp_for_aes_serp_aes(L_half);
  enc_serp_for_aes_serp_aes(R_half);
}

void enc_serp_for_aes_serp_aes(char res[]) {
  int tmp_s[16];
  for (int i = 0; i < 16; i++) {
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
  uint32_t * p;

  for (b = 0; b < 1; b++) {
    hex2bin(key);

    // set key
    memset( & skey, 0, sizeof(skey));
    p = (uint32_t * ) & skey.x[0][0];

    serpent_setkey( & skey, key);
    for (int i = 0; i < 16; i++) {
      ct2.b[i] = tmp_s[i];
    }
    serpent_encrypt(ct2.b, & skey, SERPENT_ENCRYPT);
    encr_sec_AES_for_aes_serp_aes(ct2.b);
  }
}

void encr_sec_AES_for_aes_serp_aes(byte t_enc[]) {
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
  uint32_t second_key_bit[3] = {
    128,
    192,
    256
  };
  int i = 0;
  aes_context ctx;
  aes_set_key( & ctx, second_AES_key, second_key_bit[m]);
  aes_encrypt_block( & ctx, cipher_text, text);
  /*
  for (i = 0; i < 16; i++) {
    Serial.printf("%02x", cipher_text[i]);
  }
  */
  for (int i = 0; i < 16; i++) {
    if (cipher_text[i] < 16)
      dec_st += "0";
    dec_st += String(cipher_text[i], HEX);
  }
}

void split_dec_for_aes_serp_aes(char ct[], int ct_len, int p, bool ch, bool add_r) {
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
    if (add_r == true) {
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
      for (int i = 0; i < 16; i++) {
        int c = int(res[i]);
        cipher_text[i] = c;
      }
      uint32_t second_key_bit[3] = {
        128,
        192,
        256
      };
      int i = 0;
      aes_context ctx;
      aes_set_key( & ctx, second_AES_key, second_key_bit[m]);
      aes_decrypt_block( & ctx, ret_text, cipher_text);
      for (i = 0; i < 16; i++) {
        res[i] = (char) ret_text[i];
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
    if (ch == false) {
      for (int i = 0; i < 8; i++) {
        tmp_st[i] = char(ct2.b[i]);
      }
    }
    if (ch == true) {
      decr_AES_for_aes_serp_aes(ct2.b);
    }
  }
}

void decr_AES_for_aes_serp_aes(byte sh[]) {
  uint8_t ret_text[16];
  for (int i = 0; i < 8; i++) {
    ret_text[i] = tmp_st[i];
  }
  for (int i = 0; i < 8; i++) {
    ret_text[i + 8] = sh[i];
  }
  uint8_t cipher_text[16] = {
    0
  };
  for (int i = 0; i < 16; i++) {
    int c = int(ret_text[i]);
    cipher_text[i] = c;
  }
  uint32_t key_bit[3] = {
    128,
    192,
    256
  };
  int i = 0;
  aes_context ctx;
  aes_set_key( & ctx, AES_key, key_bit[m]);
  aes_decrypt_block( & ctx, ret_text, cipher_text);
  if (decract < 4) {
    for (int i = 0; i < 8; i++) {
      if (ret_text[i] < 0x10)
        dec_tag += 0;
      dec_tag += String(ret_text[i], HEX);
    }
  } else {
    for (i = 0; i < 8; ++i) {
      dec_st += (char(ret_text[i]));
    }
  }
  decract++;
}

void encr_hash_for_aes_serpent_aes(String input) {
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
    incr_AES_key();
    incr_serp_key();
    incr_second_AES_key();
    split_by_eight_for_aes_serp_aes(hmacchar, p, 100);
    p += 8;
  }
}

void encrypt_with_aes_serpent_aes(String input) {
  back_keys();
  clear_variables();
  encr_hash_for_aes_serpent_aes(input);
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  int p = 0;
  while (str_len > p + 1) {
    incr_AES_key();
    incr_serp_key();
    incr_second_AES_key();
    split_by_eight_for_aes_serp_aes(input_arr, p, str_len);
    p += 8;
  }
  rest_keys();
}

void decrypt_with_aes_serpent_aes(String ct) {
  back_keys();
  clear_variables();
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  int count = 0;
  bool ch = false;
  while (ct_len > ext) {
    if (count % 2 == 1 && count != 0)
      ch = true;
    else {
      ch = false;
      incr_AES_key();
      incr_serp_key();
      incr_second_AES_key();
    }
    split_dec_for_aes_serp_aes(ct_array, ct_len, 0 + ext, ch, true);
    ext += 32;
    count++;
  }
  rest_keys();
}

// AES + Serpent + AES (Above)

// Blowfish + Serpent (Below)

void split_by_eight_for_bl_and_serp(char plntxt[], int k, int str_len) {
  char plt_data[] = {
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
    plt_data[i] = plntxt[i + k];
  }
  /*
  Serial.println("\nInput");
  for (int i = 0; i < 8; i++){
    Serial.print(plt_data[i]);
    Serial.print(" ");
  }
  */
  unsigned char t_encr[8];
  for (int i = 0; i < 8; i++) {
    t_encr[i] = (unsigned char) plt_data[i];
  }
  /*
  Serial.println("\nChar");
  for (int i = 0; i < 8; i++){
    Serial.print(t_encr[i]);
    Serial.print(" ");
  }
  */
  blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
  blowfish.Encrypt(t_encr, t_encr, sizeof(t_encr));
  char encr_for_serp[16];
  for (int i = 0; i < 8; i++) {
    encr_for_serp[i] = char(int(t_encr[i]));
  }
  /*
  Serial.println("\nEncrypted");
  for (int i = 0; i < 8; i++){
    Serial.print(t_encr[i]);
    Serial.print(" ");
  }
  */
  for (int i = 8; i < 16; i++) {
    encr_for_serp[i] = trng_word() % 256;
  }

  int tmp_s[16];
  for (int i = 0; i < 16; i++) {
    tmp_s[i] = encr_for_serp[i];
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

    for (int i = 0; i < 16; i++) {
      ct2.b[i] = tmp_s[i];
    }
    serpent_encrypt(ct2.b, & skey, SERPENT_ENCRYPT);
    /*
    for (int i = 0; i < 16; i++) {
      if (ct2.b[i] < 16)
        Serial.print("0");
      Serial.print(ct2.b[i], HEX);
    }
  */
  }
  for (int i = 0; i < 16; i++) {
    if (ct2.b[i] < 16)
      dec_st += "0";
    dec_st += String(ct2.b[i], HEX);
  }
}

void split_for_dec_bl_and_serp(char ct[], int ct_len, int p) {
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

    unsigned char dbl[8];
    for (int i = 0; i < 8; i++) {
      dbl[i] = (unsigned char) int(ct2.b[i]);
    }
    /*
    Serial.println("\nConv for blowfish");
    for (int i = 0; i < 8; i++){\
      Serial.print(dbl[i]);
      Serial.print(" ");
    }
    Serial.println();
    */
    blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
    blowfish.Decrypt(dbl, dbl, sizeof(dbl));
    /*
    Serial.println("\nDecr by blowfish");
    for (int i = 0; i < 8; i++){\
      Serial.print(int(dbl[i]));
      Serial.print(" ");
    }
    Serial.println();
    */
    if (decract < 4) {
      for (i = 0; i < 8; i++) {
        if (dbl[i] < 0x10)
          dec_tag += 0;
        dec_tag += String(dbl[i], HEX);
      }
    } else {
      for (i = 0; i < 8; ++i) {
        dec_st += (char(dbl[i]));
      }
    }
    decract++;
  }
}

void encr_hash_for_blowfish_serpent(String input) {
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
    incr_Blwfsh_key();
    incr_serp_key();
    split_by_eight_for_bl_and_serp(hmacchar, p, 100);
    p += 8;
  }
}

void encrypt_with_blowfish_serpent(String input) {
  back_keys();
  clear_variables();
  encr_hash_for_blowfish_serpent(input);
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  int p = 0;
  while (str_len > p + 1) {
    incr_Blwfsh_key();
    incr_serp_key();
    split_by_eight_for_bl_and_serp(input_arr, p, str_len);
    p += 8;
  }
  rest_keys();
}

void decrypt_with_blowfish_serpent(String ct) {
  back_keys();
  clear_variables();
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  int count = 0;
  while (ct_len > ext) {
    incr_Blwfsh_key();
    incr_serp_key();
    split_for_dec_bl_and_serp(ct_array, ct_len, 0 + ext);
    ext += 32;
  }
  rest_keys();
}

// Blowfish + Serpent (Above)

// AES + Serpent (Below)

void split_by_eight_for_AES_serp(char plntxt[], int k, int str_len) {
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
  for (int i = 8; i < 16; i++) {
    res[i] = trng_word() % 256;
  }
  /*
   for (int i = 0; i < 8; i++){
     Serial.print(res[i]);
  }
  Serial.println();
  */
  encr_AES_for_aes_srp(res);
}

void encr_AES_for_aes_srp(char t_enc[]) {
  uint8_t text[16];
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
  uint32_t key_bit[3] = {
    128,
    192,
    256
  };
  aes_context ctx;
  aes_set_key( & ctx, AES_key, key_bit[m]);
  aes_encrypt_block( & ctx, cipher_text, text);
  /*
  for (int i = 0; i < 16; i++) {
    Serial.printf("%02x", cipher_text[i]);
  }
  */
  char L_half[16];
  for (int i = 0; i < 8; i++) {
    L_half[i] = cipher_text[i];
  }
  char R_half[16];
  for (int i = 0; i < 8; i++) {
    R_half[i] = cipher_text[i + 8];
  }
  for (int i = 8; i < 16; i++) {
    L_half[i] = trng_word() % 256;
    R_half[i] = trng_word() % 256;
  }
  encr_serp_for_aes_srp(L_half, false);
  encr_serp_for_aes_srp(R_half, true);
}

void encr_serp_for_aes_srp(char res[], bool snd) {
  int tmp_s[16];
  for (int i = 0; i < 16; i++) {
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
  uint32_t * p;

  for (b = 0; b < 1; b++) {
    hex2bin(key);

    // set key
    memset( & skey, 0, sizeof(skey));
    p = (uint32_t * ) & skey.x[0][0];

    serpent_setkey( & skey, key);

    for (int i = 0; i < 16; i++) {
      ct2.b[i] = tmp_s[i];
    }
    serpent_encrypt(ct2.b, & skey, SERPENT_ENCRYPT);
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

void split_dec_for_aes_serp(char ct[], int ct_len, int p, bool ch) {
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
    if (ch == false) {
      for (int i = 0; i < 8; i++) {
        tmp_st[i] = char(ct2.b[i]);
      }
    }
    if (ch == true) {
      decr_AES_for_aes_serp(ct2.b);
    }
  }
}

void decr_AES_for_aes_serp(byte sh[]) {
  uint8_t ret_text[16];
  for (int i = 0; i < 8; i++) {
    ret_text[i] = tmp_st[i];
  }
  for (int i = 0; i < 8; i++) {
    ret_text[i + 8] = sh[i];
  }
  uint8_t cipher_text[16] = {
    0
  };
  for (int i = 0; i < 16; i++) {
    int c = int(ret_text[i]);
    cipher_text[i] = c;
  }
  uint32_t key_bit[3] = {
    128,
    192,
    256
  };
  int i = 0;
  aes_context ctx;
  aes_set_key( & ctx, AES_key, key_bit[m]);
  aes_decrypt_block( & ctx, ret_text, cipher_text);
  if (decract < 4) {
    for (i = 0; i < 8; i++) {
      if (ret_text[i] < 0x10)
        dec_tag += 0;
      dec_tag += String(ret_text[i], HEX);
    }
  } else {
    for (i = 0; i < 8; ++i) {
      dec_st += (char(ret_text[i]));
    }
  }
  decract++;
}

void encr_hash_for_aes_serpent(String input) {
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
    incr_AES_key();
    incr_serp_key();
    incr_second_AES_key();
    split_by_eight_for_AES_serp(hmacchar, p, 100);
    p += 8;
  }
}

void encrypt_with_aes_serpent(String input) {
  back_keys();
  clear_variables();
  encr_hash_for_aes_serpent(input);
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  int p = 0;
  while (str_len > p + 1) {
    incr_AES_key();
    incr_serp_key();
    incr_second_AES_key();
    split_by_eight_for_AES_serp(input_arr, p, str_len);
    p += 8;
  }
  rest_keys();
}

void decrypt_with_aes_serpent(String ct) {
  back_keys();
  clear_variables();
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  int count = 0;
  bool ch = false;
  while (ct_len > ext) {
    if (count % 2 == 1 && count != 0)
      ch = true;
    else {
      ch = false;
      incr_AES_key();
      incr_serp_key();
      incr_second_AES_key();
    }
    split_dec_for_aes_serp(ct_array, ct_len, 0 + ext, ch);
    ext += 32;
    count++;
  }
  rest_keys();
}

// AES + Serpent (Above)

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
  for (int i = 8; i < 16; i++) {
    res[i] = trng_word() % 256;
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

    for (int i = 0; i < 16; i++) {
      ct2.b[i] = tmp_s[i];
    }
    serpent_encrypt(ct2.b, & skey, SERPENT_ENCRYPT);
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
    incr_serp_key();
    split_by_eight_for_serp_only(hmacchar, p, 100);
    p += 8;
  }
}

void encrypt_with_serpent_only(String input) {
  back_keys();
  clear_variables();
  encr_hash_for_serpent_only(input);
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  int p = 0;
  while (str_len > p + 1) {
    incr_serp_key();
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
    incr_serp_key();
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
  for (int i = 4; i < 8; i++) {
    res[i] = trng_word() % 256;
  }
  encr_TDES(res);
}

void encr_TDES(byte inp_for_tdes[]) {
  byte out_of_tdes[8];
  des.tripleEncrypt(out_of_tdes, inp_for_tdes, des_key);
  /*
  for(int i = 0; i<8; i++){
    if(out_of_tdes[i]<16)
    Serial.print("0");
    Serial.print(out_of_tdes[i],HEX);
  }
  */
  for (int i = 0; i < 8; i++) {
    if (out_of_tdes[i] < 16)
      dec_st += "0";
    dec_st += String(out_of_tdes[i], HEX);
  }
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
    if (decract < 8) {
      for (int i = 0; i < 4; i++) {
        if (decr_text[i] < 0x10)
          dec_tag += 0;
        dec_tag += String(decr_text[i], HEX);
      }
    } else {
      for (int i = 0; i < 4; ++i) {
        dec_st += (char(decr_text[i]));
      }
    }
    decract++;
  }
}

void encr_hash_for_tdes_only(String input) {
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
  for (int i = 0; i < 8; i++) {
    incr_des_key();
    split_by_four_for_encr_tdes(hmacchar, p, 100);
    p += 4;
  }
}

void encrypt_with_tdes_only(String input) {
  back_keys();
  clear_variables();
  encr_hash_for_tdes_only(input);
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  int p = 0;
  while (str_len > p + 1) {
    incr_des_key();
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
    incr_des_key();
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

void OnPress(int key) {
  prsd_key = key;
  usb_keyb_inp = true;
}

void set_stuff_for_input(String blue_inscr) {
  curr_key = 65;
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  tft.setCursor(2, 0);
  tft.print("Char'");
  tft.setCursor(74, 0);
  tft.print("'");
  disp();
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  tft.setTextColor(current_inact_clr);
  tft.print(blue_inscr);
  tft.fillRect(155, 0, 4, 128, stripe_on_the_right_and_oth_opts_color);
}

void set_stuff_for_input_with_length(String blue_inscr) {
  curr_key = 65;
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  tft.setCursor(2, 0);
  tft.print("Char'");
  tft.setCursor(74, 0);
  tft.print("'");
  disp();
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  tft.setTextColor(current_inact_clr);
  tft.print(blue_inscr);
  tft.fillRect(155, 0, 4, 128, stripe_on_the_right_and_oth_opts_color);
  disp_length_panel();
}

void disp_length_panel(){
  tft.fillRect(0, 114, 160, 14, 0xe73c);
  tft.setTextColor(0x2145);
  tft.setTextSize(1);
  tft.setCursor(10,117);
  tft.print("Length:0");
}

void check_bounds_and_change_char() {
  if (curr_key < 32)
    curr_key = 126;

  if (curr_key > 126)
    curr_key = 32;
  curr_key = keyboard_input.charAt(keyboard_input.length() - 1);
}

void disp() {
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  tft.fillRect(62, 0, 10, 16, 0x0000);
  tft.setCursor(62, 0);
  tft.print(char(curr_key));
  tft.setTextColor(0x07e0);
  String hexstr;
  if (curr_key < 16)
    hexstr += 0;
  hexstr += String(curr_key, HEX);
  hexstr.toUpperCase();
  tft.fillRect(125, 0, 22, 14, 0x0000);
  tft.setCursor(125, 0);
  tft.print(hexstr);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 32);
  tft.print(keyboard_input);
}

void disp_stars() {
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  tft.fillRect(62, 0, 10, 16, 0x0000);
  tft.setCursor(62, 0);
  tft.print(char(curr_key));
  tft.setTextColor(0x07e0);
  String hexstr;
  if (curr_key < 16)
    hexstr += 0;
  hexstr += String(curr_key, HEX);
  hexstr.toUpperCase();
  tft.fillRect(125, 0, 22, 14, 0x0000);
  tft.setCursor(125, 0);
  tft.print(hexstr);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 32);
  int plnt = keyboard_input.length();
  String stars = "";
  for (int i = 0; i < plnt; i++) {
    stars += "*";
  }
  tft.print(stars);
}


void encdr_and_keyb_input() {
  finish_input = false;
  usb_keyb_inp = false;
  while (finish_input == false) {
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;
      if (prsd_key == 127) { // Backspace
        if (keyboard_input.length() > 0)
          keyboard_input.remove(keyboard_input.length() - 1, 1);
        //Serial.println(keyboard_input);
        tft.fillRect(0, 32, 155, 96, 0x0000);
        //Serial.println(keyboard_input);
        disp();
      }

      if (prsd_key > 31 && prsd_key < 127) {
        curr_key = prsd_key;
        keyboard_input += char(curr_key);
        //Serial.println(keyboard_input);
        disp();
      }

      if (prsd_key == 27) {
        act = false;
        finish_input = true;
      }

      if (prsd_key == 10) {
        finish_input = true;
      }

      if (prsd_key == 215) {
        curr_key++;
        disp();
        if (curr_key < 32)
          curr_key = 126;

        if (curr_key > 126)
          curr_key = 32;
      }

      if (prsd_key == 216) {
        curr_key--;
        disp();
        if (curr_key < 32)
          curr_key = 126;

        if (curr_key > 126)
          curr_key = 32;
      }

      if (prsd_key == 218) {
        keyboard_input += char(curr_key);
        //Serial.println(keyboard_input);
        disp();
      }

      if (prsd_key == 217) {
        if (keyboard_input.length() > 0)
          keyboard_input.remove(keyboard_input.length() - 1, 1);
        //Serial.println(keyboard_input);
        tft.fillRect(0, 32, 155, 96, 0x0000);
        //Serial.println(keyboard_input);
        disp();
      }
      
      if (prsd_key == 212) {
        keyboard_input = "";
        //Serial.println(keyboard_input);
        tft.fillRect(0, 32, 155, 96, 0x0000);
        //Serial.println(keyboard_input);
        disp();
      }
      //Serial.println(prsd_key);
    }
    delayMicroseconds(400);
  }
}

void encdr_and_keyb_input_with_length() {
  finish_input = false;
  usb_keyb_inp = false;
  while (finish_input == false) {
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;
      if (prsd_key == 127) { // Backspace
        if (keyboard_input.length() > 0)
          keyboard_input.remove(keyboard_input.length() - 1, 1);
        //Serial.println(keyboard_input);
        tft.fillRect(0, 32, 155, 82, 0x0000);
        //Serial.println(keyboard_input);
        disp();
      }

      if (prsd_key > 31 && prsd_key < 127) {
        curr_key = prsd_key;
        keyboard_input += char(curr_key);
        //Serial.println(keyboard_input);
        disp();
      }

      if (prsd_key == 27) {
        act = false;
        finish_input = true;
      }

      if (prsd_key == 10) {
        finish_input = true;
      }

      if (prsd_key == 215) {
        curr_key++;
        disp();
        if (curr_key < 32)
          curr_key = 126;

        if (curr_key > 126)
          curr_key = 32;
      }

      if (prsd_key == 216) {
        curr_key--;
        disp();
        if (curr_key < 32)
          curr_key = 126;

        if (curr_key > 126)
          curr_key = 32;
      }

      if (prsd_key == 218) {
        keyboard_input += char(curr_key);
        //Serial.println(keyboard_input);
        disp();
      }

      if (prsd_key == 217) {
        if (keyboard_input.length() > 0)
          keyboard_input.remove(keyboard_input.length() - 1, 1);
        //Serial.println(keyboard_input);
        tft.fillRect(0, 32, 155, 82, 0x0000);
        //Serial.println(keyboard_input);
        disp();
      }
      
      if (prsd_key == 212) {
        keyboard_input = "";
        //Serial.println(keyboard_input);
        tft.fillRect(0, 32, 155, 82, 0x0000);
        //Serial.println(keyboard_input);
        disp();
      }
      //Serial.println(prsd_key);
      int inpl = keyboard_input.length();
      if (inpl > 260){
        tft.fillRect(0, 114, 160, 14, 0xe73c);
        tft.setTextColor(0x2145);
        tft.setTextSize(1);
        tft.setCursor(10,117);
        tft.print("Length:");
      }
      tft.fillRect(52, 117, 18, 8, 0xe73c);
      tft.setTextColor(0x2145);
      tft.setCursor(52,117);
      tft.print(inpl);
    }
    delayMicroseconds(400);
  }
}

void star_encdr_and_keyb_input() {
  finish_input = false;
  usb_keyb_inp = false;
  while (finish_input == false) {
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;
      if (prsd_key == 127) {
        if (keyboard_input.length() > 0)
          keyboard_input.remove(keyboard_input.length() - 1, 1);
        //Serial.println(keyboard_input);
        tft.fillRect(0, 32, 155, 96, 0x0000);
        //Serial.println(keyboard_input);
        disp_stars();
      }

      if (prsd_key > 31 && prsd_key < 127) {
        curr_key = prsd_key;
        keyboard_input += char(curr_key);
        //Serial.println(keyboard_input);
        disp_stars();
      }

      if (prsd_key == 27) {
        act = false;
        finish_input = true;
      }

      if (prsd_key == 10) {
        finish_input = true;
      }

      if (prsd_key == 215) {
        curr_key++;
        disp_stars();
        if (curr_key < 32)
          curr_key = 126;

        if (curr_key > 126)
          curr_key = 32;
      }

      if (prsd_key == 216) {
        curr_key--;
        disp_stars();
        if (curr_key < 32)
          curr_key = 126;

        if (curr_key > 126)
          curr_key = 32;
      }

      if (prsd_key == 218) {
        keyboard_input += char(curr_key);
        //Serial.println(keyboard_input);
        disp_stars();
      }

      if (prsd_key == 217) {
        if (keyboard_input.length() > 0)
          keyboard_input.remove(keyboard_input.length() - 1, 1);
        //Serial.println(keyboard_input);
        tft.fillRect(0, 32, 155, 96, 0x0000);
        //Serial.println(keyboard_input);
        disp_stars();
      }

      if (prsd_key == 212) {
        keyboard_input = "";
        //Serial.println(keyboard_input);
        tft.fillRect(0, 32, 155, 96, 0x0000);
        //Serial.println(keyboard_input);
        disp();
      }
      
    }
    delayMicroseconds(400);
  }
}

// Functions that work with files in LittleFS (Below)

void write_to_file_with_overwrite(String filename, String content) {
  int filename_len = filename.length() + 1;
  char filename_array[filename_len];
  filename.toCharArray(filename_array, filename_len);
  SD.remove(filename_array);
  File testFile = SD.open(filename_array, FILE_WRITE);
  if (testFile) {
    //Serial.println("Write file content!");
    testFile.print(content);

    testFile.close();
  } else {
    //Serial.println("Problem on create file!");
  }
}

String read_file(String filename) {
  int filename_len = filename.length() + 1;
  char filename_array[filename_len];
  filename.toCharArray(filename_array, filename_len);
  File testFile = SD.open(filename_array, "r");
  String file_content;
  if (testFile) {
    //Serial.println("Read file content!");
    file_content = testFile.readString();
    //Serial.println(testFile.readString());
    testFile.close();
  } else {
    //Serial.println("Problem on read file!");
    file_content = "-1";
  }
  return file_content;
}

void delete_file(String filename) {
  int filename_len = filename.length() + 1;
  char filename_array[filename_len];
  filename.toCharArray(filename_array, filename_len);
  SD.remove(filename_array);
}

void draw_flower_pattern(){
  tft.fillScreen(59031);
  for (int i = 0; i < 56; i++) {
    for (int j = 0; j < 56; j++) {
      tft.drawPixel(i + 24, j + 8, flower_pattern[i][j]);
    }
  }
  for (int i = 0; i < 56; i++) {
    for (int j = 0; j < 56; j++) {
      tft.drawPixel(i + 80, j + 8, flower_pattern[55 - i][j]);
    }
  }
  for (int i = 0; i < 56; i++) {
    for (int j = 0; j < 56; j++) {
      tft.drawPixel(i + 24, j + 64, flower_pattern[i][55 - j]);
    }
  }
  for (int i = 0; i < 56; i++) {
    for (int j = 0; j < 56; j++) {
      tft.drawPixel(i + 80, j + 64, flower_pattern[55 - i][55 - j]);
    }
  }
}


void typing_inscription(){
  draw_flower_pattern();
  tft.setCursor(3, 3);
  tft.setTextColor(0x09E5);
  tft.print("Typing");
}


// Functions for Logins (Below)

void select_login(byte what_to_do_with_it) {
  // 0 - Add login
  // 1 - Edit login
  // 2 - Delete login
  // 3 - View login
  delay(DELAY_FOR_SLOTS);
  curr_key = 1;
  usb_keyb_inp = false;
  header_for_select_login(what_to_do_with_it);
  display_title_from_login_without_integrity_verification();
  bool continue_to_next = false;
  while (continue_to_next == false) {
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;

      if (prsd_key == 215)
        curr_key++;

      if (prsd_key == 216)
        curr_key--;

      if (curr_key < 1)
        curr_key = MAX_NUM_OF_RECS;

      if (curr_key > MAX_NUM_OF_RECS)
        curr_key = 1;

      if (prsd_key == 10) { // Enter
        int chsn_slot = curr_key;
        if (what_to_do_with_it == 0) {
          byte inptsrc = input_source_for_data_in_flash();
          if (inptsrc == 1)
            add_login_from_keyboard_and_encdr(chsn_slot);
          if (inptsrc == 2)
            add_login_from_serial(chsn_slot);
        }
        if (what_to_do_with_it == 1) {
          byte inptsrc = input_source_for_data_in_flash();
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          if (inptsrc == 1)
            edit_login_from_keyboard_and_encdr(chsn_slot);
          if (inptsrc == 2)
            edit_login_from_serial(chsn_slot);
        }
        if (what_to_do_with_it == 2) {
          delete_login(chsn_slot);
        }
        if (what_to_do_with_it == 3) {
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          view_login(chsn_slot);
        }
        if (what_to_do_with_it == 4) {
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

      if (prsd_key == 27) {
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
  tft.setTextSize(1);
  if (what_to_do_with_it == 0){
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add Login to Slot " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 1){
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Edit Login " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 2){
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Delete Login " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation_for_del();
  }
  if (what_to_do_with_it == 3){
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View Login " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 4){
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Type Login " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
}

void display_title_from_login_without_integrity_verification() {
  tft.setTextSize(1);
  String encrypted_title = read_file("/L" + String(curr_key) + "_ttl");
  if (encrypted_title == "-1") {
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 20);
  } else {
    clear_variables();
    decrypt_tag = false;
    decrypt_with_TDES_AES_Blowfish_Serp(encrypted_title);
    tft.setTextColor(0xffff);
    disp_centered_text(dec_st, 20);
  }
}

void add_login_from_keyboard_and_encdr(int chsn_slot) {
  enter_title_for_login(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void enter_title_for_login(int chsn_slot) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Title");
  encdr_and_keyb_input();
  if (act == true) {
    enter_username_for_login(chsn_slot, keyboard_input);
  }
  return;
}

void enter_username_for_login(int chsn_slot, String entered_title) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Username");
  encdr_and_keyb_input();
  if (act == true) {
    enter_password_for_login(chsn_slot, entered_title, keyboard_input);
  }
  return;
}

void enter_password_for_login(int chsn_slot, String entered_title, String entered_username) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Password");
  encdr_and_keyb_input();
  if (act == true) {
    enter_website_for_login(chsn_slot, entered_title, entered_username, keyboard_input);
  }
  return;
}

void enter_website_for_login(int chsn_slot, String entered_title, String entered_username, String entered_password) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Website");
  encdr_and_keyb_input();
  if (act == true) {
    write_login_to_flash(chsn_slot, entered_title, entered_username, entered_password, keyboard_input);
  }
  return;
}

void add_login_from_serial(int chsn_slot) {
  get_title_for_login_from_serial(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void get_title_for_login_from_serial(int chsn_slot) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Title");
    Serial.println("\nPaste the title here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    get_username_for_login_from_serial(chsn_slot, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_username_for_login_from_serial(int chsn_slot, String entered_title) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Username");
    Serial.println("\nPaste the username here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    get_password_for_login_from_serial(chsn_slot, entered_title, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_password_for_login_from_serial(int chsn_slot, String entered_title, String entered_username) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Password");
    Serial.println("\nPaste the password here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    get_website_for_login_from_serial(chsn_slot, entered_title, entered_username, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_website_for_login_from_serial(int chsn_slot, String entered_title, String entered_username, String entered_password) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Website");
    Serial.println("\nPaste the website here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    write_login_to_flash(chsn_slot, entered_title, entered_username, entered_password, Serial.readString());
    cont_to_next = true;
    break;
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
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Adding Login");
  tft.setCursor(0, 10);
  tft.print("To The slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 20);
  tft.print("Please wait for a while.");
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_title);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_ttl", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_username);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_usn", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_password);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_psw", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_website);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_wbs", dec_st);
  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(entered_title + entered_username + entered_password + entered_website);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void update_login_and_tag(int chsn_slot, String new_password) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Editing login in the slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");

  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(new_password);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_psw", dec_st);

  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_ttl"));
  String decrypted_title = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_usn"));
  String decrypted_username = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_wbs"));
  String decrypted_website = dec_st;

  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(decrypted_title + decrypted_username + new_password + decrypted_website);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void edit_login_from_keyboard_and_encdr(int chsn_slot) {
  if (read_file("/L" + String(chsn_slot) + "_psw") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Get Back", 120);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_psw"));
    String old_password = dec_st;
    act = true;
    clear_variables();
    set_stuff_for_input("Edit Password");
    keyboard_input = old_password;
    disp();
    encdr_and_keyb_input();
    if (act == true) {
      update_login_and_tag(chsn_slot, keyboard_input);
    }
  }
  return;
}

void edit_login_from_serial(int chsn_slot) {
  if (read_file("/L" + String(chsn_slot) + "_psw") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Get Back", 120);
    press_any_key_to_continue();
  } else {
    bool cont_to_next = false;
    while (cont_to_next == false) {
      disp_paste_smth_inscr("New Password");
      Serial.println("\nPaste new password here:");
      bool canc_op = false;
      while (!Serial.available()) {
        myusb.Task();
        if (usb_keyb_inp == true) {
          usb_keyb_inp = false;
          canc_op = true;
          break;
        }
        delayMicroseconds(400);
      }
      if (canc_op == true)
        break;
      update_login_and_tag(chsn_slot, Serial.readString());
      cont_to_next = true;
      break;
    }
  }
  return;
}

void delete_login(int chsn_slot) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Deleting login from the slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  delete_file("/L" + String(chsn_slot) + "_tag");
  delete_file("/L" + String(chsn_slot) + "_ttl");
  delete_file("/L" + String(chsn_slot) + "_usn");
  delete_file("/L" + String(chsn_slot) + "_psw");
  delete_file("/L" + String(chsn_slot) + "_wbs");
  clear_variables();
  call_main_menu();
  return;
}

void view_login(int chsn_slot) {
  if (read_file("/L" + String(chsn_slot) + "_ttl") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Get Back", 120);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_ttl"));
    String decrypted_title = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_usn"));
    String decrypted_username = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_psw"));
    String decrypted_password = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_wbs"));
    String decrypted_website = dec_st;
    clear_variables();
    decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_tag"));
    dec_st = decrypted_title + decrypted_username + decrypted_password + decrypted_website;
    bool login_integrity = verify_integrity();

    if (login_integrity == true) {
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
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
      tft.fillRect(0, 118, 160, 14, 0x0000);
      tft.fillRect(155, 0, 4, 128, current_inact_clr);
      disp_centered_text(succs_ver_inscr, 120);
    } else {
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
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
      tft.fillRect(0, 118, 160, 14, 0x0000);
      tft.fillRect(155, 0, 4, 128, five_six_five_red_color);
      disp_centered_text(faild_ver_inscr, 120);
    }
    
    act = false;
    up_arrow_to_print();
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
  if (read_file("/L" + String(chsn_slot) + "_ttl") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Get Back", 120);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_ttl"));
    String decrypted_title = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_usn"));
    String decrypted_username = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_psw"));
    String decrypted_password = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_wbs"));
    String decrypted_website = dec_st;
    clear_variables();
    decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_tag"));
    dec_st = decrypted_title + decrypted_username + decrypted_password + decrypted_website;
    bool login_integrity = verify_integrity();

    if (login_integrity == true) {
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 35);
      
      disp_centered_text("to type \"Website\"", 45);
      act = false;
      up_arrow_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(decrypted_website);
      }
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 35);
      
      disp_centered_text("to type \"Username\"", 45);
      act = false;
      up_arrow_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(decrypted_username);
      }
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 35);
      
      disp_centered_text("to type \"Password\"", 45);
      act = false;
      up_arrow_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(decrypted_password);
      }
    } else {
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setTextColor(five_six_five_red_color);
      disp_centered_text("Integrity", 65);
      disp_centered_text("Verification", 85);
      disp_centered_text("Failed!!!", 105);
      tft.setTextSize(1);
      tft.setTextColor(0xffff);
      disp_centered_text("Press Any Key", 110);   disp_centered_text("To Cancel", 120);
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
  usb_keyb_inp = false;
  header_for_select_credit_card(what_to_do_with_it);
  display_title_from_credit_card_without_integrity_verification();
  bool continue_to_next = false;
  while (continue_to_next == false) {
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;

      if (prsd_key == 215)
        curr_key++;

      if (prsd_key == 216)
        curr_key--;

      if (curr_key < 1)
        curr_key = MAX_NUM_OF_RECS;

      if (curr_key > MAX_NUM_OF_RECS)
        curr_key = 1;

      if (prsd_key == 10) { // Enter
        int chsn_slot = curr_key;
        if (what_to_do_with_it == 0) {
          byte inptsrc = input_source_for_data_in_flash();
          if (inptsrc == 1)
            add_credit_card_from_keyboard_and_encdr(chsn_slot);
          if (inptsrc == 2)
            add_credit_card_from_serial(chsn_slot);
        }
        if (what_to_do_with_it == 1) {
          byte inptsrc = input_source_for_data_in_flash();
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          if (inptsrc == 1)
            edit_credit_card_from_keyboard_and_encdr(chsn_slot);
          if (inptsrc == 2)
            edit_credit_card_from_serial(chsn_slot);
        }
        if (what_to_do_with_it == 2) {
          delete_credit_card(chsn_slot);
        }
        if (what_to_do_with_it == 3) {
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          view_credit_card(chsn_slot);
        }
        if (what_to_do_with_it == 4) {
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

      if (prsd_key == 27) {
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
  tft.setTextSize(1);
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
  tft.setTextSize(1);
  String encrypted_title = read_file("/C" + String(curr_key) + "_ttl");
  if (encrypted_title == "-1") {
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 20);
  } else {
    clear_variables();
    decrypt_tag = false;
    decrypt_with_TDES_AES_Blowfish_Serp(encrypted_title);
    tft.setTextColor(0xffff);
    disp_centered_text(dec_st, 20);
  }
}

void add_credit_card_from_keyboard_and_encdr(int chsn_slot) {
  enter_title_for_credit_card(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void enter_title_for_credit_card(int chsn_slot) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Title");
  encdr_and_keyb_input();
  if (act == true) {
    enter_cardholder_for_credit_card(chsn_slot, keyboard_input);
  }
  return;
}

void enter_cardholder_for_credit_card(int chsn_slot, String entered_title) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Cardholder Name");
  encdr_and_keyb_input();
  if (act == true) {
    enter_card_number_for_credit_card(chsn_slot, entered_title, keyboard_input);
  }
  return;
}

void enter_card_number_for_credit_card(int chsn_slot, String entered_title, String entered_cardholder) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Card Number");
  encdr_and_keyb_input();
  if (act == true) {
    enter_expiry_for_credit_card(chsn_slot, entered_title, entered_cardholder, keyboard_input);
  }
  return;
}

void enter_expiry_for_credit_card(int chsn_slot, String entered_title, String entered_cardholder, String entered_card_number) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Expiration Date");
  encdr_and_keyb_input();
  if (act == true) {
    enter_cvn_for_credit_card(chsn_slot, entered_title, entered_cardholder, entered_card_number, keyboard_input);
  }
  return;
}

void enter_cvn_for_credit_card(int chsn_slot, String entered_title, String entered_cardholder, String entered_card_number, String entered_expiry) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter CVN");
  encdr_and_keyb_input();
  if (act == true) {
    enter_pin_for_credit_card(chsn_slot, entered_title, entered_cardholder, entered_card_number, entered_expiry, keyboard_input);
  }
  return;
}

void enter_pin_for_credit_card(int chsn_slot, String entered_title, String entered_cardholder, String entered_card_number, String entered_expiry, String entered_cvn) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter PIN");
  encdr_and_keyb_input();
  if (act == true) {
    enter_zip_code_for_credit_card(chsn_slot, entered_title, entered_cardholder, entered_card_number, entered_expiry, entered_cvn, keyboard_input);
  }
  return;
}

void enter_zip_code_for_credit_card(int chsn_slot, String entered_title, String entered_cardholder, String entered_card_number, String entered_expiry, String entered_cvn, String entered_pin) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter ZIP Code");
  encdr_and_keyb_input();
  if (act == true) {
    write_credit_card_to_flash(chsn_slot, entered_title, entered_cardholder, entered_card_number, entered_expiry, entered_cvn, entered_pin, keyboard_input);
  }
  return;
}

void add_credit_card_from_serial(int chsn_slot) {
  get_title_for_credit_card_from_serial(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void get_title_for_credit_card_from_serial(int chsn_slot) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Title");
    Serial.println("\nPaste the title here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    get_cardholder_name_for_credit_card_from_serial(chsn_slot, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_cardholder_name_for_credit_card_from_serial(int chsn_slot, String entered_title) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Cardholder Name");
    Serial.println("\nPaste the cardholder name here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    get_card_number_for_credit_card_from_serial(chsn_slot, entered_title, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_card_number_for_credit_card_from_serial(int chsn_slot, String entered_title, String entered_cardholder) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Card Number");
    Serial.println("\nPaste the card number here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    get_expiration_date_for_credit_card_from_serial(chsn_slot, entered_title, entered_cardholder, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_expiration_date_for_credit_card_from_serial(int chsn_slot, String entered_title, String entered_cardholder, String entered_card_number) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Expiration Date");
    Serial.println("\nPaste the expiration date here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    get_cvn_for_credit_card_from_serial(chsn_slot, entered_title, entered_cardholder, entered_card_number, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_cvn_for_credit_card_from_serial(int chsn_slot, String entered_title, String entered_cardholder, String entered_card_number, String entered_expiry) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("CVN");
    Serial.println("\nPaste the CVN here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    get_pin_for_credit_card_from_serial(chsn_slot, entered_title, entered_cardholder, entered_card_number, entered_expiry, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_pin_for_credit_card_from_serial(int chsn_slot, String entered_title, String entered_cardholder, String entered_card_number, String entered_expiry, String entered_cvn) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("PIN");
    Serial.println("\nPaste the PIN here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    get_zip_code_for_credit_card_from_serial(chsn_slot, entered_title, entered_cardholder, entered_card_number, entered_expiry, entered_cvn, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_zip_code_for_credit_card_from_serial(int chsn_slot, String entered_title, String entered_cardholder, String entered_card_number, String entered_expiry, String entered_cvn, String entered_pin) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("ZIP Code");
    Serial.println("\nPaste the ZIP code here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    write_credit_card_to_flash(chsn_slot, entered_title, entered_cardholder, entered_card_number, entered_expiry, entered_cvn, entered_pin, Serial.readString());
    cont_to_next = true;
    break;
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
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Adding Credit Card");
  tft.setCursor(0, 10);
  tft.print("To The slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 20);
  tft.print("Please wait for a while.");
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_title);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_ttl", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_cardholder);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_hld", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_card_number);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_nmr", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_expiry);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_exp", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_cvn);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_cvn", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_pin);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_pin", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_zip_code);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_zip", dec_st);
  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(entered_title + entered_cardholder + entered_card_number + entered_expiry + entered_cvn + entered_pin + entered_zip_code);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void update_credit_card_and_tag(int chsn_slot, String new_pin) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Editing credit card in the slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(new_pin);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_pin", dec_st);
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_ttl"));
  String decrypted_title = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_hld"));
  String decrypted_cardholder = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_nmr"));
  String decrypted_card_number = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_exp"));
  String decrypted_expiry = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_cvn"));
  String decrypted_cvn = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_zip"));
  String decrypted_zip_code = dec_st;
  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(decrypted_title + decrypted_cardholder + decrypted_card_number + decrypted_expiry + decrypted_cvn + new_pin + decrypted_zip_code);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void edit_credit_card_from_keyboard_and_encdr(int chsn_slot) {
  if (read_file("/C" + String(chsn_slot) + "_pin") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Get Back", 120);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_pin"));
    String old_pin = dec_st;
    act = true;
    clear_variables();
    set_stuff_for_input("Edit PIN");
    keyboard_input = old_pin;
    disp();
    encdr_and_keyb_input();
    if (act == true) {
      update_credit_card_and_tag(chsn_slot, keyboard_input);
    }
  }
  return;
}

void edit_credit_card_from_serial(int chsn_slot) {
  if (read_file("/C" + String(chsn_slot) + "_pin") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Get Back", 120);
    press_any_key_to_continue();
  } else {
    bool cont_to_next = false;
    while (cont_to_next == false) {
      disp_paste_smth_inscr("New PIN");
      Serial.println("\nPaste new PIN here:");
      bool canc_op = false;
      while (!Serial.available()) {
        myusb.Task();
        if (usb_keyb_inp == true) {
          usb_keyb_inp = false;
          canc_op = true;
          break;
        }
        delayMicroseconds(400);
      }
      if (canc_op == true)
        break;
      update_credit_card_and_tag(chsn_slot, Serial.readString());
      cont_to_next = true;
      break;
    }
  }
  return;
}

void delete_credit_card(int chsn_slot) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Deleting credit card from the slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  delete_file("/C" + String(chsn_slot) + "_tag");
  delete_file("/C" + String(chsn_slot) + "_ttl");
  delete_file("/C" + String(chsn_slot) + "_hld");
  delete_file("/C" + String(chsn_slot) + "_nmr");
  delete_file("/C" + String(chsn_slot) + "_exp");
  delete_file("/C" + String(chsn_slot) + "_cvn");
  delete_file("/C" + String(chsn_slot) + "_pin");
  delete_file("/C" + String(chsn_slot) + "_zip");
  clear_variables();
  call_main_menu();
  return;
}

void view_credit_card(int chsn_slot) {
  if (read_file("/C" + String(chsn_slot) + "_ttl") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Get Back", 120);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_ttl"));
    String decrypted_title = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_hld"));
    String decrypted_cardholder = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_nmr"));
    String decrypted_card_number = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_exp"));
    String decrypted_expiry = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_cvn"));
    String decrypted_cvn = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_pin"));
    String decrypted_pin = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_zip"));
    String decrypted_zip_code = dec_st;
    decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_tag"));
    dec_st = decrypted_title + decrypted_cardholder + decrypted_card_number + decrypted_expiry + decrypted_cvn + decrypted_pin + decrypted_zip_code;
    bool credit_card_integrity = verify_integrity();

    if (credit_card_integrity == true) {
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
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
      tft.fillRect(0, 118, 160, 14, 0x0000);
      tft.fillRect(155, 0, 4, 128, current_inact_clr);
      disp_centered_text(succs_ver_inscr, 120);
    } else {
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
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
      tft.fillRect(0, 118, 160, 14, 0x0000);
      tft.fillRect(155, 0, 4, 128, five_six_five_red_color);
      disp_centered_text(faild_ver_inscr, 120);
    }
    act = false;
    up_arrow_to_print();
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
  if (read_file("/C" + String(chsn_slot) + "_ttl") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Get Back", 120);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_ttl"));
    String decrypted_title = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_hld"));
    String decrypted_cardholder = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_nmr"));
    String decrypted_card_number = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_exp"));
    String decrypted_expiry = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_cvn"));
    String decrypted_cvn = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_pin"));
    String decrypted_pin = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_zip"));
    String decrypted_zip_code = dec_st;
    decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_tag"));
    dec_st = decrypted_title + decrypted_cardholder + decrypted_card_number + decrypted_expiry + decrypted_cvn + decrypted_pin + decrypted_zip_code;
    bool credit_card_integrity = verify_integrity();

    if (credit_card_integrity == true) {
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 35);
      
      disp_centered_text("to type \"Cardholder Name\"", 45);
      act = false;
      up_arrow_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(decrypted_cardholder);
      }
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 35);
      
      disp_centered_text("to type \"Card Number\"", 45);
      act = false;
      up_arrow_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(decrypted_card_number);
      }
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 35);
      
      disp_centered_text("to type \"Expiration Date\"", 45);
      act = false;
      up_arrow_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(decrypted_expiry);
      }
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 35);
      
      disp_centered_text("to type \"CVN\"", 45);
      act = false;
      up_arrow_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(decrypted_cvn);
      }
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 35);
      
      disp_centered_text("to type \"PIN\"", 45);
      act = false;
      up_arrow_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(decrypted_pin);
      }
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 35);
      
      disp_centered_text("to type \"ZIP Code\"", 45);
      act = false;
      up_arrow_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(decrypted_zip_code);
      }
    } else {
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setTextColor(five_six_five_red_color);
      disp_centered_text("Integrity", 65);
      disp_centered_text("Verification", 85);
      disp_centered_text("Failed!!!", 105);
      tft.setTextSize(1);
      tft.setTextColor(0xffff);
      disp_centered_text("Press Any Key", 110);   disp_centered_text("To Cancel", 120);
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
  usb_keyb_inp = false;
  header_for_select_note(what_to_do_with_it);
  display_title_from_note_without_integrity_verification();
  bool continue_to_next = false;
  while (continue_to_next == false) {
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;

      if (prsd_key == 215)
        curr_key++;

      if (prsd_key == 216)
        curr_key--;

      if (curr_key < 1)
        curr_key = MAX_NUM_OF_RECS;

      if (curr_key > MAX_NUM_OF_RECS)
        curr_key = 1;

      if (prsd_key == 10) { // Enter
        int chsn_slot = curr_key;
        if (what_to_do_with_it == 0) {
          byte inptsrc = input_source_for_data_in_flash();
          if (inptsrc == 1)
            add_note_from_keyboard_and_encdr(chsn_slot);
          if (inptsrc == 2)
            add_note_from_serial(chsn_slot);
        }
        if (what_to_do_with_it == 1) {
          byte inptsrc = input_source_for_data_in_flash();
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          if (inptsrc == 1)
            edit_note_from_keyboard_and_encdr(chsn_slot);
          if (inptsrc == 2)
            edit_note_from_serial(chsn_slot);
        }
        if (what_to_do_with_it == 2) {
          delete_note(chsn_slot);
        }
        if (what_to_do_with_it == 3) {
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          view_note(chsn_slot);
        }
        if (what_to_do_with_it == 4) {
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

      if (prsd_key == 27) {
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
  tft.setTextSize(1);
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
  tft.setTextSize(1);
  String encrypted_title = read_file("/N" + String(curr_key) + "_ttl");
  if (encrypted_title == "-1") {
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 20);
  } else {
    clear_variables();
    decrypt_tag = false;
    decrypt_with_TDES_AES_Blowfish_Serp(encrypted_title);
    tft.setTextColor(0xffff);
    disp_centered_text(dec_st, 20);
  }
}

void add_note_from_keyboard_and_encdr(int chsn_slot) {
  enter_title_for_note(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void enter_title_for_note(int chsn_slot) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Title");
  encdr_and_keyb_input();
  if (act == true) {
    enter_content_for_note(chsn_slot, keyboard_input);
  }
  return;
}

void enter_content_for_note(int chsn_slot, String entered_title) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Content");
  encdr_and_keyb_input();
  if (act == true) {
    write_note_to_flash(chsn_slot, entered_title, keyboard_input);
  }
  return;
}

void add_note_from_serial(int chsn_slot) {
  get_title_for_note_from_serial(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void get_title_for_note_from_serial(int chsn_slot) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Title");
    Serial.println("\nPaste the title here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    get_content_for_note_from_serial(chsn_slot, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_content_for_note_from_serial(int chsn_slot, String entered_title) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Content");
    Serial.println("\nPaste the content here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    write_note_to_flash(chsn_slot, entered_title, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void write_note_to_flash(int chsn_slot, String entered_title, String entered_content) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Adding Note");
  tft.setCursor(0, 10);
  tft.print("To The slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 20);
  tft.print("Please wait for a while.");
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_title);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/N" + String(chsn_slot) + "_ttl", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_content);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/N" + String(chsn_slot) + "_cnt", dec_st);
  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(entered_title + entered_content);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/N" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void update_note_and_tag(int chsn_slot, String new_content) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Editing note in the slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");

  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(new_content);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/N" + String(chsn_slot) + "_cnt", dec_st);

  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/N" + String(chsn_slot) + "_ttl"));
  String decrypted_title = dec_st;

  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(decrypted_title + new_content);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/N" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void edit_note_from_keyboard_and_encdr(int chsn_slot) {
  if (read_file("/N" + String(chsn_slot) + "_cnt") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Get Back", 120);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/N" + String(chsn_slot) + "_cnt"));
    String old_password = dec_st;
    act = true;
    clear_variables();
    set_stuff_for_input("Edit Note");
    keyboard_input = old_password;
    disp();
    encdr_and_keyb_input();
    if (act == true) {
      update_note_and_tag(chsn_slot, keyboard_input);
    }
  }
  return;
}

void edit_note_from_serial(int chsn_slot) {
  if (read_file("/N" + String(chsn_slot) + "_cnt") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Get Back", 120);
    press_any_key_to_continue();
  } else {
    bool cont_to_next = false;
    while (cont_to_next == false) {
      disp_paste_smth_inscr("New Content");
      Serial.println("\nPaste new content here:");
      bool canc_op = false;
      while (!Serial.available()) {
        myusb.Task();
        if (usb_keyb_inp == true) {
          usb_keyb_inp = false;
          canc_op = true;
          break;
        }
        delayMicroseconds(400);
      }
      if (canc_op == true)
        break;
      update_note_and_tag(chsn_slot, Serial.readString());
      cont_to_next = true;
      break;
    }
  }
  return;
}

void delete_note(int chsn_slot) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Deleting note from the slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  delete_file("/N" + String(chsn_slot) + "_tag");
  delete_file("/N" + String(chsn_slot) + "_ttl");
  delete_file("/N" + String(chsn_slot) + "_cnt");
  clear_variables();
  call_main_menu();
  return;
}

void view_note(int chsn_slot) {
  if (read_file("/N" + String(chsn_slot) + "_ttl") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Get Back", 120);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/N" + String(chsn_slot) + "_ttl"));
    String decrypted_title = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/N" + String(chsn_slot) + "_cnt"));
    String decrypted_content = dec_st;
    clear_variables();
    decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file("/N" + String(chsn_slot) + "_tag"));
    dec_st = decrypted_title + decrypted_content;
    bool note_integrity = verify_integrity();

    if (note_integrity == true) {
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Content:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_content);
      tft.setTextSize(1);
      tft.fillRect(0, 118, 160, 14, 0x0000);
      tft.fillRect(155, 0, 4, 128, current_inact_clr);
      disp_centered_text(succs_ver_inscr, 120);
    } else {
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Content:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_content);
      tft.setTextSize(1);
      tft.fillRect(0, 118, 160, 14, 0x0000);
      tft.fillRect(155, 0, 4, 128, five_six_five_red_color);
      disp_centered_text(faild_ver_inscr, 120);
    }
    act = false;
    up_arrow_to_print();
    if (act == true) {
      Serial.println();
      Serial.print("Title:\"");
      Serial.print(decrypted_title);
      Serial.println("\"");
      Serial.print("Content:\"");
      Serial.print(decrypted_content);
      Serial.println("\"");
      if (note_integrity == true) {
        Serial.println("Integrity Verified Successfully!\n");
      } else {
        Serial.println("Integrity Verification Failed!!!\n");
      }
    }
  }
}

void type_note(int chsn_slot) {
  if (read_file("/N" + String(chsn_slot) + "_ttl") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Get Back", 120);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/N" + String(chsn_slot) + "_ttl"));
    String decrypted_title = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/N" + String(chsn_slot) + "_cnt"));
    String decrypted_content = dec_st;
    clear_variables();
    decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file("/N" + String(chsn_slot) + "_tag"));
    dec_st = decrypted_title + decrypted_content;
    bool note_integrity = verify_integrity();

    if (note_integrity == true) {
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 35);
      
      disp_centered_text("to type \"Note\"", 45);
      act = false;
      up_arrow_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(decrypted_content);
      }
    } else {
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setTextColor(five_six_five_red_color);
      disp_centered_text("Integrity", 65);
      disp_centered_text("Verification", 85);
      disp_centered_text("Failed!!!", 105);
      tft.setTextSize(1);
      tft.setTextColor(0xffff);
      disp_centered_text("Press Any Key", 110);   disp_centered_text("To Cancel", 120);
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
  usb_keyb_inp = false;
  header_for_select_phone_number(what_to_do_with_it);
  display_title_from_phone_number_without_integrity_verification();
  bool continue_to_next = false;
  while (continue_to_next == false) {
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;

      if (prsd_key == 215)
        curr_key++;

      if (prsd_key == 216)
        curr_key--;

      if (curr_key < 1)
        curr_key = MAX_NUM_OF_RECS;

      if (curr_key > MAX_NUM_OF_RECS)
        curr_key = 1;

      if (prsd_key == 10) { // Enter
        int chsn_slot = curr_key;
        if (what_to_do_with_it == 0) {
          byte inptsrc = input_source_for_data_in_flash();
          if (inptsrc == 1)
            add_phone_number_from_keyboard_and_encdr(chsn_slot);
          if (inptsrc == 2)
            add_phone_number_from_serial(chsn_slot);
        }
        if (what_to_do_with_it == 1) {
          byte inptsrc = input_source_for_data_in_flash();
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          if (inptsrc == 1)
            edit_phone_number_from_keyboard_and_encdr(chsn_slot);
          if (inptsrc == 2)
            edit_phone_number_from_serial(chsn_slot);
        }
        if (what_to_do_with_it == 2) {
          delete_phone_number(chsn_slot);
        }
        if (what_to_do_with_it == 3) {
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          view_phone_number(chsn_slot);
        }
        if (what_to_do_with_it == 4) {
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

      if (prsd_key == 27) {
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
  tft.setTextSize(1);
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
  tft.setTextSize(1);
  String encrypted_title = read_file("/P" + String(curr_key) + "_ttl");
  if (encrypted_title == "-1") {
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 20);
  } else {
    clear_variables();
    decrypt_tag = false;
    decrypt_with_TDES_AES_Blowfish_Serp(encrypted_title);
    tft.setTextColor(0xffff);
    disp_centered_text(dec_st, 20);
  }
}

void add_phone_number_from_keyboard_and_encdr(int chsn_slot) {
  enter_title_for_phone_number(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void enter_title_for_phone_number(int chsn_slot) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Title");
  encdr_and_keyb_input();
  if (act == true) {
    enter_phone_number_for_phone_number(chsn_slot, keyboard_input);
  }
  return;
}

void enter_phone_number_for_phone_number(int chsn_slot, String entered_title) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Phone Number");
  encdr_and_keyb_input();
  if (act == true) {
    write_phone_number_to_flash(chsn_slot, entered_title, keyboard_input);
  }
  return;
}

void add_phone_number_from_serial(int chsn_slot) {
  get_title_for_phone_number_from_serial(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void get_title_for_phone_number_from_serial(int chsn_slot) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Title");
    Serial.println("\nPaste the title here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    get_phone_number_for_phone_number_from_serial(chsn_slot, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_phone_number_for_phone_number_from_serial(int chsn_slot, String entered_title) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Phone Number");
    Serial.println("\nPaste the phone number here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    write_phone_number_to_flash(chsn_slot, entered_title, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void write_phone_number_to_flash(int chsn_slot, String entered_title, String entered_phone_number) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Adding Phone Number");
  tft.setCursor(0, 10);
  tft.print("To The slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 20);
  tft.print("Please wait for a while.");
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_title);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/P" + String(chsn_slot) + "_ttl", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_phone_number);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/P" + String(chsn_slot) + "_cnt", dec_st);
  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(entered_title + entered_phone_number);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/P" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void update_phone_number_and_tag(int chsn_slot, String new_phone_number) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Editing phone number in the slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");

  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(new_phone_number);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/P" + String(chsn_slot) + "_cnt", dec_st);

  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/P" + String(chsn_slot) + "_ttl"));
  String decrypted_title = dec_st;

  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(decrypted_title + new_phone_number);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/P" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void edit_phone_number_from_keyboard_and_encdr(int chsn_slot) {
  if (read_file("/P" + String(chsn_slot) + "_cnt") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Get Back", 120);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/P" + String(chsn_slot) + "_cnt"));
    String old_password = dec_st;
    act = true;
    clear_variables();
    set_stuff_for_input("Edit Phone Number");
    keyboard_input = old_password;
    disp();
    encdr_and_keyb_input();
    if (act == true) {
      update_phone_number_and_tag(chsn_slot, keyboard_input);
    }
  }
  return;
}

void edit_phone_number_from_serial(int chsn_slot) {
  if (read_file("/P" + String(chsn_slot) + "_cnt") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Get Back", 120);
    press_any_key_to_continue();
  } else {
    bool cont_to_next = false;
    while (cont_to_next == false) {
      disp_paste_smth_inscr("New Phone Number");
      Serial.println("\nPaste new phone number here:");
      bool canc_op = false;
      while (!Serial.available()) {
        myusb.Task();
        if (usb_keyb_inp == true) {
          usb_keyb_inp = false;
          canc_op = true;
          break;
        }
        delayMicroseconds(400);
      }
      if (canc_op == true)
        break;
      update_phone_number_and_tag(chsn_slot, Serial.readString());
      cont_to_next = true;
      break;
    }
  }
  return;
}

void delete_phone_number(int chsn_slot) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Deleting phone number from the slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  delete_file("/P" + String(chsn_slot) + "_tag");
  delete_file("/P" + String(chsn_slot) + "_ttl");
  delete_file("/P" + String(chsn_slot) + "_cnt");
  clear_variables();
  call_main_menu();
  return;
}

void view_phone_number(int chsn_slot) {
  if (read_file("/P" + String(chsn_slot) + "_ttl") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Get Back", 120);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/P" + String(chsn_slot) + "_ttl"));
    String decrypted_title = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/P" + String(chsn_slot) + "_cnt"));
    String decrypted_phone_number = dec_st;
    clear_variables();
    decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file("/P" + String(chsn_slot) + "_tag"));
    dec_st = decrypted_title + decrypted_phone_number;
    bool phone_number_integrity = verify_integrity();

    if (phone_number_integrity == true) {
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Phone Number:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_phone_number);
      tft.setTextSize(1);
      tft.fillRect(0, 118, 160, 14, 0x0000);
      tft.fillRect(155, 0, 4, 128, current_inact_clr);
      disp_centered_text(succs_ver_inscr, 120);
    } else {
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Phone Number:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_phone_number);
      tft.setTextSize(1);
      tft.fillRect(0, 118, 160, 14, 0x0000);
      tft.fillRect(155, 0, 4, 128, five_six_five_red_color);
      disp_centered_text(faild_ver_inscr, 120);
    }
    act = false;
    up_arrow_to_print();
    if (act == true) {
      Serial.println();
      Serial.print("Title:\"");
      Serial.print(decrypted_title);
      Serial.println("\"");
      Serial.print("Phone Number:\"");
      Serial.print(decrypted_phone_number);
      Serial.println("\"");
      if (phone_number_integrity == true) {
        Serial.println("Integrity Verified Successfully!\n");
      } else {
        Serial.println("Integrity Verification Failed!!!\n");
      }
    }
  }
}

void type_phone_number(int chsn_slot) {
  if (read_file("/P" + String(chsn_slot) + "_ttl") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Get Back", 120);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/P" + String(chsn_slot) + "_ttl"));
    String decrypted_title = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/P" + String(chsn_slot) + "_cnt"));
    String decrypted_phone_number = dec_st;
    clear_variables();
    decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file("/P" + String(chsn_slot) + "_tag"));
    dec_st = decrypted_title + decrypted_phone_number;
    bool phone_number_integrity = verify_integrity();

    if (phone_number_integrity == true) {
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 35);
      
      disp_centered_text("to type \"Phone Number\"", 45);
      act = false;
      up_arrow_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(decrypted_phone_number);
      }
    } else {
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setTextColor(five_six_five_red_color);
      disp_centered_text("Integrity", 65);
      disp_centered_text("Verification", 85);
      disp_centered_text("Failed!!!", 105);
      tft.setTextSize(1);
      tft.setTextColor(0xffff);
      disp_centered_text("Press Any Key", 110);   disp_centered_text("To Cancel", 120);
      press_any_key_to_continue();
    }
  }
}

// Functions for Phone Number (Above)

// Functions that work with files in LittleFS (Above)

void press_any_key_to_continue() {
  bool break_the_loop = false;
  while (break_the_loop == false) {
    myusb.Task();
    if (usb_keyb_inp == true) {
      break_the_loop = true;
    }
  }
  delayMicroseconds(400);
}

void up_arrow_to_print() {
  bool break_the_loop = false;
  while (break_the_loop == false) {
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;
      if (prsd_key == 218) { // It used to be the "Tab"
        act = true;
        break_the_loop = true;
      } else
        break_the_loop = true;
    }
    delayMicroseconds(400);
  }

}

void continue_to_unlock() {
  if (EEPROM.read(0) == 0)
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
  encdr_and_keyb_input();
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  print_centered_custom_hebrew_font("Mdbr", -8, colors, 4);
  tft.setTextColor(0xffff);
  disp_centered_text("Setting Master Password", sdown + 10);
  disp_centered_text("Please wait", sdown + 20);
  disp_centered_text("for a while", sdown + 30);
  //Serial.println(keyboard_input);
  String bck = keyboard_input;
  modify_keys();
  keyboard_input = bck;
  set_psswd();
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  print_centered_custom_hebrew_font("Mdbr", -8, colors, 4);
  tft.setTextColor(0xffff);
  disp_centered_text("Master Password Set", sdown + 10);
  disp_centered_text("Successfully", sdown + 20);
  disp_centered_text("Press Any Key", 110);
  disp_centered_text("To Continue", 120);
  press_any_key_to_continue();
  call_main_menu();
  return;
}

void set_psswd() {
  int str_len = keyboard_input.length() + 1;
  char input_arr[str_len];
  keyboard_input.toCharArray(input_arr, str_len);
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
  encr_hash_for_tdes_aes_blf_srp_fl(h);
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

  EEPROM.write(0, 255);
  for (int i = 0; i < 48; i++) {
    EEPROM.write(i + 1, res[i]);
  }
  compute_and_write_encrypted_tag_for_EEPROM_integrity_check();
}

void modify_keys() {
  keyboard_input += kderalgs;
  int str_len = keyboard_input.length() + 1;
  char input_arr[str_len];
  keyboard_input.toCharArray(input_arr, str_len);
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
  tft.setTextColor(0xffff);
  tft.setTextSize(1);
  set_stuff_for_input("Enter Master Password");
  star_encdr_and_keyb_input();
  tft.fillScreen(0x0000);
  print_centered_custom_hebrew_font("Mdbr", -8, colors, 4);
  tft.setTextSize(1);
  disp_centered_text("Unlocking Midbar", sdown + 10);
  disp_centered_text("Please Wait", sdown + 20);
  disp_centered_text("For A While", sdown + 30);
  //Serial.println(keyboard_input);
  String bck = keyboard_input;
  modify_keys();
  keyboard_input = bck;
  bool next_act = hash_psswd();
  clear_variables();
  tft.fillScreen(0x0000);
  if (next_act == true) {
    tft.setTextSize(1);
    print_centered_custom_hebrew_font("Mdbr", -8, colors, 4);
    disp_centered_text("Midbar Unlocked", sdown + 10);
    disp_centered_text("Successfully", sdown + 20);
    disp_centered_text("Press Any Key", 110);
    disp_centered_text("To Continue", 120);
    check_EEPROM_integrity();
    press_any_key_to_continue();
    call_main_menu();
    return;
  } else {
    tft.setTextSize(1);
    print_centered_custom_hebrew_font("Mdbr", -8, colors, 4);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Wrong Password!", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Please Reboot", sdown + 30);
    disp_centered_text("The Device", sdown + 40);
    disp_centered_text("And Try Again", sdown + 50);
    for (;;)
      delay(1000);
  }
}

bool hash_psswd() {
  int str_len = keyboard_input.length() + 1;
  char input_arr[str_len];
  keyboard_input.toCharArray(input_arr, str_len);
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
  back_keys();
  clear_variables();
  String encr_h;
  for (int i = 1; i < 49; i++) {
    if (EEPROM.read(i) < 16)
      encr_h += "0";
    encr_h += String(EEPROM.read(i), HEX);
  }
  decrypt_tag_with_TDES_AES_Blowfish_Serp_fl(encr_h);
  //Serial.println(dec_tag);
  return dec_tag.equals(res_hash);
}

void disp_centered_text(String text, int h) {
  if (text.length() < 27){
    int16_t x1;
    int16_t y1;
    uint16_t width;
    uint16_t height;
    tft.getTextBounds(text, 0, 0, & x1, & y1, & width, & height);
    tft.setCursor((160 - width) / 2, h);
    tft.print(text);
  }
  else{
    tft.setCursor(0, h);
    tft.print(text);
  }
}

// Menu (below)

void disp_button_designation() {
  tft.setTextSize(1);
  tft.setTextColor(0x07e0);
  tft.setCursor(0, 120);
  tft.print("Enter:");
  tft.print("Continue    ");
  tft.setTextColor(five_six_five_red_color);
  tft.print("Esc:");
  tft.print("Back");
}

void disp_button_designation_for_del() {
  tft.setTextSize(1);
  tft.setTextColor(five_six_five_red_color);
  tft.setCursor(0, 120);
  tft.print("Enter:");
  tft.print("Continue    ");
  tft.setTextColor(0x07e0);
  tft.print("Esc:");
  tft.print("Back");
}

void call_main_menu(){
  tft.setRotation(1);
  tft.fillScreen(0x0000);
  print_centered_custom_hebrew_font("Mdbr", -9, colors, 4);
  curr_key = 0;
  usb_keyb_inp = false;
  main_menu(0);
}

void main_menu(int curr_pos) {
  
  tft.setTextSize(1);
  const char * elements_of_menu[] = {
    "Logins In EEPROM",
    "Credit Cards In EEPROM",
    "Logins On SD Card",
    "Credit Cards On SD Card",
    "Notes On SD Card",
    "Phone Numbers On SD Card",
    "Encryption Algorithms",
    "Hash Functions",
    "Other Options"
  };

  for (int i = 0; i < 9; i++) {
    if (curr_pos == i) {
      tft.setTextColor(0xffff);
    } else {
      tft.setTextColor(current_inact_clr);
    }

    disp_centered_text(elements_of_menu[i], sdown + 1 + 10 * i);
  }
}

void input_source_for_data_in_flash_menu(int curr_pos) {
  tft.setTextSize(1);
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("USB Keyboard", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Serial Terminal", sdown + 20);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("USB Keyboard", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Serial Terminal", sdown + 20);
  }
}

byte input_source_for_data_in_flash() {
  byte inpsrc = 0;
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(current_inact_clr);
  disp_centered_text("Choose Input Source", 10);
  curr_key = 0;
  input_source_for_data_in_flash_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;

      if (prsd_key == 218)
        curr_key--;

      if (prsd_key == 217)
        curr_key++;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if (prsd_key == 10) {
        if (cont_to_next == false && curr_key == 0) {
          inpsrc = 1;
        }

        if (cont_to_next == false && curr_key == 1) {
          inpsrc = 2;
        }
        cont_to_next = true;
        break;
      }
      if (prsd_key == 27) {
        cont_to_next = true;
        break;
      }
      input_source_for_data_in_flash_menu(curr_key);

    }
    delayMicroseconds(400);
  }
  return inpsrc;
}

void action_for_data_in_flash_menu(int curr_pos) {
  
  tft.setTextSize(1);

  const char* actions[] = {"Add", "Edit", "Delete", "View", "Type"};

  for (int i = 0; i < 5; i++) {
    if (curr_pos == i) {
      tft.setTextColor(0xffff); // Active color
    } else {
      tft.setTextColor(current_inact_clr); // Inactive color
    }

    disp_centered_text(actions[i], sdown + 10 * (i + 1));
  }
}

void action_for_data_in_flash(String menu_title, byte record_type) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(current_inact_clr);
  disp_centered_text(menu_title, 10);
  curr_key = 0;
  record_type-=2;
  usb_keyb_inp = false;
  action_for_data_in_flash_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    delayMicroseconds(400);
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;

      if (prsd_key == 218)
        curr_key--;

      if (prsd_key == 217)
        curr_key++;

      if (curr_key < 0)
        curr_key = 4;

      if (curr_key > 4)
        curr_key = 0;

      if (prsd_key == 10) {
        if (cont_to_next == false && curr_key == 0) {
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

        if (cont_to_next == false && curr_key == 1) {
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

        if (cont_to_next == false && curr_key == 2) {
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

        if (cont_to_next == false && curr_key == 3) {
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

        if (cont_to_next == false && curr_key == 4) {
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
      if (prsd_key == 27) {
        cont_to_next = true;
      }
      action_for_data_in_flash_menu(curr_key);

    }
  }
  call_main_menu();
}

void input_source_for_encr_algs_menu(int curr_pos) {
  tft.setTextSize(1);
  
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("USB Keyboard", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Serial Terminal", sdown + 20);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("USB Keyboard", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Serial Terminal", sdown + 20);
  }
}

void input_source_for_encr_algs(byte record_type) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(current_inact_clr);
  disp_centered_text("Choose Input Source", 10);
  curr_key = 0;
  usb_keyb_inp = false;
  input_source_for_encr_algs_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    delayMicroseconds(400);
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;

      if (prsd_key == 218)
        curr_key--;

      if (prsd_key == 217)
        curr_key++;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if (prsd_key == 10) {

        if (cont_to_next == false && curr_key == 0) {
          if (record_type == 0)
            encr_TDES_AES_BLF_Serp();
          if (record_type == 1)
            encr_blwfsh_aes_serpent_aes();
          if (record_type == 2)
            encr_aes_serpent_aes();
          if (record_type == 3)
            encr_blowfish_serpent();
          if (record_type == 4)
            encr_aes_serpent();
          if (record_type == 5)
            encr_serpent_only();
          if (record_type == 6)
            encr_tdes_only();
          cont_to_next = true;
        }

        if (cont_to_next == false && curr_key == 1) {
          if (record_type == 0)
            encr_TDES_AES_BLF_Serp_from_Serial();
          if (record_type == 1)
            encr_blwfsh_aes_serpent_aes_from_Serial();
          if (record_type == 2)
            encr_aes_serpent_aes_from_Serial();
          if (record_type == 3)
            encr_blowfish_serpent_from_Serial();
          if (record_type == 4)
            encr_aes_serpent_from_Serial();
          if (record_type == 5)
            encr_serpent_only_from_Serial();
          if (record_type == 6)
            encr_tdes_only_from_Serial();
          cont_to_next = true;
        }

      }
      if (prsd_key == 27) {
        cont_to_next = true;
      }
      input_source_for_encr_algs_menu(curr_key);

    }
  }
  call_main_menu();
}

void what_to_do_with_encr_alg_menu(int curr_pos) {
  tft.setTextSize(1);
  
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("Encrypt String", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Decrypt String", sdown + 20);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Encrypt String", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Decrypt String", sdown + 20);
  }
}

void what_to_do_with_encr_alg(String menu_title, byte record_type) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(current_inact_clr);
  disp_centered_text(menu_title, 10);
  curr_key = 0;
  usb_keyb_inp = false;
  what_to_do_with_encr_alg_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    delayMicroseconds(400);
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;

      if (prsd_key == 218)
        curr_key--;

      if (prsd_key == 217)
        curr_key++;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if (prsd_key == 10) {
        if (cont_to_next == false && curr_key == 0) {
          input_source_for_encr_algs(record_type);
          cont_to_next = true;
        }

        if (cont_to_next == false && curr_key == 1) {
          where_to_print_plaintext(record_type);
          cont_to_next = true;
        }
      }
      if (prsd_key == 27) {
        cont_to_next = true;
      }
      what_to_do_with_encr_alg_menu(curr_key);

    }
  }
  call_main_menu();
}

void where_to_print_plaintext_menu(int curr_pos) {
  tft.setTextSize(1);
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("Display", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Serial Terminal", sdown + 20);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Display", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Serial Terminal", sdown + 20);
  }
}

void where_to_print_plaintext(byte record_type) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(current_inact_clr);
  disp_centered_text("Where to print plaintext?", 10);
  curr_key = 0;
  usb_keyb_inp = false;
  where_to_print_plaintext_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    delayMicroseconds(400);
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;

      if (prsd_key == 218)
        curr_key--;

      if (prsd_key == 217)
        curr_key++;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if (prsd_key == 10) {

        if (cont_to_next == false && curr_key == 0) {
          if (record_type == 0)
            decr_TDES_AES_BLF_Serp(true);
          if (record_type == 1)
            decr_blwfsh_aes_serpent_aes(true);
          if (record_type == 2)
            decr_aes_serpent_aes(true);
          if (record_type == 3)
            decr_blowfish_serpent(true);
          if (record_type == 4)
            decr_aes_serpent(true);
          if (record_type == 5)
            decr_serpent_only(true);
          if (record_type == 6)
            decr_tdes_only(true);
          cont_to_next = true;
        }

        if (cont_to_next == false && curr_key == 1) {
          if (record_type == 0)
            decr_TDES_AES_BLF_Serp(false);
          if (record_type == 1)
            decr_blwfsh_aes_serpent_aes(false);
          if (record_type == 2)
            decr_aes_serpent_aes(false);
          if (record_type == 3)
            decr_blowfish_serpent(false);
          if (record_type == 4)
            decr_aes_serpent(false);
          if (record_type == 5)
            decr_serpent_only(false);
          if (record_type == 6)
            decr_tdes_only(false);
          cont_to_next = true;
        }
      }
      if (prsd_key == 27) {
        cont_to_next = true;
      }
      where_to_print_plaintext_menu(curr_key);

    }
  }
  call_main_menu();
}

void encryption_algorithms_menu(int curr_pos) {
  tft.setTextSize(1);

  const char* algorithms[] = {
    "3DES+AES+Blfish+Serp CBC",
    "Blowfish+AES+Serp+AES",
    "AES+Serpent+AES",
    "Blowfish+Serpent",
    "AES+Serpent",
    "Serpent",
    "Triple DES"
  };

  for (int i = 0; i < 7; i++) {
    if (curr_pos == i) {
      tft.setTextColor(0xffff); // Active color
    } else {
      tft.setTextColor(current_inact_clr); // Inactive color
    }

    disp_centered_text(algorithms[i], sdown + 10 * i);
  }
}

void encryption_algorithms() {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(current_inact_clr);
  disp_centered_text("Encryption Algorithms", 10);
  curr_key = 0;
  usb_keyb_inp = false;
  encryption_algorithms_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    delayMicroseconds(400);
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;

      if (prsd_key == 218)
        curr_key--;

      if (prsd_key == 217)
        curr_key++;

      if (curr_key < 0)
        curr_key = 6;

      if (curr_key > 6)
        curr_key = 0;

      if (prsd_key == 10) {
        if (cont_to_next == false && curr_key == 0) {
          what_to_do_with_encr_alg("3DES+AES+Blfish+Serp CBC", curr_key);
          cont_to_next = true;
        }

        if (cont_to_next == false && curr_key == 1) {
          what_to_do_with_encr_alg("Blowfish+AES+Serp+AES", curr_key);
          cont_to_next = true;
        }

        if (cont_to_next == false && curr_key == 2) {
          what_to_do_with_encr_alg("AES+Serpent+AES", curr_key);
          cont_to_next = true;
        }

        if (cont_to_next == false && curr_key == 3) {
          what_to_do_with_encr_alg("Blowfish+Serpent", curr_key);
          cont_to_next = true;
        }

        if (cont_to_next == false && curr_key == 4) {
          what_to_do_with_encr_alg("AES+Serpent", curr_key);
          cont_to_next = true;
        }

        if (cont_to_next == false && curr_key == 5) {
          what_to_do_with_encr_alg("Serpent", curr_key);
          cont_to_next = true;
        }

        if (cont_to_next == false && curr_key == 6) {
          what_to_do_with_encr_alg("Triple DES", curr_key);
          cont_to_next = true;
        }
      }
      if (prsd_key == 27) {
        cont_to_next = true;
      }
      encryption_algorithms_menu(curr_key);

    }
  }
  call_main_menu();
}

void hash_functions_menu(int curr_pos) {
  tft.setTextSize(1);
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("SHA-256", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("SHA-512", sdown + 20);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("SHA-256", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("SHA-512", sdown + 20);
  }
}

void hash_functions() {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(current_inact_clr);
  disp_centered_text("Hash Functions", 10);
  curr_key = 0;
  usb_keyb_inp = false;
  hash_functions_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    delayMicroseconds(400);
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;

      if (prsd_key == 218)
        curr_key--;

      if (prsd_key == 217)
        curr_key++;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if (prsd_key == 10) {
        if (cont_to_next == false && curr_key == 0) {
          hash_string_with_sha(false);
          cont_to_next = true;
        }

        if (cont_to_next == false && curr_key == 1) {
          hash_string_with_sha(true);
          cont_to_next = true;
        }
      }
      if (prsd_key == 27) {
        cont_to_next = true;
      }
      hash_functions_menu(curr_key);

    }
  }
  call_main_menu();
}

void incr_custom_serp_in_cbc_key() {
  if (custom_serp_in_cbc_key[15] == 255) {
    custom_serp_in_cbc_key[15] = 0;
    if (custom_serp_in_cbc_key[14] == 255) {
      custom_serp_in_cbc_key[14] = 0;
      if (custom_serp_in_cbc_key[13] == 255) {
        custom_serp_in_cbc_key[13] = 0;
        if (custom_serp_in_cbc_key[12] == 255) {
          custom_serp_in_cbc_key[12] = 0;
          if (custom_serp_in_cbc_key[11] == 255) {
            custom_serp_in_cbc_key[11] = 0;
            if (custom_serp_in_cbc_key[10] == 255) {
              custom_serp_in_cbc_key[10] = 0;
              if (custom_serp_in_cbc_key[9] == 255) {
                custom_serp_in_cbc_key[9] = 0;
                if (custom_serp_in_cbc_key[8] == 255) {
                  custom_serp_in_cbc_key[8] = 0;
                  if (custom_serp_in_cbc_key[7] == 255) {
                    custom_serp_in_cbc_key[7] = 0;
                    if (custom_serp_in_cbc_key[6] == 255) {
                      custom_serp_in_cbc_key[6] = 0;
                      if (custom_serp_in_cbc_key[5] == 255) {
                        custom_serp_in_cbc_key[5] = 0;
                        if (custom_serp_in_cbc_key[4] == 255) {
                          custom_serp_in_cbc_key[4] = 0;
                          if (custom_serp_in_cbc_key[3] == 255) {
                            custom_serp_in_cbc_key[3] = 0;
                            if (custom_serp_in_cbc_key[2] == 255) {
                              custom_serp_in_cbc_key[2] = 0;
                              if (custom_serp_in_cbc_key[1] == 255) {
                                custom_serp_in_cbc_key[1] = 0;
                                if (custom_serp_in_cbc_key[0] == 255) {
                                  custom_serp_in_cbc_key[0] = 0;
                                } else {
                                  custom_serp_in_cbc_key[0]++;
                                }
                              } else {
                                custom_serp_in_cbc_key[1]++;
                              }
                            } else {
                              custom_serp_in_cbc_key[2]++;
                            }
                          } else {
                            custom_serp_in_cbc_key[3]++;
                          }
                        } else {
                          custom_serp_in_cbc_key[4]++;
                        }
                      } else {
                        custom_serp_in_cbc_key[5]++;
                      }
                    } else {
                      custom_serp_in_cbc_key[6]++;
                    }
                  } else {
                    custom_serp_in_cbc_key[7]++;
                  }
                } else {
                  custom_serp_in_cbc_key[8]++;
                }
              } else {
                custom_serp_in_cbc_key[9]++;
              }
            } else {
              custom_serp_in_cbc_key[10]++;
            }
          } else {
            custom_serp_in_cbc_key[11]++;
          }
        } else {
          custom_serp_in_cbc_key[12]++;
        }
      } else {
        custom_serp_in_cbc_key[13]++;
      }
    } else {
      custom_serp_in_cbc_key[14]++;
    }
  } else {
    custom_serp_in_cbc_key[15]++;
  }
}

size_t cust_k_hex2bin(void * bin) {
  size_t len, i;
  int x;
  uint8_t * p = (uint8_t * ) bin;
  for (i = 0; i < 32; i++) {
    p[i] = (uint8_t) custom_serp_in_cbc_key[i];
  }
  return 32;
}


void input_source_for_cust_key_encr_menu(int curr_pos) {
  tft.setTextSize(1);
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("USB Keyboard", sdown + 10);
    tft.setTextColor(stripe_on_the_right_and_oth_opts_color);
    disp_centered_text("Serial Terminal", sdown + 20);
  }
  if (curr_pos == 1) {
    tft.setTextColor(stripe_on_the_right_and_oth_opts_color);
    disp_centered_text("USB Keyboard", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Serial Terminal", sdown + 20);
  }
}

byte input_source_for_cust_key_encr() {
  byte inpsrc = 0;
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(stripe_on_the_right_and_oth_opts_color);
  disp_centered_text("Choose Input Source", 10);
  curr_key = 0;
  input_source_for_cust_key_encr_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;

      if (prsd_key == 218)
        curr_key--;

      if (prsd_key == 217)
        curr_key++;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if (prsd_key == 10) {
        if (cont_to_next == false && curr_key == 0) {
          inpsrc = 1;
        }

        if (cont_to_next == false && curr_key == 1) {
          inpsrc = 2;
        }
        cont_to_next = true;
        break;
      }
      if (prsd_key == 27) {
        cont_to_next = true;
        break;
      }
      input_source_for_cust_key_encr_menu(curr_key);

    }
    delayMicroseconds(400);
  }
  return inpsrc;
}

void what_to_do_with_custom_key_encr_alg_menu(int curr_pos) {
  tft.setTextSize(1);
  
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("Encrypt String", sdown + 10);
    tft.setTextColor(stripe_on_the_right_and_oth_opts_color);
    disp_centered_text("Decrypt String", sdown + 20);
  }
  if (curr_pos == 1) {
    tft.setTextColor(stripe_on_the_right_and_oth_opts_color);
    disp_centered_text("Encrypt String", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Decrypt String", sdown + 20);
  }
}

void what_to_do_with_custom_key_encr_alg() {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(stripe_on_the_right_and_oth_opts_color);
  disp_centered_text("Custom Key Encryption", 10);
  curr_key = 0;
  usb_keyb_inp = false;
  what_to_do_with_custom_key_encr_alg_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    delayMicroseconds(400);
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;

      if (prsd_key == 218)
        curr_key--;

      if (prsd_key == 217)
        curr_key++;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if (prsd_key == 10) {
        if (cont_to_next == false && curr_key == 0) {
          byte inp_src_cust_k = input_source_for_cust_key_encr();
          if (inp_src_cust_k == 1)
            get_key_for_cust_key_encr(1);
          if (inp_src_cust_k == 2)
            get_key_for_cust_key_encr(2);
          cont_to_next = true;
        }

        if (cont_to_next == false && curr_key == 1) {
          where_to_print_plaintext_for_cust_key_encr();
          cont_to_next = true;
        }
      }
      if (prsd_key == 27) {
        cont_to_next = true;
      }
      what_to_do_with_custom_key_encr_alg_menu(curr_key);

    }
  }
  call_main_menu();
}

void where_to_print_plaintext_for_cust_key_encr_menu(int curr_pos) {
  tft.setTextSize(1);
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("Display", sdown + 10);
    tft.setTextColor(stripe_on_the_right_and_oth_opts_color);
    disp_centered_text("Serial Terminal", sdown + 20);
  }
  if (curr_pos == 1) {
    tft.setTextColor(stripe_on_the_right_and_oth_opts_color);
    disp_centered_text("Display", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Serial Terminal", sdown + 20);
  }
}

void where_to_print_plaintext_for_cust_key_encr() {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(stripe_on_the_right_and_oth_opts_color);
  disp_centered_text("Where to print plaintext?", 10);
  curr_key = 0;
  usb_keyb_inp = false;
  where_to_print_plaintext_for_cust_key_encr_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    delayMicroseconds(400);
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;

      if (prsd_key == 218)
        curr_key--;

      if (prsd_key == 217)
        curr_key++;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if (prsd_key == 10) {

        if (cont_to_next == false && curr_key == 0) {
          get_key_for_cust_key_encr(3);
          cont_to_next = true;
        }

        if (cont_to_next == false && curr_key == 1) {
          get_key_for_cust_key_encr(4);
          cont_to_next = true;
        }
      }
      if (prsd_key == 27) {
        cont_to_next = true;
      }
      where_to_print_plaintext_for_cust_key_encr_menu(curr_key);

    }
  }
  call_main_menu();
}

void get_key_for_cust_key_encr(byte whatsnext) {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setTextSize(1);
  set_stuff_for_input("Enter The Key:");
  encdr_and_keyb_input();
  if (act == true) {
    int str_len = keyboard_input.length() + 1;
    char keyb_inp_arr[str_len];
    keyboard_input.toCharArray(keyb_inp_arr, str_len);
    std::string str = "";
    if (str_len > 1) {
      for (int i = 0; i < str_len - 1; i++) {
        str += keyb_inp_arr[i];
      }
    }
    String h = sha512(str).c_str();
    byte res[64];
    for (int i = 0; i < 128; i += 2) {
      if (i == 0) {
        if (h.charAt(i) != 0 && h.charAt(i + 1) != 0)
          res[i] = 16 * getNum(h.charAt(i)) + getNum(h.charAt(i + 1));
        if (h.charAt(i) != 0 && h.charAt(i + 1) == 0)
          res[i] = 16 * getNum(h.charAt(i));
        if (h.charAt(i) == 0 && h.charAt(i + 1) != 0)
          res[i] = getNum(h.charAt(i + 1));
        if (h.charAt(i) == 0 && h.charAt(i + 1) == 0)
          res[i] = 0;
      } else {
        if (h.charAt(i) != 0 && h.charAt(i + 1) != 0)
          res[i / 2] = 16 * getNum(h.charAt(i)) + getNum(h.charAt(i + 1));
        if (h.charAt(i) != 0 && h.charAt(i + 1) == 0)
          res[i / 2] = 16 * getNum(h.charAt(i));
        if (h.charAt(i) == 0 && h.charAt(i + 1) != 0)
          res[i / 2] = getNum(h.charAt(i + 1));
        if (h.charAt(i) == 0 && h.charAt(i + 1) == 0)
          res[i / 2] = 0;
      }
    }
    if (whatsnext == 1) {
      get_plaintext_for_custom_key_encr_from_keyb(res);
    }
    if (whatsnext == 2) {
      get_plaintext_for_custom_key_encr_from_serial(res);
    }
    if (whatsnext == 3) {
      decrypt_serpent_in_cbc_with_custom_key(res, true);
    }
    if (whatsnext == 4) {
      decrypt_serpent_in_cbc_with_custom_key(res, false);
    }
    clear_variables();
    curr_key = 0;
    main_menu(curr_key);
  }
  return;
}

void decrypt_serpent_in_cbc_with_custom_key(byte enckey[], bool print_plt_on_disp_or_serial) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_cphrt_inscr();
    Serial.println("\nPaste the ciphertext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    tft.fillScreen(0x0000);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.print("Decrypting the text...");
    tft.setCursor(0, 10);
    tft.print("Please wait for a while.");
    String ct = Serial.readString();
    decrypt_string_with_serpent_in_cbc(ct, enckey);
    bool plt_integr = verify_integrity_32bytes();
    if (print_plt_on_disp_or_serial == true) {
      disp_plt_on_tft(plt_integr);
      clear_variables();
      press_any_key_to_continue();
    } else {
      Serial.println("Plaintext:");
      Serial.println(dec_st);
      if (plt_integr == true)
        Serial.println("Integrity Verified Successfully!\n");
      else
        Serial.println("Integrity Verification Failed!!!\n");
    }
    clear_variables();
    for (int i = 0; i < 32; i++){
      custm_key_hmack_key[i] = 0;
      custom_serp_in_cbc_key[i] = 0;
    }
    call_main_menu();
    return;
  }
}

void get_plaintext_for_custom_key_encr_from_keyb(byte enckey[]) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter String To Encrypt");
  encdr_and_keyb_input();
  if (act == true) {
    encrypt_with_custom_key(keyboard_input, enckey);
  }
  return;
}

void get_plaintext_for_custom_key_encr_from_serial(byte enckey[]) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Plaintext");
    Serial.println("\nPaste the plaintext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    encrypt_with_custom_key(Serial.readString(), enckey);
    cont_to_next = true;
    break;
  }
  return;
}

void encrypt_with_custom_key(String plaintext_to_enc, byte enckey[]){
  for (int i = 0; i < 32; i++){
    custm_key_hmack_key[i] = enckey[i];
    custom_serp_in_cbc_key[i] = uint8_t(enckey[i + 32]);
  }
  int iv[16]; // Initialization vector
  for (int i = 0; i < 16; i++){
    iv[i] = trng_word() % 256;
  }
  encrypt_string_with_serpent_in_cbc(plaintext_to_enc, iv); // Function for encryption. Takes the plaintext and iv as the input.
  Serial.println("\nCiphertext:");
  Serial.println(dec_st);
  for (int i = 0; i < 32; i++){
    custm_key_hmack_key[i] = 0;
    custom_serp_in_cbc_key[i] = 0;
  }
  clear_variables();
}

void split_by_sixteen_for_serp_in_cbc_encryption(char plntxt[], int k, int str_len) {
  int res[] = {
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
    if (i + k > str_len - 1)
      break;
    res[i] = plntxt[i + k];
  }

  for (int i = 0; i < 16; i++) {
    res[i] ^= array_for_CBC_mode[i];
  }
  
  encrypt_with_serpent_in_cbc_cust_key(res);
}

void encrypt_iv_for_cust_key_serpent(int iv[]) {
  for (int i = 0; i < 16; i++){
    array_for_CBC_mode[i] = iv[i];
  }
  
  encrypt_with_serpent_in_cbc_cust_key(iv);
}

void encrypt_with_serpent_in_cbc_cust_key(int pass_to_serp[]) {
  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, b, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t * p;

  for (b = 0; b < 1; b++) {
    cust_k_hex2bin(key);

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
    incr_custom_serp_in_cbc_key();
    /*
    for (int i = 0; i < 16; i++) {
      if (ct2.b[i] < 16)
        Serial.print("0");
      Serial.print(ct2.b[i], HEX);
    }
    */
    for (int i = 0; i < 16; i++) {
     if (decract > 0){
        if (i < 16){
          array_for_CBC_mode[i] = int(ct2.b[i]);
        }  
     }
     if (ct2.b[i] < 16)
        dec_st += "0";
      dec_st += String(ct2.b[i], HEX);
    }
    decract++;
  }
}

void split_for_serp_in_cbc_cust_key_decryption(char ct[], int ct_len, int p) {
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
    if(decract > 16){
      for (int i = 0; i < 16; i++){
        array_for_CBC_mode[i] = prev_res[i];
      }
    }
    uint8_t ct1[32], pt1[32], key[64];
    int plen, clen, i, j;
    serpent_key skey;
    serpent_blk ct2;
    uint32_t * p;

    for (i = 0; i < 1; i++) {
      cust_k_hex2bin(key);

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
    incr_custom_serp_in_cbc_key();
    if (decract > 2) {
      for (int i = 0; i < 16; i++){
        ct2.b[i] ^= array_for_CBC_mode[i];
      }
      if (decract < 30){
        for (i = 0; i < 16; ++i) {
          if (ct2.b[i] < 0x10)
            dec_tag += "0";
          dec_tag += String(ct2.b[i], HEX);
        }
      }
      else{
        for (i = 0; i < 16; ++i) {
          if (ct2.b[i] > 0)
            dec_st += char(ct2.b[i]);
        }
      }
    }

    if (decract == -1){
      for (i = 0; i < 16; ++i) {
        array_for_CBC_mode[i] = int(ct2.b[i]);
      }
    }
    decract++;
  }
}

void encrypt_string_with_serpent_in_cbc(String input, int iv[]) {

  clear_variables();
  encrypt_iv_for_cust_key_serpent(iv);
  encr_tag_for_serpent_in_cbc(input);
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  int p = 0;
  while (str_len > p + 1) {
    split_by_sixteen_for_serp_in_cbc_encryption(input_arr, p, str_len);
    p += 16;
  }

}

void encr_tag_for_serpent_in_cbc(String input) {
  SHA256HMAC hmac(custm_key_hmack_key, sizeof(custm_key_hmack_key));
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
  for (int i = 0; i < 2; i++) {
    split_by_sixteen_for_serp_in_cbc_encryption(hmacchar, p, 100);
    p += 16;
  }
  
}

void decrypt_string_with_serpent_in_cbc(String ct, byte enckey[]) { // Function for decryption. Takes ciphertext as an input.
  for (int i = 0; i < 32; i++){
    custm_key_hmack_key[i] = enckey[i];
    custom_serp_in_cbc_key[i] = uint8_t(enckey[i + 32]);
  }
  clear_variables();
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  decract = -1;
  while (ct_len > ext) {
    split_for_serp_in_cbc_cust_key_decryption(ct_array, ct_len, 0 + ext);
    ext += 32;
    decract += 10;
  }

}

void other_options_menu(int curr_pos) {
  tft.setTextSize(1);
  const char* options[] = {
    "Back Up Data From EEPROM",
    "Restore Data To EEPROM",
    "Custom Key Encryption",
    "Read Encrypted Book",
    "Factory Reset"
  };
  for (int i = 0; i < 5; i++) {
    if (curr_pos == i) {
      tft.setTextColor(0xffff); // Active color
    } else {
      tft.setTextColor(stripe_on_the_right_and_oth_opts_color); // Inactive color
    }

    disp_centered_text(options[i], sdown + 10 * (i + 1));
  }
}

void other_options() {
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(stripe_on_the_right_and_oth_opts_color);
  disp_centered_text("Other Options", 10);
  curr_key = 0;
  usb_keyb_inp = false;
  other_options_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    delayMicroseconds(400);
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;

      if (prsd_key == 218)
        curr_key--;

      if (prsd_key == 217)
        curr_key++;

      if (curr_key < 0)
        curr_key = 4;

      if (curr_key > 4)
        curr_key = 0;

      if (prsd_key == 10) {
        if (cont_to_next == false && curr_key == 0) {
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(current_inact_clr);
          disp_centered_text("Back Up Data From EEPROM To", 10);
          byte inpsrc = serial_or_sd_card_for_data_backup(false);
          disp_button_designation();
          cont_to_next = true;
          if (inpsrc == 1)
            backup_data_to_serial();
          if (inpsrc == 2)
            backup_data_to_sd_card();
        }

        if (cont_to_next == false && curr_key == 1) {
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(current_inact_clr);
          disp_centered_text("Restore Data To EEPROM From", 10);
          byte inpsrc = serial_or_sd_card_for_data_backup(true);
          disp_button_designation();
          cont_to_next = true;
          if (inpsrc == 1)
            restore_data_from_serial();
          if (inpsrc == 2)
            restore_data_from_sd_card();
        }

        if (cont_to_next == false && curr_key == 2) {
          what_to_do_with_custom_key_encr_alg();
          cont_to_next = true;
        }
        if (cont_to_next == false && curr_key == 3) {
          action_for_encr_book();
          cont_to_next = true;
        }
        if (cont_to_next == false && curr_key == 4) {
          Factory_Reset();
          cont_to_next = true;
        }
        
      }
      if (prsd_key == 27) {
        cont_to_next = true;
      }
      other_options_menu(curr_key);

    }
  }
  call_main_menu();
}

void action_for_encr_book_menu(int curr_pos) {
  tft.setTextSize(1);
  
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("Read Book", sdown + 10);
    tft.setTextColor(stripe_on_the_right_and_oth_opts_color);
    disp_centered_text("Delete Book", sdown + 20);
    disp_centered_text("Print Encryption Key", sdown + 30);
  }
  if (curr_pos == 1) {
    tft.setTextColor(stripe_on_the_right_and_oth_opts_color);
    disp_centered_text("Read Book", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Delete Book", sdown + 20);
    tft.setTextColor(stripe_on_the_right_and_oth_opts_color);
    disp_centered_text("Print Encryption Key", sdown + 30);
  }
  if (curr_pos == 2) {
    tft.setTextColor(stripe_on_the_right_and_oth_opts_color);
    disp_centered_text("Read Book", sdown + 10);
    disp_centered_text("Delete Book", sdown + 20);
    tft.setTextColor(0xffff);
    disp_centered_text("Print Encryption Key", sdown + 30);
  }
}

void action_for_encr_book() {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(stripe_on_the_right_and_oth_opts_color);
  disp_centered_text("Encrypted Book Menu", 10);
  curr_key = 0;
  usb_keyb_inp = false;
  action_for_encr_book_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    delayMicroseconds(400);
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;

      if (prsd_key == 218)
        curr_key--;

      if (prsd_key == 217)
        curr_key++;

      if (curr_key < 0)
        curr_key = 2;

      if (curr_key > 2)
        curr_key = 0;

      if (prsd_key == 10) {
        if (cont_to_next == false && curr_key == 0) {
          String for_book_key_der;
          for (int i = 10; i < 26; i++)
            for_book_key_der += char(32 + (int(AES_key[i]) % 95));
          for (int i = 4; i < 13; i++)
            for_book_key_der += char(32 + (int(des_key[i]) % 95));
          for (int i = 10; i < 31; i++)
            for_book_key_der += char(int(hmackey[i]));
          SHA256HMAC hmac(hmackey, sizeof(hmackey));
          int str_len = for_book_key_der.length() + 1;
          char for_book_key_der_arr[str_len];
          for_book_key_der.toCharArray(for_book_key_der_arr, str_len);
          hmac.doUpdate(for_book_key_der_arr);
          byte authCode[SHA256HMAC_SIZE];
          hmac.doFinal(authCode);
          for (int i = 0; i < 32; i++){
            serp_book_key[i] = uint8_t(authCode[i]);
          }
          prinybooknames(true);
          cont_to_next = true;
        }

        if (cont_to_next == false && curr_key == 1) {
          prinybooknames(false);
          cont_to_next = true;
        }

        if (cont_to_next == false && curr_key == 2) {
          Serial.println();
          Serial.println("Book Encryption Key:");
          String for_book_key_der;
          for (int i = 10; i < 26; i++)
            for_book_key_der += char(32 + (int(AES_key[i]) % 95));
          for (int i = 4; i < 13; i++)
            for_book_key_der += char(32 + (int(des_key[i]) % 95));
          for (int i = 10; i < 31; i++)
            for_book_key_der += char(int(hmackey[i]));
          Serial.println(get_tag(for_book_key_der));
          cont_to_next = true;
        }
      }
      if (prsd_key == 27) {
        cont_to_next = true;
      }
      action_for_encr_book_menu(curr_key);

    }
  }
  call_main_menu();
}


int file_count() {
  File dir = SD.open("/books");
  int file_c = 0;
   while(true) {
     File entry = dir.openNextFile();
     if (! entry) {
       //Serial.println("** no more files **");
       break;
     }
     if (entry.isDirectory()) {
     } else {
       file_c++;
     }
     entry.close();
   }
   return file_c ;
}

void prinybooknames(bool what_to_do_with_it) {
  int nm_of_books = file_count();
  String e_books[nm_of_books];
  int bn = 0;
  File dir = SD.open("/books");
   while(true) {
     File entry = dir.openNextFile();
     if (! entry) {
       //Serial.println("** no more files **");
       break;
     }
     if (entry.isDirectory()) {
     } else {
        e_books[bn] = entry.name();
        bn++;
     }
     entry.close();
     delay(24);
   }
   select_book(e_books, nm_of_books, what_to_do_with_it);
}

void select_book(String ebooks[], int num_of_books, bool what_to_do_with_it) {
  if (num_of_books == 0){
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("No books", 5);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Get Back", 120);
    press_any_key_to_continue();
  }
  else{
  delay(DELAY_FOR_SLOTS);
  curr_key = 1;
  usb_keyb_inp = false;
  encr_book_header(what_to_do_with_it, num_of_books);
  display_a_book_name_on_tft(ebooks, 1);
  bool continue_to_next = false;
  while (continue_to_next == false) {
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;

      if (prsd_key == 215)
        curr_key++;

      if (prsd_key == 216)
        curr_key--;

      if (curr_key < 1)
        curr_key = num_of_books;

      if (curr_key > num_of_books)
        curr_key = 1;

      if (prsd_key == 10) { // Enter
        int chsn_slot = curr_key;
        tft.fillScreen(0x0000);
        tft.setTextSize(1);
        tft.setTextColor(0xffff);
        tft.setCursor(0, 0);
        tft.print("Decrypting the record...");
        tft.setCursor(0, 10);
        tft.print("Please wait for a while.");
        decrypt_the_ebook(ebooks, chsn_slot);
        if (what_to_do_with_it == false) {
          delete_book(ebooks, chsn_slot);
        }
        continue_to_next = true;
        break;
      }

      if (prsd_key == 27) {
        call_main_menu();
        continue_to_next = true;
        break;
      }
      delay(DELAY_FOR_SLOTS);
      encr_book_header(what_to_do_with_it, num_of_books);
      display_a_book_name_on_tft(ebooks, curr_key);
    }
    delayMicroseconds(500);
  }
}
  return;
}

void encr_book_header(bool what_to_do_with_it, int how_many_bks) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  if (what_to_do_with_it == true){
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Read Book " + String(curr_key) + "/" + String(how_many_bks), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == false){
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Delete Book " + String(curr_key) + "/" + String(how_many_bks), 5);
    disp_button_designation_for_del();
  }
}

void display_a_book_name_on_tft(String e_books[], int disp_book_n){
  disp_book_n--;
  tft.setTextColor(0xffff);
  tft.setTextSize(1);
  disp_centered_text(e_books[disp_book_n], 20);
}

void decrypt_the_ebook(String ebooks[], int chsn_slot){
  chsn_slot--;
  read_book("/books/" + ebooks[chsn_slot]);
}

void delete_book(String ebooks[], int chsn_slot){
  chsn_slot--;
  delete_file("/books/" + ebooks[chsn_slot]);
}

void read_book(String filename) {
  tft.fillScreen(0x0000);
  tft.setTextColor(0xce6a);
  tft.fillRect(155, 0, 4, 128, 0x630C);
  tft.setCursor(0,0);
  int filename_len = filename.length() + 1;
  char filename_array[filename_len];
  filename.toCharArray(filename_array, filename_len);
  File chosenBook = SD.open(filename_array, "r");
  int n = 0;
  bool cls_b = false;
  decract = -1;
  previous_book_segment = "00000000000000000000000000000000";
  while (chosenBook.available()) {
    bool cnt = false;
    if (n % 26 == 0 && n != 0){
      while (1){
        myusb.Task();
        if (usb_keyb_inp == true) {
          usb_keyb_inp = false;
          if (prsd_key > 0){
            if (prsd_key == 27) { // Esc
              cls_b = true;
              break;
            }
            else{
              tft.fillScreen(0x0000);
              tft.fillRect(155, 0, 4, 128, 0x630C);
              tft.setCursor(0,0);
              break;
            }
          }
        }
        delayMicroseconds(400);
      }
    }
    if (cls_b == true)
      break;
    String ct;
    for (int i = 0; i < 32; i++)
      ct += char(chosenBook.read());
    decrypt_book_part_with_serpent_in_cbc(ct);
    n++;
  }
}

void decrypt_book_part_with_serpent_in_cbc(String ct) { // Function for decryption. Takes ciphertext as an input.
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);

  int prev_ct_len = previous_book_segment.length() + 1;
  char prev_ct_array[prev_ct_len];
  previous_book_segment.toCharArray(prev_ct_array, prev_ct_len);
  
  decrypt_16_byte_book_segment(ct_array, prev_ct_array);
  decract += 10;
  previous_book_segment = ct;
}

void incr_serp_book_key() {
  for (int i = 15; i >= 0; i--) {
    if (serp_book_key[i] == 255) {
      serp_book_key[i] = 0;
    } else {
      serp_book_key[i]++;
      break;
    }
  }
}

size_t hex2bin_for_books(void * bin) {
  size_t len, i;
  int x;
  uint8_t * p = (uint8_t * ) bin;
  for (i = 0; i < 32; i++) {
    p[i] = (uint8_t) serp_book_key[i];
  }
  return 32;
}

void decrypt_16_byte_book_segment(char ct[], char prev_ct[]) {
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
    if (i == 0) {
      if (ct[i] != 0 && ct[i + 1] != 0)
        res[i] = 16 * getNum(ct[i]) + getNum(ct[i + 1]);
      if (ct[i] != 0 && ct[i + 1] == 0)
        res[i] = 16 * getNum(ct[i]);
      if (ct[i] == 0 && ct[i + 1] != 0)
        res[i] = getNum(ct[i + 1]);
      if (ct[i] == 0 && ct[i + 1] == 0)
        res[i] = 0;
    } else {
      if (ct[i] != 0 && ct[i + 1] != 0)
        res[i / 2] = 16 * getNum(ct[i]) + getNum(ct[i + 1]);
      if (ct[i] != 0 && ct[i + 1] == 0)
        res[i / 2] = 16 * getNum(ct[i]);
      if (ct[i] == 0 && ct[i + 1] != 0)
        res[i / 2] = getNum(ct[i + 1]);
      if (ct[i] == 0 && ct[i + 1] == 0)
        res[i / 2] = 0;
    }
  }

  for (int i = 0; i < 32; i += 2) {
    if (i == 0) {
      if (prev_ct[i] != 0 && prev_ct[i + 1] != 0)
        prev_res[i] = 16 * getNum(prev_ct[i]) + getNum(prev_ct[i + 1]);
      if (prev_ct[i] != 0 && prev_ct[i + 1] == 0)
        prev_res[i] = 16 * getNum(prev_ct[i]);
      if (prev_ct[i] == 0 && prev_ct[i + 1] != 0)
        prev_res[i] = getNum(prev_ct[i + 1]);
      if (prev_ct[i] == 0 && prev_ct[i + 1] == 0)
        prev_res[i] = 0;
    } else {
      if (prev_ct[i] != 0 && prev_ct[i + 1] != 0)
        prev_res[i / 2] = 16 * getNum(prev_ct[i]) + getNum(prev_ct[i + 1]);
      if (prev_ct[i] != 0 && prev_ct[i + 1] == 0)
        prev_res[i / 2] = 16 * getNum(prev_ct[i]);
      if (prev_ct[i] == 0 && prev_ct[i + 1] != 0)
        prev_res[i / 2] = getNum(prev_ct[i + 1]);
      if (prev_ct[i] == 0 && prev_ct[i + 1] == 0)
        prev_res[i / 2] = 0;
    }
  }
  
    if(decract > 16){
      for (int i = 0; i < 16; i++){
        array_for_CBC_mode[i] = prev_res[i];
      }
    }
    uint8_t ct1[32], pt1[32], key[64];
    int plen, clen, i, j;
    serpent_key skey;
    serpent_blk ct2;
    uint32_t * p;

    for (i = 0; i < 1; i++) {
      hex2bin_for_books(key);

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
    incr_serp_book_key();
    if (decract > 2) {
      for (int i = 0; i < 16; i++){
        ct2.b[i] ^= array_for_CBC_mode[i];
      }
      
      for (i = 0; i < 16; ++i) {
        if (ct2.b[i] > 31 && ct2.b[i] < 127)
          tft.print(char(ct2.b[i]));
      }
    }

    if (decract == -1){
      for (i = 0; i < 16; ++i) {
        array_for_CBC_mode[i] = int(ct2.b[i]);
      }
    }
    decract++;
}

void serial_or_sd_card_for_data_backup_menu(int curr_pos) {
  tft.setTextSize(1);
  
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("Serial Terminal", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("SD Card", sdown + 20);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Serial Terminal", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("SD Card", sdown + 20);
  }
}

byte serial_or_sd_card_for_data_backup(bool chsn_inscr) {
  byte inpsrc = 0;
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(current_inact_clr);
  if (chsn_inscr == false)
    disp_centered_text("Back Up Data To", 10);
  else
    disp_centered_text("Restore Data From", 10);
  curr_key = 0;
  serial_or_sd_card_for_data_backup_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    delayMicroseconds(400);
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;

      if (prsd_key == 218)
        curr_key--;

      if (prsd_key == 217)
        curr_key++;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if (prsd_key == 10) {
        if (cont_to_next == false && curr_key == 0) {
          inpsrc = 1;
        }

        if (cont_to_next == false && curr_key == 1) {
          inpsrc = 2;
        }
        cont_to_next = true;
        break;
      }
      if (prsd_key == 27) {
        cont_to_next = true;
        break;
      }
      serial_or_sd_card_for_data_backup_menu(curr_key);

    }
  }
  return inpsrc;
}

// Menu (Above)

void Factory_Reset() {
  tft.fillScreen(0x0000);
  tft.setTextColor(five_six_five_red_color);
  disp_centered_text("Factory Reset", 0);
  delay(500);
  disp_centered_text("Attention!!!", 20);
  tft.setTextColor(0xffff);
  delay(500);
  disp_centered_text("All your data", 40);
  delay(500);
  disp_centered_text("will be lost!", 50);
  delay(500);
  tft.setTextColor(0x1557);
  disp_centered_text("Are you sure you want", 80);
  disp_centered_text("to continue?", 90);
  tft.setTextSize(1);
  delay(5000);
  usb_keyb_inp = false;
  disp_button_designation_for_del();
  finish_input = false;
  while (finish_input == false) {
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;
      if (prsd_key == 10) {
        perform_factory_reset();
        finish_input = true;
      }

      if (prsd_key == 27) {
        finish_input = true;
      }

    }
    delayMicroseconds(400);
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
  delay(100);
  for ( unsigned int i = 0 ; i < EEPROM.length() ; i++ )
    EEPROM.write(i, 0);
  delay(100);
  delete_file("/Midback");
  for (int i = 0; i < MAX_NUM_OF_RECS; i++) {
    delete_file("/L" + String(i + 1) + "_tag");
    delete_file("/L" + String(i + 1) + "_ttl");
    delete_file("/L" + String(i + 1) + "_usn");
    delete_file("/L" + String(i + 1) + "_psw");
    delete_file("/L" + String(i + 1) + "_wbs");
    delete_file("/C" + String(i + 1) + "_tag");
    delete_file("/C" + String(i + 1) + "_ttl");
    delete_file("/C" + String(i + 1) + "_hld");
    delete_file("/C" + String(i + 1) + "_nmr");
    delete_file("/C" + String(i + 1) + "_exp");
    delete_file("/C" + String(i + 1) + "_cvn");
    delete_file("/C" + String(i + 1) + "_pin");
    delete_file("/C" + String(i + 1) + "_zip");
    delete_file("/N" + String(i + 1) + "_tag");
    delete_file("/N" + String(i + 1) + "_ttl");
    delete_file("/N" + String(i + 1) + "_cnt");
    delete_file("/P" + String(i + 1) + "_tag");
    delete_file("/P" + String(i + 1) + "_ttl");
    delete_file("/P" + String(i + 1) + "_cnt");
    tft.fillRect(0, 10, 160, 10, 0x0000);
    tft.setCursor(0, 10);
    tft.print("Progress " + String((float(i + 1) / float(MAX_NUM_OF_RECS)) * 100) + "%");
  }
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Deleting Books...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  File dir = SD.open("/books");
   while(true) {
     File entry = dir.openNextFile();
     if (! entry) {
       //Serial.println("** no more files **");
       break;
     }
     if (entry.isDirectory()) {
     } else {
      delete_file("/books/" + String(entry.name()));
     }
     entry.close();
   }
  SD.rmdir("/books");
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  disp_centered_text("DONE!", 10);
  disp_centered_text("Please reboot", 30);
  disp_centered_text("the device", 40);
  delay(100);
  for (;;) {}
}

void hash_string_with_sha(bool vrsn) {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setTextSize(1);
  set_stuff_for_input("Enter string to hash:");
  encdr_and_keyb_input();
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
  tft.setTextColor(current_inact_clr);
  tft.setTextSize(1);
  disp_centered_text("Resulted hash", 10);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 30);
  tft.println(res_hash);
  press_any_key_to_continue();
}

void hash_with_sha512() {
  int str_len = keyboard_input.length() + 1;
  char keyb_inp_arr[str_len];
  keyboard_input.toCharArray(keyb_inp_arr, str_len);
  std::string str = "";
  if (str_len > 1) {
    for (int i = 0; i < str_len - 1; i++) {
      str += keyb_inp_arr[i];
    }
  }
  String h = sha512(str).c_str();
  tft.fillScreen(0x0000);
  tft.setTextColor(current_inact_clr);
  tft.setTextSize(1);
  disp_centered_text("Resulted hash", 10);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 30);
  tft.println(h);
  press_any_key_to_continue();
}

// Functions for encryption and decryption (Below)

void disp_paste_smth_inscr(String what_to_pst) {
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setTextSize(1);
  disp_centered_text("Paste " + what_to_pst + " to", 30);
  disp_centered_text("the Serial Terminal", 40);
  tft.setTextColor(five_six_five_red_color);
  disp_centered_text("Press Any Key", 110);   disp_centered_text("To Cancel", 120);
}

void disp_paste_cphrt_inscr() {
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setTextSize(1);
  disp_centered_text("Paste Ciphertext to", 30);
  disp_centered_text("the Serial Terminal", 40);
  tft.setTextColor(five_six_five_red_color);
  disp_centered_text("Press Any Key", 110);   disp_centered_text("To Cancel", 120);
}

void disp_plt_on_tft(bool intgrt) {
  tft.fillScreen(0x0000);
  tft.setTextColor(current_inact_clr);
  tft.setTextSize(1);
  disp_centered_text("Plaintext", 4);
  if (dec_st.length() > 26)
    tft.fillRect(155, 0, 4, 128, stripe_on_the_right_and_oth_opts_color);
  if (intgrt == true)
    tft.setTextColor(0xffff);
  else {
    tft.setTextColor(five_six_five_red_color);
    tft.fillRect(0, 118, 160, 14, 0x0000);
    if (dec_st.length() > 26)
      tft.fillRect(155, 0, 4, 128, five_six_five_red_color);
    disp_centered_text(faild_ver_inscr, 120);
  }
  disp_centered_text(dec_st, 24);
}

void encr_TDES_AES_BLF_Serp() {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter text to encrypt");
  encdr_and_keyb_input();
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Encrypting the text...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  if (act == true) {
    encrypt_string_with_tdes_aes_blf_srp(keyboard_input);
    Serial.println("\nCiphertext");
    Serial.println(dec_st);
  }
  clear_variables();
  call_main_menu();
  return;
}

void encr_TDES_AES_BLF_Serp_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Plaintext");
    Serial.println("\nPaste the string you want to encrypt here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    tft.fillScreen(0x0000);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.print("Encrypting the text...");
    tft.setCursor(0, 10);
    tft.print("Please wait for a while.");
    String plt = Serial.readString();
    encrypt_string_with_tdes_aes_blf_srp(plt);
    Serial.println("\nCiphertext");
    Serial.println(dec_st);
    cont_to_next = true;
    clear_variables();
    call_main_menu();
    return;
  }
}

void decr_TDES_AES_BLF_Serp(bool print_plt_on_disp_or_serial) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_cphrt_inscr();
    Serial.println("\nPaste the ciphertext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    tft.fillScreen(0x0000);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.print("Decrypting the text...");
    tft.setCursor(0, 10);
    tft.print("Please wait for a while.");
    String ct = Serial.readString();
    decrypt_string_with_TDES_AES_Blowfish_Serp(ct);
    bool plt_integr = verify_integrity();
    if (print_plt_on_disp_or_serial == true) {
      disp_plt_on_tft(plt_integr);
      clear_variables();
      press_any_key_to_continue();
    } else {
      Serial.println("Plaintext:");
      Serial.println(dec_st);
      if (plt_integr == true)
        Serial.println("Integrity Verified Successfully!\n");
      else
        Serial.println("Integrity Verification Failed!!!\n");
    }
    clear_variables();
    call_main_menu();
    return;
  }
}

void encr_blwfsh_aes_serpent_aes() {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter text to encrypt");
  encdr_and_keyb_input();
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Encrypting the text...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  if (act == true) {
    encrypt_with_blwfsh_aes_serpent_aes(keyboard_input);
    Serial.println("\nCiphertext");
    Serial.println(dec_st);
  }
  clear_variables();
  call_main_menu();
  return;
}

void encr_blwfsh_aes_serpent_aes_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Plaintext");
    Serial.println("\nPaste the string you want to encrypt here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    tft.fillScreen(0x0000);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.print("Encrypting the text...");
    tft.setCursor(0, 10);
    tft.print("Please wait for a while.");
    String plt = Serial.readString();
    encrypt_with_blwfsh_aes_serpent_aes(plt);
    Serial.println("\nCiphertext");
    Serial.println(dec_st);
    cont_to_next = true;
    clear_variables();
    call_main_menu();
    return;
  }
}

void decr_blwfsh_aes_serpent_aes(bool print_plt_on_disp_or_serial) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_cphrt_inscr();
    Serial.println("\nPaste the ciphertext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    tft.fillScreen(0x0000);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.print("Decrypting the text...");
    tft.setCursor(0, 10);
    tft.print("Please wait for a while.");
    String ct = Serial.readString();
    decrypt_with_blwfsh_aes_serpent_aes(ct);
    bool plt_integr = verify_integrity();
    if (print_plt_on_disp_or_serial == true) {
      disp_plt_on_tft(plt_integr);
      clear_variables();
      press_any_key_to_continue();
    } else {
      Serial.println("Plaintext:");
      Serial.println(dec_st);
      if (plt_integr == true)
        Serial.println("Integrity Verified Successfully!\n");
      else
        Serial.println("Integrity Verification Failed!!!\n");
    }
    clear_variables();
    call_main_menu();
    return;
  }
}

void encr_aes_serpent_aes() {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter text to encrypt");
  encdr_and_keyb_input();
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Encrypting the text...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  if (act == true) {
    encrypt_with_aes_serpent_aes(keyboard_input);
    Serial.println("\nCiphertext");
    Serial.println(dec_st);
  }
  clear_variables();
  call_main_menu();
  return;
}

void encr_aes_serpent_aes_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Plaintext");
    Serial.println("\nPaste the string you want to encrypt here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    tft.fillScreen(0x0000);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.print("Encrypting the text...");
    tft.setCursor(0, 10);
    tft.print("Please wait for a while.");
    String plt = Serial.readString();
    encrypt_with_aes_serpent_aes(plt);
    Serial.println("\nCiphertext");
    Serial.println(dec_st);
    cont_to_next = true;
    clear_variables();
    call_main_menu();
    return;
  }
}

void decr_aes_serpent_aes(bool print_plt_on_disp_or_serial) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_cphrt_inscr();
    Serial.println("\nPaste the ciphertext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    tft.fillScreen(0x0000);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.print("Decrypting the text...");
    tft.setCursor(0, 10);
    tft.print("Please wait for a while.");
    String ct = Serial.readString();
    decrypt_with_aes_serpent_aes(ct);
    bool plt_integr = verify_integrity();
    if (print_plt_on_disp_or_serial == true) {
      disp_plt_on_tft(plt_integr);
      clear_variables();
      press_any_key_to_continue();
    } else {
      Serial.println("Plaintext:");
      Serial.println(dec_st);
      if (plt_integr == true)
        Serial.println("Integrity Verified Successfully!\n");
      else
        Serial.println("Integrity Verification Failed!!!\n");
    }
    clear_variables();
    call_main_menu();
    return;
  }
}

void encr_blowfish_serpent() {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter text to encrypt");
  encdr_and_keyb_input();
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Encrypting the text...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  if (act == true) {
    encrypt_with_blowfish_serpent(keyboard_input);
    Serial.println("\nCiphertext");
    Serial.println(dec_st);
  }
  clear_variables();
  call_main_menu();
  return;
}

void encr_blowfish_serpent_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Plaintext");
    Serial.println("\nPaste the string you want to encrypt here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    tft.fillScreen(0x0000);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.print("Encrypting the text...");
    tft.setCursor(0, 10);
    tft.print("Please wait for a while.");
    String plt = Serial.readString();
    encrypt_with_blowfish_serpent(plt);
    Serial.println("\nCiphertext");
    Serial.println(dec_st);
    cont_to_next = true;
    clear_variables();
    call_main_menu();
    return;
  }
}

void decr_blowfish_serpent(bool print_plt_on_disp_or_serial) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_cphrt_inscr();
    Serial.println("\nPaste the ciphertext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    tft.fillScreen(0x0000);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.print("Decrypting the text...");
    tft.setCursor(0, 10);
    tft.print("Please wait for a while.");
    String ct = Serial.readString();
    decrypt_with_blowfish_serpent(ct);
    bool plt_integr = verify_integrity();
    if (print_plt_on_disp_or_serial == true) {
      disp_plt_on_tft(plt_integr);
      clear_variables();
      press_any_key_to_continue();
    } else {
      Serial.println("Plaintext:");
      Serial.println(dec_st);
      if (plt_integr == true)
        Serial.println("Integrity Verified Successfully!\n");
      else
        Serial.println("Integrity Verification Failed!!!\n");
    }
    clear_variables();
    call_main_menu();
    return;
  }
}

void encr_aes_serpent() {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter text to encrypt");
  encdr_and_keyb_input();
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Encrypting the text...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  if (act == true) {
    encrypt_with_aes_serpent(keyboard_input);
    Serial.println("\nCiphertext");
    Serial.println(dec_st);
  }
  clear_variables();
  call_main_menu();
  return;
}

void encr_aes_serpent_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Plaintext");
    Serial.println("\nPaste the string you want to encrypt here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    tft.fillScreen(0x0000);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.print("Encrypting the text...");
    tft.setCursor(0, 10);
    tft.print("Please wait for a while.");
    String plt = Serial.readString();
    encrypt_with_aes_serpent(plt);
    Serial.println("\nCiphertext");
    Serial.println(dec_st);
    cont_to_next = true;
    clear_variables();
    call_main_menu();
    return;
  }
}

void decr_aes_serpent(bool print_plt_on_disp_or_serial) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_cphrt_inscr();
    Serial.println("\nPaste the ciphertext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    tft.fillScreen(0x0000);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.print("Decrypting the text...");
    tft.setCursor(0, 10);
    tft.print("Please wait for a while.");
    String ct = Serial.readString();
    decrypt_with_aes_serpent(ct);
    bool plt_integr = verify_integrity();
    if (print_plt_on_disp_or_serial == true) {
      disp_plt_on_tft(plt_integr);
      clear_variables();
      press_any_key_to_continue();
    } else {
      Serial.println("Plaintext:");
      Serial.println(dec_st);
      if (plt_integr == true)
        Serial.println("Integrity Verified Successfully!\n");
      else
        Serial.println("Integrity Verification Failed!!!\n");
    }
    clear_variables();
    call_main_menu();
    return;
  }
}

void encr_serpent_only() {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter text to encrypt");
  encdr_and_keyb_input();
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Encrypting the text...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  if (act == true) {
    encrypt_with_serpent_only(keyboard_input);
    Serial.println("\nCiphertext");
    Serial.println(dec_st);
  }
  clear_variables();
  call_main_menu();
  return;
}

void encr_serpent_only_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Plaintext");
    Serial.println("\nPaste the string you want to encrypt here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    tft.fillScreen(0x0000);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.print("Encrypting the text...");
    tft.setCursor(0, 10);
    tft.print("Please wait for a while.");
    String plt = Serial.readString();
    encrypt_with_serpent_only(plt);
    Serial.println("\nCiphertext");
    Serial.println(dec_st);
    cont_to_next = true;
    clear_variables();
    call_main_menu();
    return;
  }
}

void decr_serpent_only(bool print_plt_on_disp_or_serial) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_cphrt_inscr();
    Serial.println("\nPaste the ciphertext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    tft.fillScreen(0x0000);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.print("Decrypting the text...");
    tft.setCursor(0, 10);
    tft.print("Please wait for a while.");
    String ct = Serial.readString();
    decrypt_with_serpent_only(ct);
    bool plt_integr = verify_integrity();
    if (print_plt_on_disp_or_serial == true) {
      disp_plt_on_tft(plt_integr);
      clear_variables();
      press_any_key_to_continue();
    } else {
      Serial.println("Plaintext:");
      Serial.println(dec_st);
      if (plt_integr == true)
        Serial.println("Integrity Verified Successfully!\n");
      else
        Serial.println("Integrity Verification Failed!!!\n");
    }
    clear_variables();
    call_main_menu();
    return;
  }
}

void encr_tdes_only() {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter text to encrypt");
  encdr_and_keyb_input();
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Encrypting the text...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  if (act == true) {
    encrypt_with_tdes_only(keyboard_input);
    Serial.println("\nCiphertext");
    Serial.println(dec_st);
  }
  clear_variables();
  call_main_menu();
  return;
}

void encr_tdes_only_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Plaintext");
    Serial.println("\nPaste the string you want to encrypt here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    tft.fillScreen(0x0000);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.print("Encrypting the text...");
    tft.setCursor(0, 10);
    tft.print("Please wait for a while.");
    String plt = Serial.readString();
    encrypt_with_tdes_only(plt);
    Serial.println("\nCiphertext");
    Serial.println(dec_st);
    cont_to_next = true;
    clear_variables();
    call_main_menu();
    return;
  }
}

void decr_tdes_only(bool print_plt_on_disp_or_serial) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_cphrt_inscr();
    Serial.println("\nPaste the ciphertext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    tft.fillScreen(0x0000);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.print("Decrypting the text...");
    tft.setCursor(0, 10);
    tft.print("Please wait for a while.");
    String ct = Serial.readString();
    decrypt_with_tdes_only(ct);
    bool plt_integr = verify_integrity();
    if (print_plt_on_disp_or_serial == true) {
      disp_plt_on_tft(plt_integr);
      clear_variables();
      press_any_key_to_continue();
    } else {
      Serial.println("Plaintext:");
      Serial.println(dec_st);
      if (plt_integr == true)
        Serial.println("Integrity Verified Successfully!\n");
      else
        Serial.println("Integrity Verification Failed!!!\n");
    }
    clear_variables();
    call_main_menu();
    return;
  }
}

// Functions for encryption and decryption (Above)

void lock_scr_without_rfid() {
  tft.fillScreen(0x0000);
  byte chosen_lock_screen = trng_word() % 3;

  if (chosen_lock_screen == 0){
    for (int i = 0; i < 160; i++){
      for (int j = 0; j < 88; j++){
        tft.drawPixel(i, j + 20, Atlanta[i][j]);
      }
    }
  }
  
  if (chosen_lock_screen == 1){
    for (int i = 0; i < 160; i++){
      for (int j = 0; j < 88; j++){
        tft.drawPixel(i, j + 20, Houston[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 2){
    for (int i = 0; i < 160; i++){
      for (int j = 0; j < 88; j++){
        tft.drawPixel(i, j + 20, Kuwait_City[i][j]);
      }
    }
  }

  tft.setTextSize(1);
  disp_centered_text("Midbar Teensy 4.1", 6);
  if (sd_mnt == false){
    disp_centered_text("No SD Card", 115);
    delay(1000);
    tft.fillRect(0, 115, 160, 13, 0x0000);
  }
  disp_centered_text("Press Any Key", 115);
  bool break_the_loop = false;
  while (break_the_loop == false) {
    myusb.Task();
    if (usb_keyb_inp == true) {
      break_the_loop = true;
    }
  }
  delayMicroseconds(400);
}

// Functions for data in EEPROM (Below)

void compute_and_write_encrypted_tag_for_EEPROM_integrity_check(){
  String h;
  for (int i = 0; i < 4209; i++) {
    int cv = EEPROM.read(i);
    if (cv < 16)
      h += "0";
    h += String(cv, HEX);
  }
  back_keys();
  dec_st = "";
  encr_hash_for_tdes_aes_blf_srp_fl(h);
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
  for (int i = 0; i < 48; i++) {
    EEPROM.write(i + 4209, res[i]);
  }
}

void check_EEPROM_integrity(){
  String h;
  for (int i = 0; i < 4209; i++) {
    int cv = EEPROM.read(i);
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
  back_keys();
  clear_variables();
  String encr_h;
  for (int i = 0; i < 48; i++) {
    if (EEPROM.read(i + 4209) < 16)
      encr_h += "0";
    encr_h += String(EEPROM.read(i + 4209), HEX);
  }
  decrypt_tag_with_TDES_AES_Blowfish_Serp_fl(encr_h);
  //Serial.println(dec_tag);
  tft.setTextSize(1);
  if (dec_tag.equals(res_hash)){
    tft.setTextColor(0xf7de);
    disp_centered_text("EEPROM Integrity Check", 76);
    disp_centered_text("Completed Successfully!", 86);
  }
  else{
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("EEPROM Integrity Check", 76);
    disp_centered_text("Failed!!!", 86);
  }
}

void action_for_data_in_EEPROM_menu(int curr_pos) {
  tft.setTextSize(1);
  const char* actions[] = {"Add", "Delete", "View", "Type"};
  for (int i = 0; i < 4; i++) {
    if (curr_pos == i) {
      tft.setTextColor(0xffff); // Active color
    } else {
      tft.setTextColor(current_inact_clr); // Inactive color
    }

    disp_centered_text(actions[i], sdown + 10 * (i + 1));
  }
}

void action_for_data_in_EEPROM(bool r_type) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(current_inact_clr);
  if (r_type == false)
    disp_centered_text("Logins In EEPROM Menu", 10);
  else
    disp_centered_text("Credit Cards In EEPROM", 10);
  curr_key = 0;
  usb_keyb_inp = false;
  action_for_data_in_EEPROM_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    delayMicroseconds(400);
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;

      if (prsd_key == 218) curr_key--;  // Upwards arrow key
      if (prsd_key == 217) curr_key++;  // Downwards arrow key

      if (curr_key < 0)
        curr_key = 3;

      if (curr_key > 3)
        curr_key = 0;

      if (prsd_key == 10) {
        if (cont_to_next == false && curr_key == 0) {
          if (r_type == false)
            select_login_from_EEPROM(0);
          else
            select_credit_card_from_EEPROM(0);
          cont_to_next = true;
        }

        if (cont_to_next == false && curr_key == 1) {
          if (r_type == false)
            select_login_from_EEPROM(1);
          else
            select_credit_card_from_EEPROM(1);
          cont_to_next = true;
        }

        if (cont_to_next == false && curr_key == 2) {
          if (r_type == false)
            select_login_from_EEPROM(2);
          else
            select_credit_card_from_EEPROM(2);
          cont_to_next = true;
        }

        if (cont_to_next == false && curr_key == 3) {
          if (r_type == false)
            select_login_from_EEPROM(3);
          else
            select_credit_card_from_EEPROM(3);
          cont_to_next = true;
        }
      }
      if (prsd_key == 27) {
        cont_to_next = true;
      }
      action_for_data_in_EEPROM_menu(curr_key);

    }
  }
  call_main_menu();
}

void select_credit_card_from_EEPROM(byte what_to_do_with_it) {
  delay(1);
  curr_key = 1;
  usb_keyb_inp = false;
  header_for_select_credit_card_from_EEPROM(what_to_do_with_it);
  display_card_number_from_credit_card_in_EEPROM();
  bool continue_to_next = false;
  while (continue_to_next == false) {
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;

      if (prsd_key == 215)
        curr_key++;

      if (prsd_key == 216)
        curr_key--;

      if (curr_key < 1)
        curr_key = 12;

      if (curr_key > 12)
        curr_key = 1;

      if (prsd_key == 10) { // Enter
        int chsn_slot = curr_key;
        if (what_to_do_with_it == 0) {
          byte inptsrc = input_source_for_data_in_flash();
          if (inptsrc == 1)
            add_credit_card_to_EEPROM_from_keyboard_and_encdr(chsn_slot);
          if (inptsrc == 2)
            add_credit_card_to_EEPROM_from_serial(chsn_slot);
        }
        if (what_to_do_with_it == 1) {
          delete_credit_card_from_EEPROM(chsn_slot);
        }
        if (what_to_do_with_it == 2) {
          view_credit_card_from_EEPROM(chsn_slot);
        }
        if (what_to_do_with_it == 3) {
          type_credit_card_from_EEPROM(chsn_slot);
        }
        continue_to_next = true;
        break;
      }

      if (prsd_key == 27) {
        call_main_menu();
        continue_to_next = true;
        break;
      }
      delay(1);
      header_for_select_credit_card_from_EEPROM(what_to_do_with_it);
      display_card_number_from_credit_card_in_EEPROM();
    }
    delayMicroseconds(500);
  }
  return;
}

void display_card_number_from_credit_card_in_EEPROM(){
  tft.setTextSize(1);
  int start_address = get_slot_start_address_for_credit_card(curr_key);
  
  int extr_data[112];

  for (int i = 0; i < 112; i++) {
    extr_data[i] = EEPROM.read(i + start_address);
      
  }
  int noz = 0; // Number of zeroes
  for (int i = 0; i < 112; i++) {
    if (extr_data[i] == 0)
      noz++;
  }
  //Serial.println(noz);
  if (noz == 112) {
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 20);
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
    decrypt_with_TDES_AES_Blowfish_Serp_fl(extr_ct);
    tft.setTextColor(0xffff);
    int shift_to_card_number = MAX_NUM_OF_CHARS_FOR_CARDHOLDER;
    int end_of_card_number = MAX_NUM_OF_CHARS_FOR_CARDHOLDER + MAX_NUM_OF_CHARS_FOR_CARD_NUMBER;
    String crdn_to_disp;
    for (int i = shift_to_card_number; i < end_of_card_number; i ++){
      if (dec_st.charAt(i) > 31 && dec_st.charAt(i) < 127)
        crdn_to_disp += dec_st.charAt(i);
    }
    disp_centered_text(crdn_to_disp, 20);
  }
}

void header_for_select_credit_card_from_EEPROM(byte what_to_do_with_it){
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  if (what_to_do_with_it == 0) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add Card to Slot " + String(curr_key) + "/" + String(12), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 1) {
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Delete Card " + String(curr_key) + "/" + String(12), 5);
    disp_button_designation_for_del();
  }
  if (what_to_do_with_it == 2) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View Card " + String(curr_key) + "/" + String(12), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 3) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Type Card " + String(curr_key) + "/" + String(12), 5);
    disp_button_designation();
  }
}

void add_credit_card_to_EEPROM_from_keyboard_and_encdr(int chsn_slot) {
  enter_cardholder_for_credit_card_in_EEPROM(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void enter_cardholder_for_credit_card_in_EEPROM(int chsn_slot) {
  act = true;
  clear_variables();
  set_stuff_for_input_with_length("Enter Cardholder Name");
  encdr_and_keyb_input_with_length();
  if (act == true) {
    enter_card_number_for_credit_card_in_EEPROM(chsn_slot, keyboard_input);
  }
  return;
}

void enter_card_number_for_credit_card_in_EEPROM(int chsn_slot, String entered_cardholder) {
  act = true;
  clear_variables();
  set_stuff_for_input_with_length("Enter Card Number");
  encdr_and_keyb_input_with_length();
  if (act == true) {
    enter_expiry_for_credit_card_in_EEPROM(chsn_slot, entered_cardholder, keyboard_input);
  }
  return;
}

void enter_expiry_for_credit_card_in_EEPROM(int chsn_slot, String entered_cardholder, String entered_card_number) {
  act = true;
  clear_variables();
  set_stuff_for_input_with_length("Enter Expiration Date");
  encdr_and_keyb_input_with_length();
  if (act == true) {
    enter_cvn_for_credit_card_in_EEPROM(chsn_slot, entered_cardholder, entered_card_number, keyboard_input);
  }
  return;
}

void enter_cvn_for_credit_card_in_EEPROM(int chsn_slot, String entered_cardholder, String entered_card_number, String entered_expiry) {
  act = true;
  clear_variables();
  set_stuff_for_input_with_length("Enter CVN");
  encdr_and_keyb_input_with_length();
  if (act == true) {
    enter_pin_for_credit_card_in_EEPROM(chsn_slot, entered_cardholder, entered_card_number, entered_expiry, keyboard_input);
  }
  return;
}

void enter_pin_for_credit_card_in_EEPROM(int chsn_slot, String entered_cardholder, String entered_card_number, String entered_expiry, String entered_cvn) {
  act = true;
  clear_variables();
  set_stuff_for_input_with_length("Enter PIN");
  encdr_and_keyb_input_with_length();
  if (act == true) {
    enter_zip_code_for_credit_card_in_EEPROM(chsn_slot, entered_cardholder, entered_card_number, entered_expiry, entered_cvn, keyboard_input);
  }
  return;
}

void enter_zip_code_for_credit_card_in_EEPROM(int chsn_slot, String entered_cardholder, String entered_card_number, String entered_expiry, String entered_cvn, String entered_pin) {
  act = true;
  clear_variables();
  set_stuff_for_input_with_length("Enter ZIP Code");
  encdr_and_keyb_input_with_length();
  if (act == true) {
    write_credit_card_to_EEPROM(chsn_slot, entered_cardholder, entered_card_number, entered_expiry, entered_cvn, entered_pin, keyboard_input);
  }
  return;
}

void add_credit_card_to_EEPROM_from_serial(int chsn_slot) {
  get_cardholder_name_for_credit_card_in_EEPROM_from_serial(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void get_cardholder_name_for_credit_card_in_EEPROM_from_serial(int chsn_slot) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Cardholder Name");
    Serial.println("\nPaste the cardholder name here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    get_card_number_for_credit_card_in_EEPROM_from_serial(chsn_slot, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_card_number_for_credit_card_in_EEPROM_from_serial(int chsn_slot, String entered_cardholder) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Card Number");
    Serial.println("\nPaste the card number here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    get_expiration_date_for_credit_card_in_EEPROM_from_serial(chsn_slot, entered_cardholder, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_expiration_date_for_credit_card_in_EEPROM_from_serial(int chsn_slot, String entered_cardholder, String entered_card_number) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Expiration Date");
    Serial.println("\nPaste the expiration date here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    get_cvn_for_credit_card_in_EEPROM_from_serial(chsn_slot, entered_cardholder, entered_card_number, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_cvn_for_credit_card_in_EEPROM_from_serial(int chsn_slot, String entered_cardholder, String entered_card_number, String entered_expiry) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("CVN");
    Serial.println("\nPaste the CVN here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    get_pin_for_credit_card_in_EEPROM_from_serial(chsn_slot, entered_cardholder, entered_card_number, entered_expiry, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_pin_for_credit_card_in_EEPROM_from_serial(int chsn_slot, String entered_cardholder, String entered_card_number, String entered_expiry, String entered_cvn) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("PIN");
    Serial.println("\nPaste the PIN here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    get_zip_code_for_credit_card_in_EEPROM_from_serial(chsn_slot, entered_cardholder, entered_card_number, entered_expiry, entered_cvn, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_zip_code_for_credit_card_in_EEPROM_from_serial(int chsn_slot, String entered_cardholder, String entered_card_number, String entered_expiry, String entered_cvn, String entered_pin) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("ZIP Code");
    Serial.println("\nPaste the ZIP code here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    write_credit_card_to_EEPROM(chsn_slot, entered_cardholder, entered_card_number, entered_expiry, entered_cvn, entered_pin, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void write_credit_card_to_EEPROM(int chsn_slot, String entered_cardholder, String entered_card_number, String entered_expiry, String entered_cvn, String entered_pin, String entered_zip) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Adding Credit Card");
  tft.setCursor(0, 10);
  tft.print("To The slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 20);
  tft.print("Please wait for a while.");
  
  char crdhldr [MAX_NUM_OF_CHARS_FOR_CARDHOLDER];
  char crdnmbr [MAX_NUM_OF_CHARS_FOR_CARD_NUMBER];
  char exprdt [MAX_NUM_OF_CHARS_FOR_EXPIRATION_DATE];
  char cvn_arr [MAX_NUM_OF_CHARS_FOR_CVN];
  char pin_arr [MAX_NUM_OF_CHARS_FOR_PIN];
  char zpc_arr [MAX_NUM_OF_CHARS_FOR_ZIP_CODE];

  for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_CARDHOLDER; i++){
    crdhldr[i] = 127 + (trng_word() % 129);
  }

  for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_CARD_NUMBER; i++){
    crdnmbr[i] = 127 + (trng_word() % 129);
  }

  for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_EXPIRATION_DATE; i++){
    exprdt[i] = 127 + (trng_word() % 129);
  }

  for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_CVN; i++){
    cvn_arr[i] = 127 + (trng_word() % 129);
  }

  for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_PIN; i++){
    pin_arr[i] = 127 + (trng_word() % 129);
  }

  for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_ZIP_CODE; i++){
    zpc_arr[i] = 127 + (trng_word() % 129);
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
  encrypt_with_TDES_AES_Blowfish_Serp_fl(resulted_string);
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
    EEPROM.write(i + start_address, res[i]);
  }
  compute_and_write_encrypted_tag_for_EEPROM_integrity_check();
  return;
}

void delete_credit_card_from_EEPROM(int chsn_slot){
  int start_address = get_slot_start_address_for_credit_card(chsn_slot);
  for (int i = 0; i < 112; i++) {
    EEPROM.write(i + start_address, 0);
  }  
  compute_and_write_encrypted_tag_for_EEPROM_integrity_check();
  return;
}

void view_credit_card_from_EEPROM(int chsn_slot){
  int start_address = get_slot_start_address_for_credit_card(chsn_slot);
  
  int extr_data[112];

  for (int i = 0; i < 112; i++) {
    extr_data[i] = EEPROM.read(i + start_address);
      
  }
  int noz = 0; // Number of zeroes
  for (int i = 0; i < 112; i++) {
    if (extr_data[i] == 0)
      noz++;
  }
  //Serial.println(noz);
  if (noz == 112) {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Get Back", 120);
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
    decrypt_with_TDES_AES_Blowfish_Serp_fl(extr_ct);

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
    tft.setTextSize(1);
    tft.setCursor(0, 0);
    tft.setTextColor(current_inact_clr);
    tft.print("Cardholder Name:");
    tft.setTextColor(0xffff);
    tft.println(cardholder_to_disp);
    tft.setTextColor(current_inact_clr);
    tft.print("Card Number:");
    tft.setTextColor(0xffff);
    tft.println(card_num_to_disp);
    tft.setTextColor(current_inact_clr);
    tft.print("Expiration Date:");
    tft.setTextColor(0xffff);
    tft.println(exp_to_disp);
    tft.setTextColor(current_inact_clr);
    tft.print("CVN:");
    tft.setTextColor(0xffff);
    tft.println(cvn_to_disp);
    tft.setTextColor(current_inact_clr);
    tft.print("PIN:");
    tft.setTextColor(0xffff);
    tft.println(pin_to_disp);
    tft.setTextColor(current_inact_clr);
    tft.print("ZIP Code:");
    tft.setTextColor(0xffff);
    tft.println(zip_to_disp);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    tft.fillRect(155, 0, 4, 128, stripe_on_the_right_and_oth_opts_color);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Get Back", 120);
    press_any_key_to_continue();
    }
}

void type_credit_card_from_EEPROM(int chsn_slot){
  int start_address = get_slot_start_address_for_credit_card(chsn_slot);
  
  int extr_data[112];

  for (int i = 0; i < 112; i++) {
    extr_data[i] = EEPROM.read(i + start_address);
      
  }
  int noz = 0; // Number of zeroes
  for (int i = 0; i < 112; i++) {
    if (extr_data[i] == 0)
      noz++;
  }
  //Serial.println(noz);
  if (noz == 112) {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Get Back", 120);
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
    decrypt_with_TDES_AES_Blowfish_Serp_fl(extr_ct);

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
      tft.setTextSize(1);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 35);
      
      disp_centered_text("to type \"Cardholder Name\"", 45);
      act = false;
      up_arrow_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(cardholder_to_disp);
      }
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 35);
      
      disp_centered_text("to type \"Card Number\"", 45);
      act = false;
      up_arrow_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(card_num_to_disp);
      }
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 35);
      
      disp_centered_text("to type \"Expiration Date\"", 45);
      act = false;
      up_arrow_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(exp_to_disp);
      }
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 35);
      
      disp_centered_text("to type \"CVN\"", 45);
      act = false;
      up_arrow_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(cvn_to_disp);
      }
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 35);
      
      disp_centered_text("to type \"PIN\"", 45);
      act = false;
      up_arrow_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(pin_to_disp);
      }
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 35);
      
      disp_centered_text("to type \"ZIP Code\"", 45);
      act = false;
      up_arrow_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(zip_to_disp);
      }
    }
}

void select_login_from_EEPROM(byte what_to_do_with_it) {
  // 0 - Add login
  // 1 - Delete login
  // 2 - View login
  // 3 - Type login
  delay(1);
  curr_key = 1;
  usb_keyb_inp = false;
  header_for_select_login_from_EEPROM(what_to_do_with_it);
  display_website_from_login_in_EEPROM();
  bool continue_to_next = false;
  while (continue_to_next == false) {
    myusb.Task();
    if (usb_keyb_inp == true) {
      usb_keyb_inp = false;

      if (prsd_key == 215)
        curr_key++;

      if (prsd_key == 216)
        curr_key--;

      if (curr_key < 1)
        curr_key = 16;

      if (curr_key > 16)
        curr_key = 1;

      if (prsd_key == 10) { // Enter
        int chsn_slot = curr_key;
        if (what_to_do_with_it == 0) {
          byte inptsrc = input_source_for_data_in_flash();
          if (inptsrc == 1)
            add_login_to_EEPROM_from_keyboard_and_encdr(chsn_slot);
          if (inptsrc == 2)
            add_login_to_EEPROM_from_serial(chsn_slot);
        }
        if (what_to_do_with_it == 1) {
          delete_login_from_EEPROM(chsn_slot);
        }
        if (what_to_do_with_it == 2) {
          view_login_from_EEPROM(chsn_slot);
        }
        if (what_to_do_with_it == 3) {
          type_login_from_EEPROM(chsn_slot);
        }
        continue_to_next = true;
        break;
      }

      if (prsd_key == 27) {
        call_main_menu();
        continue_to_next = true;
        break;
      }
      delay(1);
      header_for_select_login_from_EEPROM(what_to_do_with_it);
      display_website_from_login_in_EEPROM();
    }
    delayMicroseconds(500);
  }
  return;
}

void add_login_to_EEPROM_from_keyboard_and_encdr(int chsn_slot) {
  enter_username_for_login_in_EEPROM_in_EEPROM(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void enter_username_for_login_in_EEPROM_in_EEPROM(int chsn_slot) {
  act = true;
  clear_variables();
  set_stuff_for_input_with_length("Enter Username");
  encdr_and_keyb_input_with_length();
  if (act == true) {
    enter_password_for_login_in_EEPROM_in_EEPROM(chsn_slot, keyboard_input);
  }
  return;
}

void enter_password_for_login_in_EEPROM_in_EEPROM(int chsn_slot, String entered_username) {
  act = true;
  clear_variables();
  set_stuff_for_input_with_length("Enter Password");
  encdr_and_keyb_input_with_length();
  if (act == true) {
    enter_website_for_login_in_EEPROM_in_EEPROM(chsn_slot, entered_username, keyboard_input);
  }
  return;
}

void enter_website_for_login_in_EEPROM_in_EEPROM(int chsn_slot, String entered_username, String entered_password) {
  act = true;
  clear_variables();
  set_stuff_for_input_with_length("Enter Website");
  encdr_and_keyb_input_with_length();
  if (act == true) {
    write_login_to_EEPROM(chsn_slot, entered_username, entered_password, keyboard_input);
  }
  return;
}

void add_login_to_EEPROM_from_serial(int chsn_slot) {
  get_username_for_login_in_EEPROM_from_serial(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void get_username_for_login_in_EEPROM_from_serial(int chsn_slot) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Username");
    Serial.println("\nPaste the username here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    get_password_for_login_in_EEPROM_from_serial(chsn_slot, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_password_for_login_in_EEPROM_from_serial(int chsn_slot, String entered_username) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Password");
    Serial.println("\nPaste the password here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    get_website_for_login_in_EEPROM_from_serial(chsn_slot, entered_username, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_website_for_login_in_EEPROM_from_serial(int chsn_slot, String entered_username, String entered_password) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Website");
    Serial.println("\nPaste the website here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    write_login_to_EEPROM(chsn_slot, entered_username, entered_password, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void write_login_to_EEPROM(int chsn_slot, String entered_username, String entered_password, String entered_website) {
  /*
  Serial.println();
  Serial.println(chsn_slot);
  Serial.println(entered_username);
  Serial.println(entered_password);
  Serial.println(entered_website);
  */
  char usrnarr[MAX_NUM_OF_CHARS_FOR_USERNAME];
  char passarr[MAX_NUM_OF_CHARS_FOR_PASSWORD];
  char websarr[MAX_NUM_OF_CHARS_FOR_WEBSITE];

  for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_USERNAME; i++){
    usrnarr[i] = 127 + (trng_word() % 129);
  }

  for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_PASSWORD; i++){
    passarr[i] = 127 + (trng_word() % 129);
  }

  for (int i = 0; i < MAX_NUM_OF_CHARS_FOR_WEBSITE; i++){
    websarr[i] = 127 + (trng_word() % 129);
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
  encrypt_with_TDES_AES_Blowfish_Serp_fl(resulted_string);
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
    //Serial.println(get_slot_start_address_for_logins(i));
  int start_address = get_slot_start_address_for_logins(chsn_slot);
  for (int i = 0; i < 176; i++) {
    EEPROM.write(i + start_address, res[i]);
  }  
  compute_and_write_encrypted_tag_for_EEPROM_integrity_check();
  return;
}

void header_for_select_login_from_EEPROM(byte what_to_do_with_it){
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  if (what_to_do_with_it == 0) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add Login to Slot " + String(curr_key) + "/" + String(16), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 1) {
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Delete Login " + String(curr_key) + "/" + String(16), 5);
    disp_button_designation_for_del();
  }
  if (what_to_do_with_it == 2) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View Login " + String(curr_key) + "/" + String(16), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 3) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Type Login " + String(curr_key) + "/" + String(16), 5);
    disp_button_designation();
  }
}

void display_website_from_login_in_EEPROM(){
  tft.setTextSize(1);
  int start_address = get_slot_start_address_for_logins(curr_key);
  
  int extr_data[176];
  
  for (int i = 0; i < 176; i++) {
    extr_data[i] = EEPROM.read(i + start_address);
      
  }
  int noz = 0; // Number of zeroes
  for (int i = 0; i < 176; i++) {
    if (extr_data[i] == 0)
      noz++;
  }
  //Serial.println(noz);
  if (noz == 176) {
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 20);
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
    decrypt_with_TDES_AES_Blowfish_Serp_fl(extr_ct);
    tft.setTextColor(0xffff);
    int shift_to_webs = MAX_NUM_OF_CHARS_FOR_USERNAME + MAX_NUM_OF_CHARS_FOR_PASSWORD;
    String webs_to_disp;
    for (int i = shift_to_webs; i < 160; i ++){
      if (dec_st.charAt(i) > 31 && dec_st.charAt(i) < 127)
        webs_to_disp += dec_st.charAt(i);
    }
    disp_centered_text(webs_to_disp, 20);
  }
}

void delete_login_from_EEPROM(int chsn_slot){
  int start_address = get_slot_start_address_for_logins(chsn_slot);
  for (int i = 0; i < 176; i++) {
    EEPROM.write(i + start_address, 0);
  }  
  compute_and_write_encrypted_tag_for_EEPROM_integrity_check();
  return;
}

void view_login_from_EEPROM(int chsn_slot){
  tft.setTextSize(1);
  int start_address = get_slot_start_address_for_logins(chsn_slot);
  
  int extr_data[176];
  
  for (int i = 0; i < 176; i++) {
    extr_data[i] = EEPROM.read(i + start_address);
      
  }
  int noz = 0; // Number of zeroes
  for (int i = 0; i < 176; i++) {
    if (extr_data[i] == 0)
      noz++;
  }
  //Serial.println(noz);
  if (noz == 176) {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Get Back", 120);
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
    decrypt_with_TDES_AES_Blowfish_Serp_fl(extr_ct);

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
    String webs_to_disp;
    for (int i = shift_to_webs; i < 160; i ++){
      if (dec_st.charAt(i) > 31 && dec_st.charAt(i) < 127)
        webs_to_disp += dec_st.charAt(i);
    }

    tft.fillScreen(0x0000);
    tft.setTextSize(1);
    tft.setCursor(0, 5);
    tft.setTextColor(current_inact_clr);
    tft.print("Username:");
    tft.setTextColor(0xffff);
    tft.println(usrn_to_disp);
    tft.setTextColor(current_inact_clr);
    tft.print("Password:");
    tft.setTextColor(0xffff);
    tft.println(pass_to_disp);
    tft.setTextColor(current_inact_clr);
    tft.print("Website:");
    tft.setTextColor(0xffff);
    tft.println(webs_to_disp);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    tft.fillRect(155, 0, 4, 128, stripe_on_the_right_and_oth_opts_color);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Get Back", 120);
    press_any_key_to_continue();
  }
}

void type_login_from_EEPROM(int chsn_slot){
  tft.setTextSize(1);
  int start_address = get_slot_start_address_for_logins(chsn_slot);
  
  int extr_data[176];
  
  for (int i = 0; i < 176; i++) {
    extr_data[i] = EEPROM.read(i + start_address);
      
  }
  int noz = 0; // Number of zeroes
  for (int i = 0; i < 176; i++) {
    if (extr_data[i] == 0)
      noz++;
  }
  //Serial.println(noz);
  if (noz == 176) {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Get Back", 120);
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
    decrypt_with_TDES_AES_Blowfish_Serp_fl(extr_ct);

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
    String webs_to_disp;
    for (int i = shift_to_webs; i < 160; i ++){
      if (dec_st.charAt(i) > 31 && dec_st.charAt(i) < 127)
        webs_to_disp += dec_st.charAt(i);
    }

      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 35);
      disp_centered_text("to type \"Website\"", 45);
      act = false;
      up_arrow_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(webs_to_disp);
      }
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 35);
      disp_centered_text("to type \"Username\"", 45);
      act = false;
      up_arrow_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(usrn_to_disp);
      }
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setTextColor(0xffff);
      disp_centered_text("Press the \"Upwards Arrow\"", 35);
      disp_centered_text("to type \"Password\"", 45);
      act = false;
      up_arrow_to_print();
      if (act == true){
        typing_inscription();
        type_on_virtual_keyboard(pass_to_disp);
      }
  }
}

int get_slot_start_address_for_credit_card(int chsn_slot){
  if (chsn_slot == 1)
    return 2865;
  else{
    return (2865 + (112 * (chsn_slot - 1)));
  }
}

int get_slot_start_address_for_logins(int chsn_slot){
  if (chsn_slot == 1)
    return 49;
  else{
    return (49 + (176 * (chsn_slot - 1)));
  }
}

void backup_data_to_serial(){
  String extr_eeprom_content;
  for (int i = 0; i < 4257; i++) {
    if (EEPROM.read(i) < 16)
      extr_eeprom_content += "0";
    extr_eeprom_content += String(EEPROM.read(i), HEX);
  }
  Serial.println("\nEEPROM data:");
  Serial.println(extr_eeprom_content);
  Serial.println();
}

void backup_data_to_sd_card(){
  String extr_eeprom_content;
  for (int i = 0; i < 4257; i++) {
    if (EEPROM.read(i) < 16)
      extr_eeprom_content += "0";
    extr_eeprom_content += String(EEPROM.read(i), HEX);
  }
  write_to_file_with_overwrite("/Midback", extr_eeprom_content);
}

void restore_data_from_serial(){
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("EEPROM Data");
    Serial.println("\nPaste the EEPROM data here:");
    bool canc_op = false;
    while (!Serial.available()) {
      myusb.Task();
      if (usb_keyb_inp == true) {
        usb_keyb_inp = false;
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    dec_st = "";
    dec_st = Serial.readString();
    restore_data_to_eeprom();
    cont_to_next = true;
    break;
  }
  return;
}

void restore_data_from_sd_card(){
  dec_st = "";
  dec_st = read_file("/Midback");
  restore_data_to_eeprom();
}

void restore_data_to_eeprom(){
  byte res[4257];
  for (int i = 0; i < 8514; i += 2) {
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

  for (int i = 0; i < 4257; i++) {
    EEPROM.write(i, res[i]);
  }
}

// Functions for data in EEPROM (Above)

void setup(void) {
  tft.initR(INITR_BLACKTAB);
  tft.setRotation(1);
  tft.fillScreen(0x0000);
  tft.setCursor(0, 0);
  tft.print("Loading...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  trng_init();
  myusb.begin();
  keyboard1.attachPress(OnPress);
  Serial.begin(115200);
  //Serial.println(F("Inizializing FS..."));
  if (!SD.begin(chipSelect)) {
    sd_mnt = false;
    //Serial.println("Card Mount Failed");
    lock_scr_without_rfid();
  } else {
    sd_mnt = true;
    lock_scr_without_rfid();
  }

  m = 2; // Set AES to 256-bit mode
  clb_m = 4;

  continue_to_unlock();
}

void loop() {
  myusb.Task();
  if (usb_keyb_inp == true) {
    usb_keyb_inp = false;
    if (prsd_key == 218)
      curr_key--;

    if (prsd_key == 217)
      curr_key++;

    if (curr_key < 0)
      curr_key = 8;

    if (curr_key > 8)
      curr_key = 0;

    if (prsd_key == 10) {
      
      if (curr_key == 0)
        action_for_data_in_EEPROM(false);

      if (curr_key == 1)
        action_for_data_in_EEPROM(true);
        
      if (curr_key == 2)
        action_for_data_in_flash("Logins Menu", curr_key);

      if (curr_key == 3)
        action_for_data_in_flash("Credit Cards Menu", curr_key);

      if (curr_key == 4)
        action_for_data_in_flash("Notes Menu", curr_key);

      if (curr_key == 5)
        action_for_data_in_flash("Phone Numbers Menu", curr_key);

      if (curr_key == 6)
        encryption_algorithms();

      if (curr_key == 7)
        hash_functions();

      if (curr_key == 8)
        other_options();
    }
    main_menu(curr_key);

  }
  delayMicroseconds(400);
}
