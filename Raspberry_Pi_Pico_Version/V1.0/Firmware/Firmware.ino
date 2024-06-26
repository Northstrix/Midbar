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
https://github.com/moononournation/Arduino_GFX
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/intrbiz/arduino-crypto
https://github.com/GyverLibs/EncButton
*/
// !!! Before uploading this sketch -
// Change the Flash Size (Tools -> Flash Size) to the
// "2MB (Sketch: 1MB, FS: 1MB)" !!!
#include "Arduino.h"
#include "LittleFS.h"
#include <PS2KeyAdvanced.h>
#include <EncButton2.h>
#include <Arduino_GFX_Library.h>
#include "DES.h"
#include "aes.h"
#include "blowfish.h"
#include "serpent.h"
#include "Crypto.h"
#include "midbaricon.h"
#include "sha512.h"

#define DATAPIN 14
#define IRQPIN 15

#include <Arduino_GFX_Library.h>
#define GFX_BL DF_GFX_BL

#if defined(DISPLAY_DEV_KIT)
Arduino_GFX * gfx = create_default_Arduino_GFX();
#else
Arduino_DataBus * bus = create_default_Arduino_DataBus();
Arduino_GFX * gfx = new Arduino_ILI9341(bus, DF_GFX_RST, 0 /* rotation */ , false /* IPS */ );
#endif

#define MAX_NUM_OF_RECS 250

DES des;
Blowfish blowfish;

EncButton2 < EB_ENC > enc0(INPUT, 12, 13);
EncButton2 < EB_BTN > encoder_button(INPUT, 9);
EncButton2 < EB_BTN > a_button(INPUT, 11);
EncButton2 < EB_BTN > b_button(INPUT, 10);

PS2KeyAdvanced keyboard;

int m;
int clb_m;
String dec_st;
String dec_tag;
byte tmp_st[8];
int pass_to_serp[16];
int decract;
byte array_for_CBC_mode[10];
uint16_t c;
String keyboard_input;
int curr_key;
bool finish_input;
bool act;;
bool decrypt_tag;
const uint16_t current_inact_clr = 0x051b;
const uint16_t five_six_five_red_color = 0xf940;
int trash;

// Keys (Below)

String kderalgs = "91x6euOj2j6mEe73M94bq3w5CQUdQ8R48zw";
int numofkincr = 381;
byte hmackey[] = {"IVg2RHE7o22fQFI16WboV9x3E2m0ZL6W4EgrO4CoyPf4Ol4X3Q4q2IvvjW9Tf5jq8CZs20hL5432Swtx6blEMJj67PM7A37BuY06K6KM6ST1Nn01iHQelfcVIE0"};
byte des_key[] = {
0xec,0x5b,0x46,0xd9,0xad,0xec,0x0f,0x1d,
0xbb,0xbf,0x71,0x29,0x65,0x11,0xa0,0x28,
0xba,0x4c,0xbf,0xd8,0x78,0x25,0xfc,0xcb
};
uint8_t AES_key[32] = {
0xfc,0x42,0x05,0x45,
0x0c,0x43,0x8b,0xdf,
0xee,0xde,0xff,0x95,
0x56,0xca,0x1f,0x22,
0xf7,0x15,0xba,0xca,
0x09,0x6e,0x67,0x4d,
0x8b,0x93,0x7e,0xe8,
0xdb,0x10,0x06,0x37
};
unsigned char Blwfsh_key[] = {
0x85,0xea,0x44,0xff,
0x6c,0x4e,0x11,0xb0,
0x58,0x06,0x1a,0xee,
0x15,0xdd,0xf9,0xd3,
0x1c,0x47,0x2d,0x3f,
0x8c,0xf7,0x9c,0x61
};
uint8_t serp_key[32] = {
0x21,0xfb,0xa5,0xb0,
0xf6,0xb9,0xc7,0xe7,
0xb2,0x07,0xc1,0xfd,
0x57,0xf6,0x77,0x72,
0xe1,0x7b,0xa4,0x7c,
0x0c,0xc4,0xbe,0x9d,
0xed,0x1b,0x54,0x02,
0xcb,0xac,0x9f,0x6b
};
uint8_t second_AES_key[32] = {
0x1b,0x88,0xab,0xa3,
0xa0,0x05,0xf6,0xb1,
0xf7,0xf7,0xa1,0x33,
0x0b,0xa5,0x2c,0xc6,
0xdf,0x51,0xa3,0xf2,
0x9a,0xf2,0xf4,0x48,
0x6e,0xb5,0x8e,0xe5,
0xf2,0xa1,0xcf,0x4a
};

// Keys (Above)

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

uint32_t rnd_whitened(void){
  uint32_t random = 0;
  uint32_t random_bit;
  volatile uint32_t *rnd_reg = (uint32_t *)(ROSC_BASE + ROSC_RANDOMBIT_OFFSET);

  for (int k = 0; k < 32; k++) {
    while (1) {
      random_bit = (*rnd_reg) & 1;
      if (random_bit != ((*rnd_reg) & 1)) break;
    }

    random = (random << 1) | random_bit;
  }
    
    return random;
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
    array_for_CBC_mode[i] = rnd_whitened() % 256;
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
    res2[i] = rnd_whitened() % 256;
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

// 3DES + AES + Blowfish + Serpent in CBC Mode (Above)

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
    encr_for_aes[i] = rnd_whitened() % 256;
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
    L_half[i] = rnd_whitened() % 256;
    R_half[i] = rnd_whitened() % 256;
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
    t_encr[i] = rnd_whitened() % 256;
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
    L_half[i] = rnd_whitened() % 256;
    R_half[i] = rnd_whitened() % 256;
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
    encr_for_serp[i] = rnd_whitened() % 256;
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
    res[i] = rnd_whitened() % 256;
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
    L_half[i] = rnd_whitened() % 256;
    R_half[i] = rnd_whitened() % 256;
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
    res[i] = rnd_whitened() % 256;
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
    res[i] = rnd_whitened() % 256;
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

void set_stuff_for_input(String blue_inscr) {
  curr_key = 65;
  gfx->fillScreen(0x0000);
  gfx->setTextSize(2);
  gfx->setTextColor(0xffff);
  gfx->setCursor(2, 0);
  gfx->print("Char'");
  gfx->setCursor(74, 0);
  gfx->print("'");
  disp();
  gfx->setCursor(0, 24);
  gfx->setTextSize(2);
  gfx->setTextColor(current_inact_clr);
  gfx->print(blue_inscr);
  gfx->fillRect(312, 0, 8, 240, current_inact_clr);
  gfx->setTextColor(0x07e0);
  gfx->setCursor(216, 0);
  gfx->print("ASCII:");
}

void check_bounds_and_change_char() {
  if (curr_key < 32)
    curr_key = 126;

  if (curr_key > 126)
    curr_key = 32;

  if (keyboard_input.length() > 0)
    curr_key = keyboard_input.charAt(keyboard_input.length() - 1);
}

void check_bounds() {
  if (curr_key < 32)
    curr_key = 126;

  if (curr_key > 126)
    curr_key = 32;
}

void disp() {
  //gfx->fillScreen(0x0000);
  gfx->setTextSize(2);
  gfx->setTextColor(0xffff);
  gfx->fillRect(62, 0, 10, 16, 0x0000);
  gfx->setCursor(62, 0);
  gfx->print(char(curr_key));
  gfx->fillRect(288, 0, 22, 14, 0x0000);
  gfx->setCursor(288, 0);
  String hexstr;
  if (curr_key < 16)
    hexstr += 0;
  hexstr += String(curr_key, HEX);
  hexstr.toUpperCase();
  gfx->setTextColor(0x07e0);
  gfx->print(hexstr);
  gfx->setTextColor(0xffff);
  gfx->setTextSize(2);
  gfx->setCursor(0, 48);
  gfx->print(keyboard_input);
}

void disp_stars() {
  //gfx->fillScreen(0x0000);
  gfx->setTextSize(2);
  gfx->setTextColor(0xffff);
  gfx->fillRect(62, 0, 10, 16, 0x0000);
  gfx->setCursor(62, 0);
  gfx->print(char(curr_key));
  gfx->fillRect(288, 0, 22, 14, 0x0000);
  gfx->setCursor(288, 0);
  String hexstr;
  if (curr_key < 16)
    hexstr += 0;
  hexstr += String(curr_key, HEX);
  hexstr.toUpperCase();
  gfx->setTextColor(0x07e0);
  gfx->print(hexstr);
  int plnt = keyboard_input.length();
  String stars = "";
  for (int i = 0; i < plnt; i++) {
    stars += "*";
  }
  gfx->setTextColor(0xffff);
  gfx->setTextSize(2);
  gfx->setCursor(0, 48);
  gfx->print(stars);
}

void encdr_and_keyb_input() {
  finish_input = false;
  while (finish_input == false) {
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
    delayMicroseconds(400);

    a_button.tick();
    if (a_button.press()) {
      keyboard_input += char(curr_key);
      //Serial.println(keyboard_input);
      disp();
    }
    delayMicroseconds(400);

    b_button.tick();
    if (b_button.press()) {
      if (keyboard_input.length() > 0)
        keyboard_input.remove(keyboard_input.length() - 1, 1);
      //Serial.println(keyboard_input);
      gfx->fillRect(0, 48, 312, 192, 0x0000);
      //Serial.println(keyboard_input);
      disp();
    }
    delayMicroseconds(400);

    if (keyboard.available()) {
      // read the next key
      c = keyboard.read();
      if (c > 0 && ((c & 0xFF) != 6)) {
        /*
        if (c & PS2_BREAK) Serial.print("break ~ ");
        if (!(c & PS2_BREAK)) Serial.print("make  ~ ");
        Serial.print( "Value " );
        Serial.print( c, HEX );
        Serial.print( " - Status Bits " );
        Serial.print( c >> 8, HEX );
        Serial.print( "  Code " );
        Serial.println( c & 0xFF, HEX );
        if (!(c & PS2_BREAK))
          Serial.println(char(c & 0xFF));
        */

        if (c >> 8 == 192 && (c & PS2_BREAK)) {
          if ((c & 0xFF) > 64 && (c & 0xFF) < 91) // Capital letters
            keyboard_input += (char(c & 0xFF));

          if ((c & 0xFF) == 93)
            keyboard_input += ("{");

          if ((c & 0xFF) == 94)
            keyboard_input += ("}");

          if ((c & 0xFF) == 91)
            keyboard_input += (":");

          if ((c & 0xFF) == 58)
            keyboard_input += (char(34)); // "

          if ((c & 0xFF) == 92)
            keyboard_input += ("|");

          if ((c & 0xFF) == 59)
            keyboard_input += ("<");

          if ((c & 0xFF) == 61)
            keyboard_input += (">");

          if ((c & 0xFF) == 62)
            keyboard_input += ("?");

          if ((c & 0xFF) == 64)
            keyboard_input += ("~");

          if ((c & 0xFF) == 60)
            keyboard_input += ("_");

          if ((c & 0xFF) == 95)
            keyboard_input += ("+");

          if ((c & 0xFF) == 49)
            keyboard_input += ("!");

          if ((c & 0xFF) == 50)
            keyboard_input += ("@");

          if ((c & 0xFF) == 51)
            keyboard_input += ("#");

          if ((c & 0xFF) == 52)
            keyboard_input += ("$");

          if ((c & 0xFF) == 53)
            keyboard_input += ("%");

          if ((c & 0xFF) == 54)
            keyboard_input += ("^");

          if ((c & 0xFF) == 55)
            keyboard_input += ("&");

          if ((c & 0xFF) == 56)
            keyboard_input += ("*");

          if ((c & 0xFF) == 57)
            keyboard_input += ("(");

          if ((c & 0xFF) == 48)
            keyboard_input += (")");

          check_bounds_and_change_char();
          disp();

        }
        if (c >> 8 == 129 && (c & PS2_BREAK)) {
          bool cll_chck_bnds = true;
          if ((c & 0xFF) == 30) // Enter
            finish_input = true;

          if ((c & 0xFF) == 27) {
            //Serial.println(keyboard_input);
            act = false;
            finish_input = true;
          }

          if (c == 33045) {
            curr_key--;
            cll_chck_bnds = false;
            check_bounds();
          }

          if (c == 33046) {
            curr_key++;
            cll_chck_bnds = false;
            check_bounds();
          }

          if (c == 33055)
            keyboard_input += (" "); // Space

          if (c == 33052) { // Backspace
            if (keyboard_input.length() > 0)
              keyboard_input.remove(keyboard_input.length() - 1, 1);
            //Serial.println(keyboard_input);
            gfx->fillRect(0, 48, 312, 192, 0x0000);
          }

          if (cll_chck_bnds == true)
            check_bounds_and_change_char();
          disp();
        }
        if (c >> 8 == 128 && (c & PS2_BREAK)) {

          if ((c & 0xFF) > 47 && (c & 0xFF) < 58) // Digits
            keyboard_input += (char((c & 0xFF)));

          if ((c & 0xFF) > 64 && (c & 0xFF) < 91) // Lowercase letters
            keyboard_input += (char((c & 0xFF) + 32));

          if ((c & 0xFF) == 93)
            keyboard_input += ("[");

          if ((c & 0xFF) == 94)
            keyboard_input += ("]");

          if ((c & 0xFF) == 91)
            keyboard_input += (";");

          if ((c & 0xFF) == 58)
            keyboard_input += ("'");

          if ((c & 0xFF) == 92)
            keyboard_input += ("\\");

          if ((c & 0xFF) == 59)
            keyboard_input += (",");

          if ((c & 0xFF) == 61)
            keyboard_input += (".");

          if ((c & 0xFF) == 62)
            keyboard_input += ("/");

          if ((c & 0xFF) == 64)
            keyboard_input += ("`");

          if ((c & 0xFF) == 60)
            keyboard_input += ("-");

          if ((c & 0xFF) == 95)
            keyboard_input += ("=");

          check_bounds_and_change_char();
          disp();
        }
      }
    }

    delayMicroseconds(400);
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      //Serial.println(keyboard_input);
      finish_input = true;
    }
    if (encoder_button.hasClicks(5)) {
      //Serial.println(keyboard_input);
      act = false;
      finish_input = true;
    }
    delayMicroseconds(400);
  }
}

void star_encdr_and_keyb_input() {
  finish_input = false;
  while (finish_input == false) {
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
    delayMicroseconds(400);

    a_button.tick();
    if (a_button.press()) {
      keyboard_input += char(curr_key);
      //Serial.println(keyboard_input);
      disp_stars();
    }
    delayMicroseconds(400);

    b_button.tick();
    if (b_button.press()) {
      if (keyboard_input.length() > 0)
        keyboard_input.remove(keyboard_input.length() - 1, 1);
      //Serial.println(keyboard_input);
      gfx->fillRect(0, 48, 312, 192, 0x0000);
      //Serial.println(keyboard_input);
      disp_stars();
    }
    delayMicroseconds(400);

    if (keyboard.available()) {
      // read the next key
      c = keyboard.read();
      if (c > 0 && ((c & 0xFF) != 6)) {
        /*
        if (c & PS2_BREAK) Serial.print("break ~ ");
        if (!(c & PS2_BREAK)) Serial.print("make  ~ ");
        Serial.print( "Value " );
        Serial.print( c, HEX );
        Serial.print( " - Status Bits " );
        Serial.print( c >> 8, HEX );
        Serial.print( "  Code " );
        Serial.println( c & 0xFF, HEX );
        if (!(c & PS2_BREAK))
          Serial.println(char(c & 0xFF));
        */

        if (c >> 8 == 192 && (c & PS2_BREAK)) {
          if ((c & 0xFF) > 64 && (c & 0xFF) < 91) // Capital letters
            keyboard_input += (char(c & 0xFF));

          if ((c & 0xFF) == 93)
            keyboard_input += ("{");

          if ((c & 0xFF) == 94)
            keyboard_input += ("}");

          if ((c & 0xFF) == 91)
            keyboard_input += (":");

          if ((c & 0xFF) == 58)
            keyboard_input += (char(34)); // "

          if ((c & 0xFF) == 92)
            keyboard_input += ("|");

          if ((c & 0xFF) == 59)
            keyboard_input += ("<");

          if ((c & 0xFF) == 61)
            keyboard_input += (">");

          if ((c & 0xFF) == 62)
            keyboard_input += ("?");

          if ((c & 0xFF) == 64)
            keyboard_input += ("~");

          if ((c & 0xFF) == 60)
            keyboard_input += ("_");

          if ((c & 0xFF) == 95)
            keyboard_input += ("+");

          if ((c & 0xFF) == 49)
            keyboard_input += ("!");

          if ((c & 0xFF) == 50)
            keyboard_input += ("@");

          if ((c & 0xFF) == 51)
            keyboard_input += ("#");

          if ((c & 0xFF) == 52)
            keyboard_input += ("$");

          if ((c & 0xFF) == 53)
            keyboard_input += ("%");

          if ((c & 0xFF) == 54)
            keyboard_input += ("^");

          if ((c & 0xFF) == 55)
            keyboard_input += ("&");

          if ((c & 0xFF) == 56)
            keyboard_input += ("*");

          if ((c & 0xFF) == 57)
            keyboard_input += ("(");

          if ((c & 0xFF) == 48)
            keyboard_input += (")");

          check_bounds_and_change_char();
          disp_stars();

        }
        if (c >> 8 == 129 && (c & PS2_BREAK)) {
          bool cll_chck_bnds = true;
          if ((c & 0xFF) == 30) // Enter
            finish_input = true;

          if (c == 33045) {
            curr_key--;
            cll_chck_bnds = false;
            check_bounds();
          }

          if (c == 33046) {
            curr_key++;
            cll_chck_bnds = false;
            check_bounds();
          }

          if (c == 33055)
            keyboard_input += (" "); // Space

          if (c == 33052) { // Backspace
            if (keyboard_input.length() > 0)
              keyboard_input.remove(keyboard_input.length() - 1, 1);
            //Serial.println(keyboard_input);
            gfx->fillRect(0, 48, 312, 192, 0x0000);
          }

          if (cll_chck_bnds == true)
            check_bounds_and_change_char();
          disp_stars();
        }
        if (c >> 8 == 128 && (c & PS2_BREAK)) {

          if ((c & 0xFF) > 47 && (c & 0xFF) < 58) // Digits
            keyboard_input += (char((c & 0xFF)));

          if ((c & 0xFF) > 64 && (c & 0xFF) < 91) // Lowercase letters
            keyboard_input += (char((c & 0xFF) + 32));

          if ((c & 0xFF) == 93)
            keyboard_input += ("[");

          if ((c & 0xFF) == 94)
            keyboard_input += ("]");

          if ((c & 0xFF) == 91)
            keyboard_input += (";");

          if ((c & 0xFF) == 58)
            keyboard_input += ("'");

          if ((c & 0xFF) == 92)
            keyboard_input += ("\\");

          if ((c & 0xFF) == 59)
            keyboard_input += (",");

          if ((c & 0xFF) == 61)
            keyboard_input += (".");

          if ((c & 0xFF) == 62)
            keyboard_input += ("/");

          if ((c & 0xFF) == 64)
            keyboard_input += ("`");

          if ((c & 0xFF) == 60)
            keyboard_input += ("-");

          if ((c & 0xFF) == 95)
            keyboard_input += ("=");

          check_bounds_and_change_char();
          disp_stars();

        }
      }
    }
    delayMicroseconds(400);
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      //Serial.println(keyboard_input);
      finish_input = true;
    }
    delayMicroseconds(400);
  }
}

// Functions that work with files in LittleFS (Below)

void write_to_file_with_overwrite(String filename, String content) {
  LittleFS.remove(filename);
  File testFile = LittleFS.open(filename, "w");
  if (testFile) {
    //Serial.println("Write file content!");
    testFile.print(content);

    testFile.close();
  } else {
    //Serial.println("Problem on create file!");
  }
}

String read_file(String filename) {
  File testFile = LittleFS.open(filename, "r");
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

// Functions for Logins (Below)

void select_login(byte what_to_do_with_it) {
  // 0 - Add login
  // 1 - Edit login
  // 2 - Delete login
  // 3 - View login
  curr_key = 1;
  header_for_select_login(what_to_do_with_it);
  display_title_from_login_without_integrity_verification();
  bool continue_to_next = false;
  while (continue_to_next == false) {
    enc0.tick();

    if (enc0.left()) {
      curr_key--;
    }

    if (enc0.right()) {
      curr_key++;
    }

    if (curr_key < 1)
      curr_key = MAX_NUM_OF_RECS;

    if (curr_key > MAX_NUM_OF_RECS)
      curr_key = 1;

    if (enc0.turn()) {
      header_for_select_login(what_to_do_with_it);
      display_title_from_login_without_integrity_verification();
    }
    delayMicroseconds(500);

    a_button.tick();
    if (a_button.press()) {
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
        if (inptsrc == 1)
          edit_login_from_keyboard_and_encdr(chsn_slot);
        if (inptsrc == 2)
          edit_login_from_serial(chsn_slot);
      }
      if (what_to_do_with_it == 2) {
        delete_login(chsn_slot);
      }
      if (what_to_do_with_it == 3) {
        view_login(chsn_slot);
      }
      continue_to_next = true;
      break;
    }
    delayMicroseconds(500);

    b_button.tick();
    if (b_button.press()) {
      call_main_menu();
      continue_to_next = true;
      break;

    }
    delayMicroseconds(500);

    if (keyboard.available()) {
      // read the next key
      c = keyboard.read();
      if (c > 0 && ((c & 0xFF) != 6)) {
        if (c >> 8 == 129 && (c & PS2_BREAK)) {

          if (c == 33046)
            curr_key++;

          if (c == 33045)
            curr_key--;

          if (curr_key < 1)
            curr_key = MAX_NUM_OF_RECS;

          if (curr_key > MAX_NUM_OF_RECS)
            curr_key = 1;

          if ((c & 0xFF) == 30) { // Enter
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
              if (inptsrc == 1)
                edit_login_from_keyboard_and_encdr(chsn_slot);
              if (inptsrc == 2)
                edit_login_from_serial(chsn_slot);
            }
            if (what_to_do_with_it == 2) {
              delete_login(chsn_slot);
            }
            if (what_to_do_with_it == 3) {
              view_login(chsn_slot);
            }
            continue_to_next = true;
            break;
          }

          if ((c & 0xFF) == 27) {
            call_main_menu();
            continue_to_next = true;
            break;
          }

          header_for_select_login(what_to_do_with_it);
          display_title_from_login_without_integrity_verification();
        }
      }
    }
    delayMicroseconds(500);
  }
  return;
}

void header_for_select_login(byte what_to_do_with_it) {
  gfx->fillScreen(0x0000);
  gfx->setTextSize(2);
  if (what_to_do_with_it == 0) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Add Login to Slot " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 1) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Edit Login " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 2) {
    gfx->setTextColor(five_six_five_red_color);
    disp_centered_text("Delete Login " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation_for_del();
  }
  if (what_to_do_with_it == 3) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("View Login " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
}

void display_title_from_login_without_integrity_verification() {
  gfx->setTextSize(2);
  String encrypted_title = read_file("/L" + String(curr_key) + "_ttl");
  if (encrypted_title == "-1") {
    gfx->setTextColor(0x07e0);
    disp_centered_text("Empty", 35);
  } else {
    clear_variables();
    decrypt_tag = false;
    decrypt_with_TDES_AES_Blowfish_Serp(encrypted_title);
    gfx->setTextColor(0xffff);
    disp_centered_text(dec_st, 35);
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
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
  gfx->fillScreen(0x0000);
  gfx->setTextSize(1);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 0);
  gfx->print("Adding login to the slot N" + String(chsn_slot) + "...");
  gfx->setCursor(0, 10);
  gfx->print("Please wait for a while.");
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_title);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_ttl", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_username);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_usn", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_password);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_psw", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_website);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_wbs", dec_st);
  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(entered_title + entered_username + entered_password + entered_website);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void update_login_and_tag(int chsn_slot, String new_password) {
  gfx->fillScreen(0x0000);
  gfx->setTextSize(1);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 0);
  gfx->print("Editing login in the slot N" + String(chsn_slot) + "...");
  gfx->setCursor(0, 10);
  gfx->print("Please wait for a while.");

  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(new_password);
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
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void edit_login_from_keyboard_and_encdr(int chsn_slot) {
  if (read_file("/L" + String(chsn_slot) + "_psw") == "-1") {
    gfx->fillScreen(0x0000);
    gfx->setTextColor(0x07e0);
    gfx->setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    gfx->setTextSize(1);
    gfx->setTextColor(0xffff);
    disp_centered_text("Press any key to return to the main menu", 232);
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
    gfx->fillScreen(0x0000);
    gfx->setTextColor(0x07e0);
    gfx->setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    gfx->setTextSize(1);
    gfx->setTextColor(0xffff);
    disp_centered_text("Press any key to return to the main menu", 232);
    press_any_key_to_continue();
  }
  else {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("New Password");
    Serial.println("\nPaste new password here:");
    bool canc_op = false;
    while (!Serial.available()) {
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
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
  gfx->fillScreen(0x0000);
  gfx->setTextSize(1);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 0);
  gfx->print("Deleting login from the slot N" + String(chsn_slot) + "...");
  gfx->setCursor(0, 10);
  gfx->print("Please wait for a while.");
  LittleFS.remove("/L" + String(chsn_slot) + "_tag");
  LittleFS.remove("/L" + String(chsn_slot) + "_ttl");
  LittleFS.remove("/L" + String(chsn_slot) + "_usn");
  LittleFS.remove("/L" + String(chsn_slot) + "_psw");
  LittleFS.remove("/L" + String(chsn_slot) + "_wbs");
  clear_variables();
  call_main_menu();
  return;
}

void view_login(int chsn_slot) {
  if (read_file("/L" + String(chsn_slot) + "_ttl") == "-1") {
    gfx->fillScreen(0x0000);
    gfx->setTextColor(0x07e0);
    gfx->setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    gfx->setTextSize(1);
    gfx->setTextColor(0xffff);
    disp_centered_text("Press any key to return to the main menu", 232);
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

    gfx->fillScreen(0x0000);
    gfx->setTextSize(2);
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Title", 5);
    gfx->setTextColor(0xffff);
    gfx->setCursor(0, 35);
    gfx->print(decrypted_title);

    gfx->setTextSize(1);
    if (login_integrity == true) {
      gfx->fillRect(0, 230, 320, 14, 0x0000);
      gfx->fillRect(312, 0, 8, 240, current_inact_clr);
      disp_centered_text("Integrity Verified Successfully!", 232);
    } else {
      gfx->fillRect(0, 230, 320, 14, 0x0000);
      gfx->fillRect(312, 0, 8, 240, five_six_five_red_color);
      disp_centered_text("Integrity Verification Failed!!!", 232);
    }
    press_any_key_to_continue();

    gfx->fillScreen(0x0000);
    gfx->setTextSize(2);
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Username", 5);
    gfx->setTextColor(0xffff);
    gfx->setCursor(0, 35);
    gfx->print(decrypted_username);

    gfx->setTextSize(1);
    if (login_integrity == true) {
      gfx->fillRect(0, 230, 320, 14, 0x0000);
      gfx->fillRect(312, 0, 8, 240, current_inact_clr);
      disp_centered_text("Integrity Verified Successfully!", 232);
    } else {
      gfx->fillRect(0, 230, 320, 14, 0x0000);
      gfx->fillRect(312, 0, 8, 240, five_six_five_red_color);
      disp_centered_text("Integrity Verification Failed!!!", 232);
    }
    press_any_key_to_continue();

    gfx->fillScreen(0x0000);
    gfx->setTextSize(2);
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Password", 5);
    gfx->setTextColor(0xffff);
    gfx->setCursor(0, 35);
    gfx->print(decrypted_password);

    gfx->setTextSize(1);
    if (login_integrity == true) {
      gfx->fillRect(0, 230, 320, 14, 0x0000);
      gfx->fillRect(312, 0, 8, 240, current_inact_clr);
      disp_centered_text("Integrity Verified Successfully!", 232);
    } else {
      gfx->fillRect(0, 230, 320, 14, 0x0000);
      gfx->fillRect(312, 0, 8, 240, five_six_five_red_color);
      disp_centered_text("Integrity Verification Failed!!!", 232);
    }
    press_any_key_to_continue();

    gfx->fillScreen(0x0000);
    gfx->setTextSize(2);
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Website", 5);
    gfx->setTextColor(0xffff);
    gfx->setCursor(0, 35);
    gfx->print(decrypted_website);

    gfx->setTextSize(1);
    if (login_integrity == true) {
      gfx->fillRect(0, 230, 320, 14, 0x0000);
      gfx->fillRect(312, 0, 8, 240, current_inact_clr);
      disp_centered_text("Integrity Verified Successfully!", 232);
    } else {
      gfx->fillRect(0, 230, 320, 14, 0x0000);
      gfx->fillRect(312, 0, 8, 240, five_six_five_red_color);
      disp_centered_text("Integrity Verification Failed!!!", 232);
    }
    press_any_key_to_continue();
  }
}

// Functions for Logins (Above)

// Functions for Credit Cards (Below)

void select_credit_card(byte what_to_do_with_it) {
  curr_key = 1;
  header_for_select_credit_card(what_to_do_with_it);
  display_title_from_credit_card_without_integrity_verification();
  bool continue_to_next = false;
  while (continue_to_next == false) {
    enc0.tick();

    if (enc0.left()) {
      curr_key--;
    }

    if (enc0.right()) {
      curr_key++;
    }

    if (curr_key < 1)
      curr_key = MAX_NUM_OF_RECS;

    if (curr_key > MAX_NUM_OF_RECS)
      curr_key = 1;

    if (enc0.turn()) {
      header_for_select_credit_card(what_to_do_with_it);
      display_title_from_credit_card_without_integrity_verification();
    }
    delayMicroseconds(500);

    a_button.tick();
    if (a_button.press()) {
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
        if (inptsrc == 1)
          edit_credit_card_from_keyboard_and_encdr(chsn_slot);
        if (inptsrc == 2)
          edit_credit_card_from_serial(chsn_slot);
      }
      if (what_to_do_with_it == 2) {
        delete_credit_card(chsn_slot);
      }
      if (what_to_do_with_it == 3) {
        view_credit_card(chsn_slot);
      }
      continue_to_next = true;
      break;
    }
    delayMicroseconds(500);

    b_button.tick();
    if (b_button.press()) {
      call_main_menu();
      continue_to_next = true;
      break;

    }
    delayMicroseconds(500);

    if (keyboard.available()) {
      // read the next key
      c = keyboard.read();
      if (c > 0 && ((c & 0xFF) != 6)) {
        if (c >> 8 == 129 && (c & PS2_BREAK)) {

          if (c == 33046)
            curr_key++;

          if (c == 33045)
            curr_key--;

          if (curr_key < 1)
            curr_key = MAX_NUM_OF_RECS;

          if (curr_key > MAX_NUM_OF_RECS)
            curr_key = 1;

          if ((c & 0xFF) == 30) { // Enter
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
              if (inptsrc == 1)
                edit_credit_card_from_keyboard_and_encdr(chsn_slot);
              if (inptsrc == 2)
                edit_credit_card_from_serial(chsn_slot);
            }
            if (what_to_do_with_it == 2) {
              delete_credit_card(chsn_slot);
            }
            if (what_to_do_with_it == 3) {
              view_credit_card(chsn_slot);
            }
            continue_to_next = true;
            break;
          }

          if ((c & 0xFF) == 27) {
            call_main_menu();
            continue_to_next = true;
            break;
          }

          header_for_select_credit_card(what_to_do_with_it);
          display_title_from_credit_card_without_integrity_verification();
        }
      }
    }
    delayMicroseconds(500);
  }
  return;
}

void header_for_select_credit_card(byte what_to_do_with_it) {
  gfx->fillScreen(0x0000);
  gfx->setTextSize(2);
  if (what_to_do_with_it == 0) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Add Card to Slot " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 1) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Edit Credit Card " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 2) {
    gfx->setTextColor(five_six_five_red_color);
    disp_centered_text("Delete Credit Card " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation_for_del();
  }
  if (what_to_do_with_it == 3) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("View Credit Card " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
}

void display_title_from_credit_card_without_integrity_verification() {
  gfx->setTextSize(2);
  String encrypted_title = read_file("/C" + String(curr_key) + "_ttl");
  if (encrypted_title == "-1") {
    gfx->setTextColor(0x07e0);
    disp_centered_text("Empty", 35);
  } else {
    clear_variables();
    decrypt_tag = false;
    decrypt_with_TDES_AES_Blowfish_Serp(encrypted_title);
    gfx->setTextColor(0xffff);
    disp_centered_text(dec_st, 35);
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
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
  gfx->fillScreen(0x0000);
  gfx->setTextSize(1);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 0);
  gfx->print("Adding credit card to the slot N" + String(chsn_slot) + "...");
  gfx->setCursor(0, 10);
  gfx->print("Please wait for a while.");
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_title);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_ttl", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_cardholder);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_hld", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_card_number);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_nmr", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_expiry);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_exp", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_cvn);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_cvn", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_pin);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_pin", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_zip_code);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_zip", dec_st);
  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(entered_title + entered_cardholder + entered_card_number + entered_expiry + entered_cvn + entered_pin + entered_zip_code);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void update_credit_card_and_tag(int chsn_slot, String new_pin) {
  gfx->fillScreen(0x0000);
  gfx->setTextSize(1);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 0);
  gfx->print("Editing credit card in the slot N" + String(chsn_slot) + "...");
  gfx->setCursor(0, 10);
  gfx->print("Please wait for a while.");
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(new_pin);
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
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void edit_credit_card_from_keyboard_and_encdr(int chsn_slot) {
  if (read_file("/C" + String(chsn_slot) + "_pin") == "-1") {
    gfx->fillScreen(0x0000);
    gfx->setTextColor(0x07e0);
    gfx->setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    gfx->setTextSize(1);
    gfx->setTextColor(0xffff);
    disp_centered_text("Press any key to return to the main menu", 232);
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
    gfx->fillScreen(0x0000);
    gfx->setTextColor(0x07e0);
    gfx->setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    gfx->setTextSize(1);
    gfx->setTextColor(0xffff);
    disp_centered_text("Press any key to return to the main menu", 232);
    press_any_key_to_continue();
  }
  else {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("New PIN");
    Serial.println("\nPaste new PIN here:");
    bool canc_op = false;
    while (!Serial.available()) {
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
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
  gfx->fillScreen(0x0000);
  gfx->setTextSize(1);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 0);
  gfx->print("Deleting credit card from the slot N" + String(chsn_slot) + "...");
  gfx->setCursor(0, 10);
  gfx->print("Please wait for a while.");
  LittleFS.remove("/C" + String(chsn_slot) + "_tag");
  LittleFS.remove("/C" + String(chsn_slot) + "_ttl");
  LittleFS.remove("/C" + String(chsn_slot) + "_hld");
  LittleFS.remove("/C" + String(chsn_slot) + "_nmr");
  LittleFS.remove("/C" + String(chsn_slot) + "_exp");
  LittleFS.remove("/C" + String(chsn_slot) + "_cvn");
  LittleFS.remove("/C" + String(chsn_slot) + "_pin");
  LittleFS.remove("/C" + String(chsn_slot) + "_zip");
  clear_variables();
  call_main_menu();
  return;
}

void view_credit_card(int chsn_slot) {
  if (read_file("/C" + String(chsn_slot) + "_ttl") == "-1") {
    gfx->fillScreen(0x0000);
    gfx->setTextColor(0x07e0);
    gfx->setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    gfx->setTextSize(1);
    gfx->setTextColor(0xffff);
    disp_centered_text("Press any key to return to the main menu", 232);
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
    bool login_integrity = verify_integrity();

    if (login_integrity == true) {
      gfx->fillScreen(0x0000);
      gfx->setTextSize(2);
      gfx->setCursor(0, 5);
      gfx->setTextColor(current_inact_clr);
      gfx->print("Title:");
      gfx->setTextColor(0xffff);
      gfx->println(decrypted_title);
      gfx->setTextColor(current_inact_clr);
      gfx->print("Cardholder Name:");
      gfx->setTextColor(0xffff);
      gfx->println(decrypted_cardholder);
      gfx->setTextColor(current_inact_clr);
      gfx->print("Card Number:");
      gfx->setTextColor(0xffff);
      gfx->println(decrypted_card_number);
      gfx->setTextColor(current_inact_clr);
      gfx->print("Expiration Date:");
      gfx->setTextColor(0xffff);
      gfx->println(decrypted_expiry);
      gfx->setTextColor(current_inact_clr);
      gfx->print("CVN:");
      gfx->setTextColor(0xffff);
      gfx->println(decrypted_cvn);
      gfx->setTextColor(current_inact_clr);
      gfx->print("PIN:");
      gfx->setTextColor(0xffff);
      gfx->println(decrypted_pin);
      gfx->setTextColor(current_inact_clr);
      gfx->print("ZIP Code:");
      gfx->setTextColor(0xffff);
      gfx->println(decrypted_zip_code);
      gfx->setTextSize(1);
      gfx->fillRect(0, 230, 320, 14, 0x0000);
      gfx->fillRect(312, 0, 8, 240, current_inact_clr);
      disp_centered_text("Integrity Verified Successfully!", 232);
    } else {
      gfx->fillScreen(0x0000);
      gfx->setTextSize(2);
      gfx->setCursor(0, 5);
      gfx->setTextColor(current_inact_clr);
      gfx->print("Title:");
      gfx->setTextColor(five_six_five_red_color);
      gfx->println(decrypted_title);
      gfx->setTextColor(current_inact_clr);
      gfx->print("Cardholder Name:");
      gfx->setTextColor(five_six_five_red_color);
      gfx->println(decrypted_cardholder);
      gfx->setTextColor(current_inact_clr);
      gfx->print("Card Number:");
      gfx->setTextColor(five_six_five_red_color);
      gfx->println(decrypted_card_number);
      gfx->setTextColor(current_inact_clr);
      gfx->print("Expiration Date:");
      gfx->setTextColor(five_six_five_red_color);
      gfx->println(decrypted_expiry);
      gfx->setTextColor(current_inact_clr);
      gfx->print("CVN:");
      gfx->setTextColor(five_six_five_red_color);
      gfx->println(decrypted_cvn);
      gfx->setTextColor(current_inact_clr);
      gfx->print("PIN:");
      gfx->setTextColor(five_six_five_red_color);
      gfx->println(decrypted_pin);
      gfx->setTextColor(current_inact_clr);
      gfx->print("ZIP Code:");
      gfx->setTextColor(five_six_five_red_color);
      gfx->println(decrypted_zip_code);
      gfx->setTextSize(1);
      gfx->fillRect(0, 230, 320, 14, 0x0000);
      gfx->fillRect(312, 0, 8, 240, five_six_five_red_color);
      disp_centered_text("Integrity Verification Failed!!!", 232);
    }
    press_any_key_to_continue();
  }
}

// Functions for Credit Cards (Above)

// Functions for Notes (Below)

void select_note(byte what_to_do_with_it) {
  curr_key = 1;
  header_for_select_note(what_to_do_with_it);
  display_title_from_note_without_integrity_verification();
  bool continue_to_next = false;
  while (continue_to_next == false) {
    enc0.tick();

    if (enc0.left()) {
      curr_key--;
    }

    if (enc0.right()) {
      curr_key++;
    }

    if (curr_key < 1)
      curr_key = MAX_NUM_OF_RECS;

    if (curr_key > MAX_NUM_OF_RECS)
      curr_key = 1;

    if (enc0.turn()) {
      header_for_select_note(what_to_do_with_it);
      display_title_from_note_without_integrity_verification();
    }
    delayMicroseconds(500);

    a_button.tick();
    if (a_button.press()) {
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
        if (inptsrc == 1)
          edit_note_from_keyboard_and_encdr(chsn_slot);
        if (inptsrc == 2)
          edit_note_from_serial(chsn_slot);
      }
      if (what_to_do_with_it == 2) {
        delete_note(chsn_slot);
      }
      if (what_to_do_with_it == 3) {
        view_note(chsn_slot);
      }
      continue_to_next = true;
      break;
    }
    delayMicroseconds(500);

    b_button.tick();
    if (b_button.press()) {
      call_main_menu();
      continue_to_next = true;
      break;

    }
    delayMicroseconds(500);

    if (keyboard.available()) {
      // read the next key
      c = keyboard.read();
      if (c > 0 && ((c & 0xFF) != 6)) {
        if (c >> 8 == 129 && (c & PS2_BREAK)) {

          if (c == 33046)
            curr_key++;

          if (c == 33045)
            curr_key--;

          if (curr_key < 1)
            curr_key = MAX_NUM_OF_RECS;

          if (curr_key > MAX_NUM_OF_RECS)
            curr_key = 1;

          if ((c & 0xFF) == 30) { // Enter
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
              if (inptsrc == 1)
                edit_note_from_keyboard_and_encdr(chsn_slot);
              if (inptsrc == 2)
                edit_note_from_serial(chsn_slot);
            }
            if (what_to_do_with_it == 2) {
              delete_note(chsn_slot);
            }
            if (what_to_do_with_it == 3) {
              view_note(chsn_slot);
            }
            continue_to_next = true;
            break;
          }

          if ((c & 0xFF) == 27) {
            call_main_menu();
            continue_to_next = true;
            break;
          }

          header_for_select_note(what_to_do_with_it);
          display_title_from_note_without_integrity_verification();
        }
      }
    }
    delayMicroseconds(500);
  }
  return;
}

void header_for_select_note(byte what_to_do_with_it) {
  gfx->fillScreen(0x0000);
  gfx->setTextSize(2);
  if (what_to_do_with_it == 0) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Add Note to Slot " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 1) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Edit Note " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 2) {
    gfx->setTextColor(five_six_five_red_color);
    disp_centered_text("Delete Note " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation_for_del();
  }
  if (what_to_do_with_it == 3) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("View Note " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
}

void display_title_from_note_without_integrity_verification() {
  gfx->setTextSize(2);
  String encrypted_title = read_file("/N" + String(curr_key) + "_ttl");
  if (encrypted_title == "-1") {
    gfx->setTextColor(0x07e0);
    disp_centered_text("Empty", 35);
  } else {
    clear_variables();
    decrypt_tag = false;
    decrypt_with_TDES_AES_Blowfish_Serp(encrypted_title);
    gfx->setTextColor(0xffff);
    disp_centered_text(dec_st, 35);
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
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
  gfx->fillScreen(0x0000);
  gfx->setTextSize(1);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 0);
  gfx->print("Adding note to the slot N" + String(chsn_slot) + "...");
  gfx->setCursor(0, 10);
  gfx->print("Please wait for a while.");
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_title);
  write_to_file_with_overwrite("/N" + String(chsn_slot) + "_ttl", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_content);
  write_to_file_with_overwrite("/N" + String(chsn_slot) + "_cnt", dec_st);
  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(entered_title + entered_content);
  write_to_file_with_overwrite("/N" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void update_note_and_tag(int chsn_slot, String new_content) {
  gfx->fillScreen(0x0000);
  gfx->setTextSize(1);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 0);
  gfx->print("Editing note in the slot N" + String(chsn_slot) + "...");
  gfx->setCursor(0, 10);
  gfx->print("Please wait for a while.");

  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(new_content);
  write_to_file_with_overwrite("/N" + String(chsn_slot) + "_cnt", dec_st);

  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/N" + String(chsn_slot) + "_ttl"));
  String decrypted_title = dec_st;

  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(decrypted_title + new_content);
  write_to_file_with_overwrite("/N" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void edit_note_from_keyboard_and_encdr(int chsn_slot) {
  if (read_file("/N" + String(chsn_slot) + "_cnt") == "-1") {
    gfx->fillScreen(0x0000);
    gfx->setTextColor(0x07e0);
    gfx->setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    gfx->setTextSize(1);
    gfx->setTextColor(0xffff);
    disp_centered_text("Press any key to return to the main menu", 232);
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
    gfx->fillScreen(0x0000);
    gfx->setTextColor(0x07e0);
    gfx->setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    gfx->setTextSize(1);
    gfx->setTextColor(0xffff);
    disp_centered_text("Press any key to return to the main menu", 232);
    press_any_key_to_continue();
  }
  else {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("New Content");
    Serial.println("\nPaste new content here:");
    bool canc_op = false;
    while (!Serial.available()) {
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
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
  gfx->fillScreen(0x0000);
  gfx->setTextSize(1);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 0);
  gfx->print("Deleting note from the slot N" + String(chsn_slot) + "...");
  gfx->setCursor(0, 10);
  gfx->print("Please wait for a while.");
  LittleFS.remove("/N" + String(chsn_slot) + "_tag");
  LittleFS.remove("/N" + String(chsn_slot) + "_ttl");
  LittleFS.remove("/N" + String(chsn_slot) + "_cnt");
  clear_variables();
  call_main_menu();
  return;
}

void view_note(int chsn_slot) {
  if (read_file("/N" + String(chsn_slot) + "_ttl") == "-1") {
    gfx->fillScreen(0x0000);
    gfx->setTextColor(0x07e0);
    gfx->setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    gfx->setTextSize(1);
    gfx->setTextColor(0xffff);
    disp_centered_text("Press any key to return to the main menu", 232);
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
    bool login_integrity = verify_integrity();

    if (login_integrity == true) {
      gfx->fillScreen(0x0000);
      gfx->setTextSize(2);
      gfx->setCursor(0, 5);
      gfx->setTextColor(current_inact_clr);
      gfx->print("Title:");
      gfx->setTextColor(0xffff);
      gfx->println(decrypted_title);
      gfx->setTextColor(current_inact_clr);
      gfx->print("Content:");
      gfx->setTextColor(0xffff);
      gfx->println(decrypted_content);
      gfx->setTextSize(1);
      gfx->fillRect(0, 230, 320, 14, 0x0000);
      gfx->fillRect(312, 0, 8, 240, current_inact_clr);
      disp_centered_text("Integrity Verified Successfully!", 232);
    } else {
      gfx->fillScreen(0x0000);
      gfx->setTextSize(2);
      gfx->setCursor(0, 5);
      gfx->setTextColor(current_inact_clr);
      gfx->print("Title:");
      gfx->setTextColor(five_six_five_red_color);
      gfx->println(decrypted_title);
      gfx->setTextColor(current_inact_clr);
      gfx->print("Content:");
      gfx->setTextColor(five_six_five_red_color);
      gfx->println(decrypted_content);
      gfx->setTextSize(1);
      gfx->fillRect(0, 230, 320, 14, 0x0000);
      gfx->fillRect(312, 0, 8, 240, five_six_five_red_color);
      disp_centered_text("Integrity Verification Failed!!!", 232);
    }
    press_any_key_to_continue();
  }
}

// Functions for Notes (Above)

// Functions for Phone Numbers (Below)

void select_phone_number(byte what_to_do_with_it) {
  curr_key = 1;
  header_for_select_phone_number(what_to_do_with_it);
  display_title_from_phone_number_without_integrity_verification();
  bool continue_to_next = false;
  while (continue_to_next == false) {
    enc0.tick();

    if (enc0.left()) {
      curr_key--;
    }

    if (enc0.right()) {
      curr_key++;
    }

    if (curr_key < 1)
      curr_key = MAX_NUM_OF_RECS;

    if (curr_key > MAX_NUM_OF_RECS)
      curr_key = 1;

    if (enc0.turn()) {
      header_for_select_phone_number(what_to_do_with_it);
      display_title_from_phone_number_without_integrity_verification();
    }
    delayMicroseconds(500);

    a_button.tick();
    if (a_button.press()) {
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
        if (inptsrc == 1)
          edit_phone_number_from_keyboard_and_encdr(chsn_slot);
        if (inptsrc == 2)
          edit_phone_number_from_serial(chsn_slot);
      }
      if (what_to_do_with_it == 2) {
        delete_phone_number(chsn_slot);
      }
      if (what_to_do_with_it == 3) {
        view_phone_number(chsn_slot);
      }
      continue_to_next = true;
      break;
    }
    delayMicroseconds(500);

    b_button.tick();
    if (b_button.press()) {
      call_main_menu();
      continue_to_next = true;
      break;

    }
    delayMicroseconds(500);

    if (keyboard.available()) {
      // read the next key
      c = keyboard.read();
      if (c > 0 && ((c & 0xFF) != 6)) {
        if (c >> 8 == 129 && (c & PS2_BREAK)) {

          if (c == 33046)
            curr_key++;

          if (c == 33045)
            curr_key--;

          if (curr_key < 1)
            curr_key = MAX_NUM_OF_RECS;

          if (curr_key > MAX_NUM_OF_RECS)
            curr_key = 1;

          if ((c & 0xFF) == 30) { // Enter
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
              if (inptsrc == 1)
                edit_phone_number_from_keyboard_and_encdr(chsn_slot);
              if (inptsrc == 2)
                edit_phone_number_from_serial(chsn_slot);
            }
            if (what_to_do_with_it == 2) {
              delete_phone_number(chsn_slot);
            }
            if (what_to_do_with_it == 3) {
              view_phone_number(chsn_slot);
            }
            continue_to_next = true;
            break;
          }

          if ((c & 0xFF) == 27) {
            call_main_menu();
            continue_to_next = true;
            break;
          }

          header_for_select_phone_number(what_to_do_with_it);
          display_title_from_phone_number_without_integrity_verification();
        }
      }
    }
    delayMicroseconds(500);
  }
  return;
}

void header_for_select_phone_number(byte what_to_do_with_it) {
  gfx->fillScreen(0x0000);
  gfx->setTextSize(2);
  if (what_to_do_with_it == 0) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Add Phone to Slot " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 1) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Edit Phone Number " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 2) {
    gfx->setTextColor(five_six_five_red_color);
    disp_centered_text("Delete Phone " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation_for_del();
  }
  if (what_to_do_with_it == 3) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("View Phone Number " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
}

void display_title_from_phone_number_without_integrity_verification() {
  gfx->setTextSize(2);
  String encrypted_title = read_file("/P" + String(curr_key) + "_ttl");
  if (encrypted_title == "-1") {
    gfx->setTextColor(0x07e0);
    disp_centered_text("Empty", 35);
  } else {
    clear_variables();
    decrypt_tag = false;
    decrypt_with_TDES_AES_Blowfish_Serp(encrypted_title);
    gfx->setTextColor(0xffff);
    disp_centered_text(dec_st, 35);
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
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
  gfx->fillScreen(0x0000);
  gfx->setTextSize(1);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 0);
  gfx->print("Adding phone number to the slot N" + String(chsn_slot) + "...");
  gfx->setCursor(0, 10);
  gfx->print("Please wait for a while.");
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_title);
  write_to_file_with_overwrite("/P" + String(chsn_slot) + "_ttl", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_phone_number);
  write_to_file_with_overwrite("/P" + String(chsn_slot) + "_cnt", dec_st);
  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(entered_title + entered_phone_number);
  write_to_file_with_overwrite("/P" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void update_phone_number_and_tag(int chsn_slot, String new_phone_number) {
  gfx->fillScreen(0x0000);
  gfx->setTextSize(1);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 0);
  gfx->print("Editing phone number in the slot N" + String(chsn_slot) + "...");
  gfx->setCursor(0, 10);
  gfx->print("Please wait for a while.");

  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(new_phone_number);
  write_to_file_with_overwrite("/P" + String(chsn_slot) + "_cnt", dec_st);

  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/P" + String(chsn_slot) + "_ttl"));
  String decrypted_title = dec_st;

  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(decrypted_title + new_phone_number);
  write_to_file_with_overwrite("/P" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void edit_phone_number_from_keyboard_and_encdr(int chsn_slot) {
  if (read_file("/P" + String(chsn_slot) + "_cnt") == "-1") {
    gfx->fillScreen(0x0000);
    gfx->setTextColor(0x07e0);
    gfx->setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    gfx->setTextSize(1);
    gfx->setTextColor(0xffff);
    disp_centered_text("Press any key to return to the main menu", 232);
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
    gfx->fillScreen(0x0000);
    gfx->setTextColor(0x07e0);
    gfx->setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    gfx->setTextSize(1);
    gfx->setTextColor(0xffff);
    disp_centered_text("Press any key to return to the main menu", 232);
    press_any_key_to_continue();
  } else {
    bool cont_to_next = false;
    while (cont_to_next == false) {
      disp_paste_smth_inscr("New Phone Number");
      Serial.println("\nPaste new phone number here:");
      bool canc_op = false;
      while (!Serial.available()) {
        a_button.tick();
        if (a_button.press()) {
          canc_op = true;
          break;
        }
        delayMicroseconds(400);

        b_button.tick();
        if (b_button.press()) {
          canc_op = true;
          break;
        }
        delayMicroseconds(400);

        if (keyboard.available()) {
          c = keyboard.read();
          if (c > 0 && ((c & 0xFF) != 6)) {
            if (c >> 8 == 192 && (c & PS2_BREAK)) {
              canc_op = true;
              break;
            }
            if (c >> 8 == 129 && (c & PS2_BREAK)) {
              canc_op = true;
              break;
            }
            if (c >> 8 == 128 && (c & PS2_BREAK)) {
              canc_op = true;
              break;
            }
          }
        }

        delayMicroseconds(400);
        encoder_button.tick();
        if (encoder_button.press()) {
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
  gfx->fillScreen(0x0000);
  gfx->setTextSize(1);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 0);
  gfx->print("Deleting phone number from the slot N" + String(chsn_slot) + "...");
  gfx->setCursor(0, 10);
  gfx->print("Please wait for a while.");
  LittleFS.remove("/P" + String(chsn_slot) + "_tag");
  LittleFS.remove("/P" + String(chsn_slot) + "_ttl");
  LittleFS.remove("/P" + String(chsn_slot) + "_cnt");
  clear_variables();
  call_main_menu();
  return;
}

void view_phone_number(int chsn_slot) {
  if (read_file("/P" + String(chsn_slot) + "_ttl") == "-1") {
    gfx->fillScreen(0x0000);
    gfx->setTextColor(0x07e0);
    gfx->setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    gfx->setTextSize(1);
    gfx->setTextColor(0xffff);
    disp_centered_text("Press any key to return to the main menu", 232);
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
    bool login_integrity = verify_integrity();

    if (login_integrity == true) {
      gfx->fillScreen(0x0000);
      gfx->setTextSize(2);
      gfx->setCursor(0, 5);
      gfx->setTextColor(current_inact_clr);
      gfx->print("Title:");
      gfx->setTextColor(0xffff);
      gfx->println(decrypted_title);
      gfx->setTextColor(current_inact_clr);
      gfx->print("Phone Number:");
      gfx->setTextColor(0xffff);
      gfx->println(decrypted_phone_number);
      gfx->setTextSize(1);
      gfx->fillRect(0, 230, 320, 14, 0x0000);
      gfx->fillRect(312, 0, 8, 240, current_inact_clr);
      disp_centered_text("Integrity Verified Successfully!", 232);
    } else {
      gfx->fillScreen(0x0000);
      gfx->setTextSize(2);
      gfx->setCursor(0, 5);
      gfx->setTextColor(current_inact_clr);
      gfx->print("Title:");
      gfx->setTextColor(five_six_five_red_color);
      gfx->println(decrypted_title);
      gfx->setTextColor(current_inact_clr);
      gfx->print("Phone Number:");
      gfx->setTextColor(five_six_five_red_color);
      gfx->println(decrypted_phone_number);
      gfx->setTextSize(1);
      gfx->fillRect(0, 230, 320, 14, 0x0000);
      gfx->fillRect(312, 0, 8, 240, five_six_five_red_color);
      disp_centered_text("Integrity Verification Failed!!!", 232);
    }
    press_any_key_to_continue();
  }
}

// Functions for Phone Number (Above)

// Functions that work with files in LittleFS (Above)

void press_any_key_to_continue() {
  bool break_the_loop = false;
  while (break_the_loop == false) {

    a_button.tick();
    if (a_button.press())
      break_the_loop = true;
    delayMicroseconds(400);

    b_button.tick();
    if (b_button.press())
      break_the_loop = true;
    delayMicroseconds(400);

    if (keyboard.available()) {
      c = keyboard.read();
      if (c > 0 && ((c & 0xFF) != 6)) {
        if (c >> 8 == 192 && (c & PS2_BREAK)) {
          break_the_loop = true;
        }
        if (c >> 8 == 129 && (c & PS2_BREAK)) {
          break_the_loop = true;
        }
        if (c >> 8 == 128 && (c & PS2_BREAK)) {
          break_the_loop = true;
        }
      }
    }

    delayMicroseconds(400);
    encoder_button.tick();
    if (encoder_button.press()) {
      break_the_loop = true;
    }
    delayMicroseconds(400);
  }
}

void continue_to_unlock() {
  if (read_file("/mpass").equals("-1"))
    set_pass();
  else
    unlock_midbar();
  return;
}

void set_pass() {
  clear_variables();
  gfx->fillScreen(0x0000);
  gfx->setTextColor(0xffff);
  gfx->setTextSize(1);
  set_stuff_for_input("Set Master Password");
  encdr_and_keyb_input();
  gfx->fillScreen(0x0000);
  gfx->setTextSize(2);
  for (int i = 0; i < 161; i++) {
    for (int j = 0; j < 40; j++) {
      gfx->drawPixel(i + 79, j + 10, handwritten_midbar[i][j]);
    }
  }
  gfx->setTextColor(0xffff);
  disp_centered_text("Setting Master Password", 65);
  disp_centered_text("Please wait", 85);
  disp_centered_text("for a while", 105);
  //Serial.println(keyboard_input);
  String bck = keyboard_input;
  modify_keys();
  keyboard_input = bck;
  set_psswd();
  gfx->fillScreen(0x0000);
  gfx->setTextSize(2);
  for (int i = 0; i < 161; i++) {
    for (int j = 0; j < 40; j++) {
      gfx->drawPixel(i + 79, j + 10, handwritten_midbar[i][j]);
    }
  }
  gfx->setTextColor(0xffff);
  disp_centered_text("Master Password Set", 65);
  disp_centered_text("Successfully", 85);
  disp_centered_text("Press Enter", 105);
  disp_centered_text("or Quad-click", 125);
  disp_centered_text("the encoder button", 145);
  disp_centered_text("to continue", 165);
  bool cont1 = true;
  while (cont1 == true) {
    encoder_button.tick();
    if (encoder_button.hasClicks(4))
      cont1 = false;
    delayMicroseconds(400);
    if (keyboard.available()) {
      c = keyboard.read();
      if (c > 0 && ((c & 0xFF) != 6)) {
        if (c >> 8 == 129 && (c & PS2_BREAK)) {
          if ((c & 0xFF) == 30) // Enter
            cont1 = false;
        }
      }
    }
    delayMicroseconds(400);
  }
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
  }
  //Serial.println();
  //Serial.println(h);
  back_keys();
  dec_st = "";
  encr_hash_for_tdes_aes_blf_srp(h);
  rest_keys();
  //Serial.println(dec_st);

  write_to_file_with_overwrite("/mpass", dec_st);
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
  gfx->fillScreen(0x0000);
  gfx->setTextColor(0xffff);
  gfx->setTextSize(2);
  set_stuff_for_input("Enter Master Password");
  star_encdr_and_keyb_input();
  gfx->fillScreen(0x0000);
  for (int i = 0; i < 125; i++) {
    for (int j = 0; j < 40; j++) {
      gfx->drawPixel(i + 97, j + 10, handwritten_midbar[i + 193][j]);
    }
  }
  gfx->setTextSize(2);
  disp_centered_text("Unlocking Midbar", 65);
  disp_centered_text("Please wait", 85);
  disp_centered_text("for a while", 105);
  //Serial.println(keyboard_input);
  String bck = keyboard_input;
  modify_keys();
  keyboard_input = bck;
  bool next_act = hash_psswd();
  clear_variables();
  gfx->fillScreen(0x0000);
  for (int i = 0; i < 125; i++) {
    for (int j = 0; j < 40; j++) {
      gfx->drawPixel(i + 97, j + 10, handwritten_midbar[i + 193][j]);
    }
  }
  if (next_act == true) {
    gfx->setTextSize(2);
    disp_centered_text("Midbar unlocked", 65);
    disp_centered_text("successfully", 85);
    disp_centered_text("Press Enter", 105);
    disp_centered_text("or Quad-click", 125);
    disp_centered_text("the encoder button", 145);
    disp_centered_text("to continue", 165);
    bool cont1 = true;
    while (cont1 == true) {
      encoder_button.tick();
      if (encoder_button.hasClicks(4))
        cont1 = false;
      delayMicroseconds(400);
      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            if ((c & 0xFF) == 30) // Enter
              cont1 = false;
          }
        }
      }
      delayMicroseconds(400);
    }
    call_main_menu();
    return;
  } else {
    gfx->setTextSize(2);
    gfx->setTextColor(five_six_five_red_color);
    disp_centered_text("Wrong Password!", 65);
    gfx->setTextColor(0xffff);
    disp_centered_text("Please reboot", 100);
    disp_centered_text("the device", 120);
    disp_centered_text("and try again", 140);
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
  //Serial.println(read_file("/mpass"));
  decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file("/mpass"));
  //Serial.println(dec_tag);
  return dec_tag.equals(res_hash);
}

void disp_centered_text(String text, int h) {
  int16_t x1;
  int16_t y1;
  uint16_t width;
  uint16_t height;

  gfx->getTextBounds(text, 0, 0, & x1, & y1, & width, & height);
  gfx->setCursor((320 - width) / 2, h);
  gfx->print(text);
}

// Menu (below)

void disp_button_designation() {
  gfx->setTextSize(1);
  gfx->setTextColor(0x07e0);
  gfx->setCursor(0, 232);
  gfx->print("A button, 'Enter' - continue ");
  gfx->setTextColor(five_six_five_red_color);
  gfx->print("B button, 'Esc' - cancel");
}

void disp_button_designation_for_del() {
  gfx->setTextSize(1);
  gfx->setTextColor(five_six_five_red_color);
  gfx->setCursor(0, 232);
  gfx->print("A button, 'Enter' - continue ");
  gfx->setTextColor(0x07e0);
  gfx->print("B button, 'Esc' - cancel");
}

void call_main_menu() {
  gfx->fillScreen(0x0000);
  for (int i = 0; i < 320; i++) {
    for (int j = 0; j < 40; j++) {
      gfx->drawPixel(i, j + 10, handwritten_midbar[i][j]);
    }
  }
  curr_key = 0;
  main_menu(curr_key);
}

void main_menu(int curr_pos) {
  gfx->setTextSize(2);
  byte sdown = 60;
  if (curr_pos == 0) {
    gfx->setTextColor(0xffff);
    disp_centered_text("Logins", sdown + 10);
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Credit Cards", sdown + 30);
    disp_centered_text("Notes", sdown + 50);
    disp_centered_text("Phone Numbers", sdown + 70);
    disp_centered_text("Encryption Algorithms", sdown + 90);
    disp_centered_text("Hash Functions", sdown + 110);
    disp_centered_text("Factory Reset", sdown + 130);
  }
  if (curr_pos == 1) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    gfx->setTextColor(0xffff);
    disp_centered_text("Credit Cards", sdown + 30);
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Notes", sdown + 50);
    disp_centered_text("Phone Numbers", sdown + 70);
    disp_centered_text("Encryption Algorithms", sdown + 90);
    disp_centered_text("Hash Functions", sdown + 110);
    disp_centered_text("Factory Reset", sdown + 130);
  }
  if (curr_pos == 2) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    disp_centered_text("Credit Cards", sdown + 30);
    gfx->setTextColor(0xffff);
    disp_centered_text("Notes", sdown + 50);
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Phone Numbers", sdown + 70);
    disp_centered_text("Encryption Algorithms", sdown + 90);
    disp_centered_text("Hash Functions", sdown + 110);
    disp_centered_text("Factory Reset", sdown + 130);
  }
  if (curr_pos == 3) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    disp_centered_text("Credit Cards", sdown + 30);
    disp_centered_text("Notes", sdown + 50);
    gfx->setTextColor(0xffff);
    disp_centered_text("Phone Numbers", sdown + 70);
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Encryption Algorithms", sdown + 90);
    disp_centered_text("Hash Functions", sdown + 110);
    disp_centered_text("Factory Reset", sdown + 130);
  }
  if (curr_pos == 4) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    disp_centered_text("Credit Cards", sdown + 30);
    disp_centered_text("Notes", sdown + 50);
    disp_centered_text("Phone Numbers", sdown + 70);
    gfx->setTextColor(0xffff);
    disp_centered_text("Encryption Algorithms", sdown + 90);
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Hash Functions", sdown + 110);
    disp_centered_text("Factory Reset", sdown + 130);
  }
  if (curr_pos == 5) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    disp_centered_text("Credit Cards", sdown + 30);
    disp_centered_text("Notes", sdown + 50);
    disp_centered_text("Phone Numbers", sdown + 70);
    disp_centered_text("Encryption Algorithms", sdown + 90);
    gfx->setTextColor(0xffff);
    disp_centered_text("Hash Functions", sdown + 110);
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Factory Reset", sdown + 130);
  }
  if (curr_pos == 6) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    disp_centered_text("Credit Cards", sdown + 30);
    disp_centered_text("Notes", sdown + 50);
    disp_centered_text("Phone Numbers", sdown + 70);
    disp_centered_text("Encryption Algorithms", sdown + 90);
    disp_centered_text("Hash Functions", sdown + 110);
    gfx->setTextColor(0xffff);
    disp_centered_text("Factory Reset", sdown + 130);
  }
}

void input_source_for_data_in_flash_menu(int curr_pos) {
  gfx->setTextSize(2);
  byte sdown = 60;
  if (curr_pos == 0) {
    gfx->setTextColor(0xffff);
    disp_centered_text("Encoder + Keyboard", sdown + 10);
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Serial Terminal", sdown + 30);
  }
  if (curr_pos == 1) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Encoder + Keyboard", sdown + 10);
    gfx->setTextColor(0xffff);
    disp_centered_text("Serial Terminal", sdown + 30);
  }
}

byte input_source_for_data_in_flash() {
  byte inpsrc = 0;
  gfx->fillScreen(0x0000);
  gfx->setTextSize(2);
  gfx->setTextColor(current_inact_clr);
  disp_centered_text("Choose Input Source", 10);
  curr_key = 0;
  input_source_for_data_in_flash_menu(curr_key);
  disp_button_designation();
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
      input_source_for_data_in_flash_menu(curr_key);
    }

    a_button.tick();
    if (a_button.press()) {
      if (curr_key == 0) {
        inpsrc = 1;
      }

      if (curr_key == 1) {
        inpsrc = 2;
      }
      cont_to_next = true;
      break;
    }

    b_button.tick();
    if (b_button.press()) {
      cont_to_next = true;
      break;
    }

    delayMicroseconds(400);
    if (keyboard.available()) {
      c = keyboard.read();
      if (c > 0 && ((c & 0xFF) != 6)) {
        if (c >> 8 == 129 && (c & PS2_BREAK)) {

          if (c == 33047)
            curr_key--;

          if (c == 33048)
            curr_key++;

          if (curr_key < 0)
            curr_key = 1;

          if (curr_key > 1)
            curr_key = 0;

          if ((c & 0xFF) == 30) {
            if (curr_key == 0) {
              inpsrc = 1;
            }

            if (curr_key == 1) {
              inpsrc = 2;
            }
            cont_to_next = true;
            break;
          }
          if ((c & 0xFF) == 27) {
            cont_to_next = true;
            break;
          }
          input_source_for_data_in_flash_menu(curr_key);

        }
      }
    }
  }
  return inpsrc;
}

void action_for_data_in_flash_menu(int curr_pos) {
  gfx->setTextSize(2);
  byte sdown = 60;
  if (curr_pos == 0) {
    gfx->setTextColor(0xffff);
    disp_centered_text("Add", sdown + 10);
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Edit", sdown + 30);
    disp_centered_text("Delete", sdown + 50);
    disp_centered_text("View", sdown + 70);
  }
  if (curr_pos == 1) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Add", sdown + 10);
    gfx->setTextColor(0xffff);
    disp_centered_text("Edit", sdown + 30);
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Delete", sdown + 50);
    disp_centered_text("View", sdown + 70);
  }
  if (curr_pos == 2) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Add", sdown + 10);
    disp_centered_text("Edit", sdown + 30);
    gfx->setTextColor(0xffff);
    disp_centered_text("Delete", sdown + 50);
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("View", sdown + 70);
  }
  if (curr_pos == 3) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Add", sdown + 10);
    disp_centered_text("Edit", sdown + 30);
    disp_centered_text("Delete", sdown + 50);
    gfx->setTextColor(0xffff);
    disp_centered_text("View", sdown + 70);
  }
}

void action_for_data_in_flash(String menu_title, byte record_type) {
  gfx->fillScreen(0x0000);
  gfx->setTextSize(2);
  gfx->setTextColor(current_inact_clr);
  disp_centered_text(menu_title, 10);
  curr_key = 0;
  action_for_data_in_flash_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
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
      action_for_data_in_flash_menu(curr_key);
    }

    trash = rnd_whitened();
    delayMicroseconds(400);

    a_button.tick();
    if (a_button.press()) {
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

      if (curr_key == 1) {
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

      if (curr_key == 2) {
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

      if (curr_key == 3) {
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
    }

    b_button.tick();
    if (b_button.press()) {
      cont_to_next = true;
    }

    delayMicroseconds(400);
    if (keyboard.available()) {
      c = keyboard.read();
      if (c > 0 && ((c & 0xFF) != 6)) {
        if (c >> 8 == 129 && (c & PS2_BREAK)) {

          if (c == 33047)
            curr_key--;

          if (c == 33048)
            curr_key++;

          if (curr_key < 0)
            curr_key = 3;

          if (curr_key > 3)
            curr_key = 0;

          if ((c & 0xFF) == 30) {
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

            if (curr_key == 1) {
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

            if (curr_key == 2) {
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

            if (curr_key == 3) {
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
          }
          if ((c & 0xFF) == 27) {
            cont_to_next = true;
          }
          action_for_data_in_flash_menu(curr_key);
        }
      }
    }
  }
  call_main_menu();
}

void input_source_for_encr_algs_menu(int curr_pos) {
  gfx->setTextSize(2);
  byte sdown = 60;
  if (curr_pos == 0) {
    gfx->setTextColor(0xffff);
    disp_centered_text("Encoder + Keyboard", sdown + 10);
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Serial Terminal", sdown + 30);
  }
  if (curr_pos == 1) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Encoder + Keyboard", sdown + 10);
    gfx->setTextColor(0xffff);
    disp_centered_text("Serial Terminal", sdown + 30);
  }
}

void input_source_for_encr_algs(byte record_type) {
  gfx->fillScreen(0x0000);
  gfx->setTextSize(2);
  gfx->setTextColor(current_inact_clr);
  disp_centered_text("Choose Input Source", 10);
  curr_key = 0;
  input_source_for_encr_algs_menu(curr_key);
  disp_button_designation();
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
      input_source_for_encr_algs_menu(curr_key);
    }

    a_button.tick();
    if (a_button.press()) {
      if (curr_key == 0) {
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

      if (curr_key == 1) {
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

    b_button.tick();
    if (b_button.press()) {
      cont_to_next = true;
    }

    delayMicroseconds(400);
    if (keyboard.available()) {
      c = keyboard.read();
      if (c > 0 && ((c & 0xFF) != 6)) {
        if (c >> 8 == 129 && (c & PS2_BREAK)) {

          if (c == 33047)
            curr_key--;

          if (c == 33048)
            curr_key++;

          if (curr_key < 0)
            curr_key = 1;

          if (curr_key > 1)
            curr_key = 0;

          if ((c & 0xFF) == 30) {

            if (curr_key == 0) {
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

            if (curr_key == 1) {
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
          if ((c & 0xFF) == 27) {
            cont_to_next = true;
          }
          input_source_for_encr_algs_menu(curr_key);
        }
      }
    }
  }
  call_main_menu();
}

void what_to_do_with_encr_alg_menu(int curr_pos) {
  gfx->setTextSize(2);
  byte sdown = 60;
  if (curr_pos == 0) {
    gfx->setTextColor(0xffff);
    disp_centered_text("Encrypt String", sdown + 10);
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Decrypt String", sdown + 30);
  }
  if (curr_pos == 1) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Encrypt String", sdown + 10);
    gfx->setTextColor(0xffff);
    disp_centered_text("Decrypt String", sdown + 30);
  }
}

void what_to_do_with_encr_alg(String menu_title, byte record_type) {
  gfx->fillScreen(0x0000);
  gfx->setTextSize(2);
  gfx->setTextColor(current_inact_clr);
  disp_centered_text(menu_title, 10);
  curr_key = 0;
  what_to_do_with_encr_alg_menu(curr_key);
  disp_button_designation();
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
      what_to_do_with_encr_alg_menu(curr_key);
    }

    a_button.tick();
    if (a_button.press()) {
      if (curr_key == 0) {
        input_source_for_encr_algs(record_type);
        cont_to_next = true;
      }

      if (curr_key == 1) {
        where_to_print_plaintext(record_type);
        cont_to_next = true;
      }
    }

    b_button.tick();
    if (b_button.press()) {
      cont_to_next = true;
    }

    delayMicroseconds(400);
    if (keyboard.available()) {
      c = keyboard.read();
      if (c > 0 && ((c & 0xFF) != 6)) {
        if (c >> 8 == 129 && (c & PS2_BREAK)) {

          if (c == 33047)
            curr_key--;

          if (c == 33048)
            curr_key++;

          if (curr_key < 0)
            curr_key = 1;

          if (curr_key > 1)
            curr_key = 0;

          if ((c & 0xFF) == 30) {
            if (curr_key == 0) {
              input_source_for_encr_algs(record_type);
              cont_to_next = true;
            }

            if (curr_key == 1) {
              where_to_print_plaintext(record_type);
              cont_to_next = true;
            }
          }
          if ((c & 0xFF) == 27) {
            cont_to_next = true;
          }
          what_to_do_with_encr_alg_menu(curr_key);
        }
      }
    }
  }
  call_main_menu();
}

void where_to_print_plaintext_menu(int curr_pos) {
  gfx->setTextSize(2);
  byte sdown = 60;
  if (curr_pos == 0) {
    gfx->setTextColor(0xffff);
    disp_centered_text("Display", sdown + 10);
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Serial Terminal", sdown + 30);
  }
  if (curr_pos == 1) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Display", sdown + 10);
    gfx->setTextColor(0xffff);
    disp_centered_text("Serial Terminal", sdown + 30);
  }
}

void where_to_print_plaintext(byte record_type) {
  gfx->fillScreen(0x0000);
  gfx->setTextSize(2);
  gfx->setTextColor(current_inact_clr);
  disp_centered_text("Where to print plaintext?", 10);
  curr_key = 0;
  where_to_print_plaintext_menu(curr_key);
  disp_button_designation();
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
      where_to_print_plaintext_menu(curr_key);
    }

    a_button.tick();
    if (a_button.press()) {
      if (curr_key == 0) {
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

      if (curr_key == 1) {
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

    b_button.tick();
    if (b_button.press()) {
      cont_to_next = true;
    }

    delayMicroseconds(400);
    if (keyboard.available()) {
      c = keyboard.read();
      if (c > 0 && ((c & 0xFF) != 6)) {
        if (c >> 8 == 129 && (c & PS2_BREAK)) {

          if (c == 33047)
            curr_key--;

          if (c == 33048)
            curr_key++;

          if (curr_key < 0)
            curr_key = 1;

          if (curr_key > 1)
            curr_key = 0;

          if ((c & 0xFF) == 30) {

            if (curr_key == 0) {
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

            if (curr_key == 1) {
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
          if ((c & 0xFF) == 27) {
            cont_to_next = true;
          }
          where_to_print_plaintext_menu(curr_key);
        }
      }
    }
  }
  call_main_menu();
}

void encryption_algorithms_menu(int curr_pos) {
  gfx->setTextSize(2);
  byte sdown = 50;
  if (curr_pos == 0) {
    gfx->setTextColor(0xffff);
    disp_centered_text("3DES+AES+Blfish+Serp CBC", sdown + 10);
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Blowfish+AES+Serp+AES", sdown + 30);
    disp_centered_text("AES+Serpent+AES", sdown + 50);
    disp_centered_text("Blowfish+Serpent", sdown + 70);
    disp_centered_text("AES+Serpent", sdown + 90);
    disp_centered_text("Serpent", sdown + 110);
    disp_centered_text("Triple DES", sdown + 130);
  }
  if (curr_pos == 1) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("3DES+AES+Blfish+Serp CBC", sdown + 10);
    gfx->setTextColor(0xffff);
    disp_centered_text("Blowfish+AES+Serp+AES", sdown + 30);
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("AES+Serpent+AES", sdown + 50);
    disp_centered_text("Blowfish+Serpent", sdown + 70);
    disp_centered_text("AES+Serpent", sdown + 90);
    disp_centered_text("Serpent", sdown + 110);
    disp_centered_text("Triple DES", sdown + 130);
  }
  if (curr_pos == 2) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("3DES+AES+Blfish+Serp CBC", sdown + 10);
    disp_centered_text("Blowfish+AES+Serp+AES", sdown + 30);
    gfx->setTextColor(0xffff);
    disp_centered_text("AES+Serpent+AES", sdown + 50);
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Blowfish+Serpent", sdown + 70);
    disp_centered_text("AES+Serpent", sdown + 90);
    disp_centered_text("Serpent", sdown + 110);
    disp_centered_text("Triple DES", sdown + 130);
  }
  if (curr_pos == 3) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("3DES+AES+Blfish+Serp CBC", sdown + 10);
    disp_centered_text("Blowfish+AES+Serp+AES", sdown + 30);
    disp_centered_text("AES+Serpent+AES", sdown + 50);
    gfx->setTextColor(0xffff);
    disp_centered_text("Blowfish+Serpent", sdown + 70);
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("AES+Serpent", sdown + 90);
    disp_centered_text("Serpent", sdown + 110);
    disp_centered_text("Triple DES", sdown + 130);
  }
  if (curr_pos == 4) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("3DES+AES+Blfish+Serp CBC", sdown + 10);
    disp_centered_text("Blowfish+AES+Serp+AES", sdown + 30);
    disp_centered_text("AES+Serpent+AES", sdown + 50);
    disp_centered_text("Blowfish+Serpent", sdown + 70);
    gfx->setTextColor(0xffff);
    disp_centered_text("AES+Serpent", sdown + 90);
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Serpent", sdown + 110);
    disp_centered_text("Triple DES", sdown + 130);
  }
  if (curr_pos == 5) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("3DES+AES+Blfish+Serp CBC", sdown + 10);
    disp_centered_text("Blowfish+AES+Serp+AES", sdown + 30);
    disp_centered_text("AES+Serpent+AES", sdown + 50);
    disp_centered_text("Blowfish+Serpent", sdown + 70);
    disp_centered_text("AES+Serpent", sdown + 90);
    gfx->setTextColor(0xffff);
    disp_centered_text("Serpent", sdown + 110);
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("Triple DES", sdown + 130);
  }
  if (curr_pos == 6) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("3DES+AES+Blfish+Serp CBC", sdown + 10);
    disp_centered_text("Blowfish+AES+Serp+AES", sdown + 30);
    disp_centered_text("AES+Serpent+AES", sdown + 50);
    disp_centered_text("Blowfish+Serpent", sdown + 70);
    disp_centered_text("AES+Serpent", sdown + 90);
    disp_centered_text("Serpent", sdown + 110);
    gfx->setTextColor(0xffff);
    disp_centered_text("Triple DES", sdown + 130);
  }
}

void encryption_algorithms() {
  gfx->fillScreen(0x0000);
  gfx->setTextSize(2);
  gfx->setTextColor(current_inact_clr);
  disp_centered_text("Encryption Algorithms", 10);
  curr_key = 0;
  encryption_algorithms_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 6;

    if (curr_key > 6)
      curr_key = 0;

    if (enc0.turn()) {
      encryption_algorithms_menu(curr_key);
    }

    a_button.tick();
    if (a_button.press()) {
      if (curr_key == 0) {
        what_to_do_with_encr_alg("3DES+AES+Blfish+Serp CBC", curr_key);
        cont_to_next = true;
      }

      if (curr_key == 1) {
        what_to_do_with_encr_alg("Blowfish+AES+Serp+AES", curr_key);
        cont_to_next = true;
      }

      if (curr_key == 2) {
        what_to_do_with_encr_alg("AES+Serpent+AES", curr_key);
        cont_to_next = true;
      }

      if (curr_key == 3) {
        what_to_do_with_encr_alg("Blowfish+Serpent", curr_key);
        cont_to_next = true;
      }

      if (curr_key == 4) {
        what_to_do_with_encr_alg("AES+Serpent", curr_key);
        cont_to_next = true;
      }

      if (curr_key == 5) {
        what_to_do_with_encr_alg("Serpent", curr_key);
        cont_to_next = true;
      }

      if (curr_key == 6) {
        what_to_do_with_encr_alg("Triple DES", curr_key);
        cont_to_next = true;
      }
    }

    b_button.tick();
    if (b_button.press()) {
      cont_to_next = true;
    }

    delayMicroseconds(400);
    if (keyboard.available()) {
      c = keyboard.read();
      if (c > 0 && ((c & 0xFF) != 6)) {
        if (c >> 8 == 129 && (c & PS2_BREAK)) {

          if (c == 33047)
            curr_key--;

          if (c == 33048)
            curr_key++;

          if (curr_key < 0)
            curr_key = 6;

          if (curr_key > 6)
            curr_key = 0;

          if ((c & 0xFF) == 30) {
            if (curr_key == 0) {
              what_to_do_with_encr_alg("3DES+AES+Blfish+Serp CBC", curr_key);
              cont_to_next = true;
            }

            if (curr_key == 1) {
              what_to_do_with_encr_alg("Blowfish+AES+Serp+AES", curr_key);
              cont_to_next = true;
            }

            if (curr_key == 2) {
              what_to_do_with_encr_alg("AES+Serpent+AES", curr_key);
              cont_to_next = true;
            }

            if (curr_key == 3) {
              what_to_do_with_encr_alg("Blowfish+Serpent", curr_key);
              cont_to_next = true;
            }

            if (curr_key == 4) {
              what_to_do_with_encr_alg("AES+Serpent", curr_key);
              cont_to_next = true;
            }

            if (curr_key == 5) {
              what_to_do_with_encr_alg("Serpent", curr_key);
              cont_to_next = true;
            }

            if (curr_key == 6) {
              what_to_do_with_encr_alg("Triple DES", curr_key);
              cont_to_next = true;
            }
          }
          if ((c & 0xFF) == 27) {
            cont_to_next = true;
          }
          encryption_algorithms_menu(curr_key);
        }
      }
    }
  }
  call_main_menu();
}

void hash_functions_menu(int curr_pos) {
  gfx->setTextSize(2);
  byte sdown = 60;
  if (curr_pos == 0) {
    gfx->setTextColor(0xffff);
    disp_centered_text("SHA-256", sdown + 10);
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("SHA-512", sdown + 30);
  }
  if (curr_pos == 1) {
    gfx->setTextColor(current_inact_clr);
    disp_centered_text("SHA-256", sdown + 10);
    gfx->setTextColor(0xffff);
    disp_centered_text("SHA-512", sdown + 30);
  }
}

void hash_functions() {
  gfx->fillScreen(0x0000);
  gfx->setTextSize(2);
  gfx->setTextColor(current_inact_clr);
  disp_centered_text("Hash Functions", 10);
  curr_key = 0;
  hash_functions_menu(curr_key);
  disp_button_designation();
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
      hash_functions_menu(curr_key);
    }

    a_button.tick();
    if (a_button.press()) {
      if (curr_key == 0) {
        hash_string_with_sha(false);
        cont_to_next = true;
      }

      if (curr_key == 1) {
        hash_string_with_sha(true);
        cont_to_next = true;
      }
    }

    b_button.tick();
    if (b_button.press()) {
      cont_to_next = true;
    }

    delayMicroseconds(400);
    if (keyboard.available()) {
      c = keyboard.read();
      if (c > 0 && ((c & 0xFF) != 6)) {
        if (c >> 8 == 129 && (c & PS2_BREAK)) {

          if (c == 33047)
            curr_key--;

          if (c == 33048)
            curr_key++;

          if (curr_key < 0)
            curr_key = 1;

          if (curr_key > 1)
            curr_key = 0;

          if ((c & 0xFF) == 30) {
            if (curr_key == 0) {
              hash_string_with_sha(false);
              cont_to_next = true;
            }

            if (curr_key == 1) {
              hash_string_with_sha(true);
              cont_to_next = true;
            }
          }
          if ((c & 0xFF) == 27) {
            cont_to_next = true;
          }
          hash_functions_menu(curr_key);
        }
      }
    }
  }
  call_main_menu();
}

// Menu (Above)

void Factory_Reset() {
  gfx->fillScreen(0x0000);
  gfx->setTextColor(five_six_five_red_color);
  disp_centered_text("Factory Reset", 10);
  delay(500);
  disp_centered_text("Attention!!!", 50);
  gfx->setTextColor(0xffff);
  delay(500);
  disp_centered_text("All your data", 90);
  delay(500);
  disp_centered_text("will be lost!", 110);
  delay(500);
  gfx->setTextColor(0x1557);
  disp_centered_text("Are you sure you want", 150);
  disp_centered_text("to continue?", 170);
  gfx->setTextSize(1);
  delay(5000);
  disp_button_designation_for_del();
  finish_input = false;
  while (finish_input == false) {
    a_button.tick();
    if (a_button.press()) {
      perform_factory_reset();
      finish_input = true;
    }
    delayMicroseconds(400);

    b_button.tick();
    if (b_button.press()) {
      finish_input = true;
    }
    delayMicroseconds(400);

    if (keyboard.available()) {
      // read the next key
      c = keyboard.read();
      if (c > 0 && ((c & 0xFF) != 6)) {
        if (c >> 8 == 129 && (c & PS2_BREAK)) {
          bool cll_chck_bnds = true;
          if ((c & 0xFF) == 30) {
            perform_factory_reset();
            finish_input = true;
          }

          if ((c & 0xFF) == 27) {
            finish_input = true;
          }
        }
      }
    }
    delayMicroseconds(400);
  }
  clear_variables();
  call_main_menu();
  return;
}

void perform_factory_reset() {
  gfx->fillScreen(0x0000);
  gfx->setTextSize(1);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 0);
  gfx->print("Performing Factory Reset...");
  gfx->setCursor(0, 10);
  gfx->print("Please wait for a while.");
  LittleFS.remove("/mpass");
  for (int i = 0; i < MAX_NUM_OF_RECS; i++) {
    LittleFS.remove("/L" + String(i + 1) + "_tag");
    LittleFS.remove("/L" + String(i + 1) + "_ttl");
    LittleFS.remove("/L" + String(i + 1) + "_usn");
    LittleFS.remove("/L" + String(i + 1) + "_psw");
    LittleFS.remove("/L" + String(i + 1) + "_wbs");
    LittleFS.remove("/C" + String(i + 1) + "_tag");
    LittleFS.remove("/C" + String(i + 1) + "_ttl");
    LittleFS.remove("/C" + String(i + 1) + "_hld");
    LittleFS.remove("/C" + String(i + 1) + "_nmr");
    LittleFS.remove("/C" + String(i + 1) + "_exp");
    LittleFS.remove("/C" + String(i + 1) + "_cvn");
    LittleFS.remove("/C" + String(i + 1) + "_pin");
    LittleFS.remove("/C" + String(i + 1) + "_zip");
    LittleFS.remove("/N" + String(i + 1) + "_tag");
    LittleFS.remove("/N" + String(i + 1) + "_ttl");
    LittleFS.remove("/N" + String(i + 1) + "_cnt");
    LittleFS.remove("/P" + String(i + 1) + "_tag");
    LittleFS.remove("/P" + String(i + 1) + "_ttl");
    LittleFS.remove("/P" + String(i + 1) + "_cnt");
  }
  gfx->fillScreen(0x0000);
  gfx->setTextColor(0xffff);
  disp_centered_text("DONE!", 10);
  disp_centered_text("Please reboot", 30);
  disp_centered_text("the device", 40);
  delay(100);
  for (;;){}
}

void hash_string_with_sha(bool vrsn) {
  act = true;
  clear_variables();
  gfx->fillScreen(0x0000);
  gfx->setTextColor(0xffff);
  gfx->setTextSize(1);
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
  gfx->fillScreen(0x0000);
  gfx->setTextColor(current_inact_clr);
  gfx->setTextSize(2);
  disp_centered_text("Resulted hash", 10);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 40);
  gfx->println(res_hash);
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
  gfx->fillScreen(0x0000);
  gfx->setTextColor(current_inact_clr);
  gfx->setTextSize(2);
  disp_centered_text("Resulted hash", 10);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 40);
  gfx->println(h);
  press_any_key_to_continue();
}

// Functions for encryption and decryption (Below)

void disp_paste_smth_inscr(String what_to_pst) {
  gfx->fillScreen(0x0000);
  gfx->setTextColor(0xffff);
  gfx->setTextSize(2);
  disp_centered_text("Paste " + what_to_pst + " to", 30);
  disp_centered_text("the Serial Terminal", 50);
  gfx->setTextColor(five_six_five_red_color);
  disp_centered_text("Press any button", 200);
  disp_centered_text("to cancel", 220);
}

void disp_paste_cphrt_inscr() {
  gfx->fillScreen(0x0000);
  gfx->setTextColor(0xffff);
  gfx->setTextSize(2);
  disp_centered_text("Paste Ciphertext to", 30);
  disp_centered_text("the Serial Terminal", 50);
  gfx->setTextColor(five_six_five_red_color);
  disp_centered_text("Press any button", 200);
  disp_centered_text("to cancel", 220);
}

void disp_plt_on_oled(bool intgrt) {
  gfx->fillScreen(0x0000);
  gfx->setTextColor(current_inact_clr);
  gfx->setTextSize(1);
  disp_centered_text("Plaintext", 10);
  if (intgrt == true)
    gfx->setTextColor(0xffff);
  else {
    gfx->setTextColor(five_six_five_red_color);
    disp_centered_text("Integrity Verification failed!!!", 232);
  }
  disp_centered_text(dec_st, 30);
}

void encr_TDES_AES_BLF_Serp() {
  act = true;
  clear_variables();
  gfx->fillScreen(0x0000);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 20);
  gfx->setTextSize(1);
  set_stuff_for_input("Enter text to encrypt");
  encdr_and_keyb_input();
  gfx->fillScreen(0x0000);
  gfx->setTextSize(1);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 0);
  gfx->print("Encrypting the text...");
  gfx->setCursor(0, 10);
  gfx->print("Please wait for a while.");
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    gfx->fillScreen(0x0000);
    gfx->setTextSize(1);
    gfx->setTextColor(0xffff);
    gfx->setCursor(0, 0);
    gfx->print("Encrypting the text...");
    gfx->setCursor(0, 10);
    gfx->print("Please wait for a while.");
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    gfx->fillScreen(0x0000);
    gfx->setTextSize(1);
    gfx->setTextColor(0xffff);
    gfx->setCursor(0, 0);
    gfx->print("Decrypting the text...");
    gfx->setCursor(0, 10);
    gfx->print("Please wait for a while.");
    String ct = Serial.readString();
    decrypt_string_with_TDES_AES_Blowfish_Serp(ct);
    bool plt_integr = verify_integrity();
    if (print_plt_on_disp_or_serial == true) {
      disp_plt_on_oled(plt_integr);
      clear_variables();
      press_any_key_to_continue();
    } else {
      Serial.println("Plaintext:");
      Serial.println(dec_st);
      if (plt_integr == true)
        Serial.println("Integrity verified successfully!");
      else
        Serial.println("Integrity Verification failed!!!");
    }
    clear_variables();
    call_main_menu();
    return;
  }
}

void encr_blwfsh_aes_serpent_aes() {
  act = true;
  clear_variables();
  gfx->fillScreen(0x0000);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 20);
  gfx->setTextSize(1);
  set_stuff_for_input("Enter text to encrypt");
  encdr_and_keyb_input();
  gfx->fillScreen(0x0000);
  gfx->setTextSize(1);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 0);
  gfx->print("Encrypting the text...");
  gfx->setCursor(0, 10);
  gfx->print("Please wait for a while.");
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    gfx->fillScreen(0x0000);
    gfx->setTextSize(1);
    gfx->setTextColor(0xffff);
    gfx->setCursor(0, 0);
    gfx->print("Encrypting the text...");
    gfx->setCursor(0, 10);
    gfx->print("Please wait for a while.");
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    gfx->fillScreen(0x0000);
    gfx->setTextSize(1);
    gfx->setTextColor(0xffff);
    gfx->setCursor(0, 0);
    gfx->print("Decrypting the text...");
    gfx->setCursor(0, 10);
    gfx->print("Please wait for a while.");
    String ct = Serial.readString();
    decrypt_with_blwfsh_aes_serpent_aes(ct);
    bool plt_integr = verify_integrity();
    if (print_plt_on_disp_or_serial == true) {
      disp_plt_on_oled(plt_integr);
      clear_variables();
      press_any_key_to_continue();
    } else {
      Serial.println("Plaintext:");
      Serial.println(dec_st);
      if (plt_integr == true)
        Serial.println("Integrity verified successfully!");
      else
        Serial.println("Integrity Verification failed!!!");
    }
    clear_variables();
    call_main_menu();
    return;
  }
}

void encr_aes_serpent_aes() {
  act = true;
  clear_variables();
  gfx->fillScreen(0x0000);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 20);
  gfx->setTextSize(1);
  set_stuff_for_input("Enter text to encrypt");
  encdr_and_keyb_input();
  gfx->fillScreen(0x0000);
  gfx->setTextSize(1);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 0);
  gfx->print("Encrypting the text...");
  gfx->setCursor(0, 10);
  gfx->print("Please wait for a while.");
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    gfx->fillScreen(0x0000);
    gfx->setTextSize(1);
    gfx->setTextColor(0xffff);
    gfx->setCursor(0, 0);
    gfx->print("Encrypting the text...");
    gfx->setCursor(0, 10);
    gfx->print("Please wait for a while.");
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    gfx->fillScreen(0x0000);
    gfx->setTextSize(1);
    gfx->setTextColor(0xffff);
    gfx->setCursor(0, 0);
    gfx->print("Decrypting the text...");
    gfx->setCursor(0, 10);
    gfx->print("Please wait for a while.");
    String ct = Serial.readString();
    decrypt_with_aes_serpent_aes(ct);
    bool plt_integr = verify_integrity();
    if (print_plt_on_disp_or_serial == true) {
      disp_plt_on_oled(plt_integr);
      clear_variables();
      press_any_key_to_continue();
    } else {
      Serial.println("Plaintext:");
      Serial.println(dec_st);
      if (plt_integr == true)
        Serial.println("Integrity verified successfully!");
      else
        Serial.println("Integrity Verification failed!!!");
    }
    clear_variables();
    call_main_menu();
    return;
  }
}

void encr_blowfish_serpent() {
  act = true;
  clear_variables();
  gfx->fillScreen(0x0000);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 20);
  gfx->setTextSize(1);
  set_stuff_for_input("Enter text to encrypt");
  encdr_and_keyb_input();
  gfx->fillScreen(0x0000);
  gfx->setTextSize(1);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 0);
  gfx->print("Encrypting the text...");
  gfx->setCursor(0, 10);
  gfx->print("Please wait for a while.");
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    gfx->fillScreen(0x0000);
    gfx->setTextSize(1);
    gfx->setTextColor(0xffff);
    gfx->setCursor(0, 0);
    gfx->print("Encrypting the text...");
    gfx->setCursor(0, 10);
    gfx->print("Please wait for a while.");
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    gfx->fillScreen(0x0000);
    gfx->setTextSize(1);
    gfx->setTextColor(0xffff);
    gfx->setCursor(0, 0);
    gfx->print("Decrypting the text...");
    gfx->setCursor(0, 10);
    gfx->print("Please wait for a while.");
    String ct = Serial.readString();
    decrypt_with_blowfish_serpent(ct);
    bool plt_integr = verify_integrity();
    if (print_plt_on_disp_or_serial == true) {
      disp_plt_on_oled(plt_integr);
      clear_variables();
      press_any_key_to_continue();
    } else {
      Serial.println("Plaintext:");
      Serial.println(dec_st);
      if (plt_integr == true)
        Serial.println("Integrity verified successfully!");
      else
        Serial.println("Integrity Verification failed!!!");
    }
    clear_variables();
    call_main_menu();
    return;
  }
}

void encr_aes_serpent() {
  act = true;
  clear_variables();
  gfx->fillScreen(0x0000);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 20);
  gfx->setTextSize(1);
  set_stuff_for_input("Enter text to encrypt");
  encdr_and_keyb_input();
  gfx->fillScreen(0x0000);
  gfx->setTextSize(1);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 0);
  gfx->print("Encrypting the text...");
  gfx->setCursor(0, 10);
  gfx->print("Please wait for a while.");
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    gfx->fillScreen(0x0000);
    gfx->setTextSize(1);
    gfx->setTextColor(0xffff);
    gfx->setCursor(0, 0);
    gfx->print("Encrypting the text...");
    gfx->setCursor(0, 10);
    gfx->print("Please wait for a while.");
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    gfx->fillScreen(0x0000);
    gfx->setTextSize(1);
    gfx->setTextColor(0xffff);
    gfx->setCursor(0, 0);
    gfx->print("Decrypting the text...");
    gfx->setCursor(0, 10);
    gfx->print("Please wait for a while.");
    String ct = Serial.readString();
    decrypt_with_aes_serpent(ct);
    bool plt_integr = verify_integrity();
    if (print_plt_on_disp_or_serial == true) {
      disp_plt_on_oled(plt_integr);
      clear_variables();
      press_any_key_to_continue();
    } else {
      Serial.println("Plaintext:");
      Serial.println(dec_st);
      if (plt_integr == true)
        Serial.println("Integrity verified successfully!");
      else
        Serial.println("Integrity Verification failed!!!");
    }
    clear_variables();
    call_main_menu();
    return;
  }
}

void encr_serpent_only() {
  act = true;
  clear_variables();
  gfx->fillScreen(0x0000);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 20);
  gfx->setTextSize(1);
  set_stuff_for_input("Enter text to encrypt");
  encdr_and_keyb_input();
  gfx->fillScreen(0x0000);
  gfx->setTextSize(1);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 0);
  gfx->print("Encrypting the text...");
  gfx->setCursor(0, 10);
  gfx->print("Please wait for a while.");
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    gfx->fillScreen(0x0000);
    gfx->setTextSize(1);
    gfx->setTextColor(0xffff);
    gfx->setCursor(0, 0);
    gfx->print("Encrypting the text...");
    gfx->setCursor(0, 10);
    gfx->print("Please wait for a while.");
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    gfx->fillScreen(0x0000);
    gfx->setTextSize(1);
    gfx->setTextColor(0xffff);
    gfx->setCursor(0, 0);
    gfx->print("Decrypting the text...");
    gfx->setCursor(0, 10);
    gfx->print("Please wait for a while.");
    String ct = Serial.readString();
    decrypt_with_serpent_only(ct);
    bool plt_integr = verify_integrity();
    if (print_plt_on_disp_or_serial == true) {
      disp_plt_on_oled(plt_integr);
      clear_variables();
      press_any_key_to_continue();
    } else {
      Serial.println("Plaintext:");
      Serial.println(dec_st);
      if (plt_integr == true)
        Serial.println("Integrity verified successfully!");
      else
        Serial.println("Integrity Verification failed!!!");
    }
    clear_variables();
    call_main_menu();
    return;
  }
}

void encr_tdes_only() {
  act = true;
  clear_variables();
  gfx->fillScreen(0x0000);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 20);
  gfx->setTextSize(1);
  set_stuff_for_input("Enter text to encrypt");
  encdr_and_keyb_input();
  gfx->fillScreen(0x0000);
  gfx->setTextSize(1);
  gfx->setTextColor(0xffff);
  gfx->setCursor(0, 0);
  gfx->print("Encrypting the text...");
  gfx->setCursor(0, 10);
  gfx->print("Please wait for a while.");
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    gfx->fillScreen(0x0000);
    gfx->setTextSize(1);
    gfx->setTextColor(0xffff);
    gfx->setCursor(0, 0);
    gfx->print("Encrypting the text...");
    gfx->setCursor(0, 10);
    gfx->print("Please wait for a while.");
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
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);

      if (keyboard.available()) {
        c = keyboard.read();
        if (c > 0 && ((c & 0xFF) != 6)) {
          if (c >> 8 == 192 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 129 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
          if (c >> 8 == 128 && (c & PS2_BREAK)) {
            canc_op = true;
            break;
          }
        }
      }

      delayMicroseconds(400);
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
        break;
      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    gfx->fillScreen(0x0000);
    gfx->setTextSize(1);
    gfx->setTextColor(0xffff);
    gfx->setCursor(0, 0);
    gfx->print("Decrypting the text...");
    gfx->setCursor(0, 10);
    gfx->print("Please wait for a while.");
    String ct = Serial.readString();
    decrypt_with_tdes_only(ct);
    bool plt_integr = verify_integrity();
    if (print_plt_on_disp_or_serial == true) {
      disp_plt_on_oled(plt_integr);
      clear_variables();
      press_any_key_to_continue();
    } else {
      Serial.println("Plaintext:");
      Serial.println(dec_st);
      if (plt_integr == true)
        Serial.println("Integrity verified successfully!");
      else
        Serial.println("Integrity Verification failed!!!");
    }
    clear_variables();
    call_main_menu();
    return;
  }
}

// Functions for encryption and decryption (Above)

unsigned int k = 0;
int chosen_lock_screen;

void shift_letter_background() {

  bool break_the_loop = false;
  while (break_the_loop == false) {

    if (chosen_lock_screen == 0) {
      for (int i = 0; i < 306; i++) {
        for (int j = 0; j < 77; j++) {
          if (mdb_icon[i][j] == 1)
            gfx->drawPixel(i + 7, j + 87, Dallas[(i + 7 + k) % 320][j + 87]);
        }
      }
    }

    if (chosen_lock_screen == 1) {
      for (int i = 0; i < 306; i++) {
        for (int j = 0; j < 77; j++) {
          if (mdb_icon[i][j] == 1)
            gfx->drawPixel(i + 7, j + 87, Tel_Aviv[(i + 7 + k) % 320][j + 87]);
        }
      }
    }

    if (chosen_lock_screen == 2) {
      for (int i = 0; i < 306; i++) {
        for (int j = 0; j < 77; j++) {
          if (mdb_icon[i][j] == 1)
            gfx->drawPixel(i + 7, j + 87, Montreal[(i + 7 + k) % 320][j + 87]);
        }
      }
    }

    if (chosen_lock_screen == 3) {
      for (int i = 0; i < 306; i++) {
        for (int j = 0; j < 77; j++) {
          if (mdb_icon[i][j] == 1)
            gfx->drawPixel(i + 7, j + 87, Salt_Lake_City[(i + 7 + k) % 320][j + 87]);
        }
      }
    }

    k++;

    a_button.tick();
    if (a_button.press())
      break_the_loop = true;
    delayMicroseconds(400);

    b_button.tick();
    if (b_button.press())
      break_the_loop = true;
    delayMicroseconds(400);

    if (keyboard.available()) {
      c = keyboard.read();
      if (c > 0 && ((c & 0xFF) != 6)) {
        if (c >> 8 == 192 && (c & PS2_BREAK)) {
          break_the_loop = true;
        }
        if (c >> 8 == 129 && (c & PS2_BREAK)) {
          break_the_loop = true;
        }
        if (c >> 8 == 128 && (c & PS2_BREAK)) {
          break_the_loop = true;
        }
      }
    }

    delayMicroseconds(400);
    encoder_button.tick();
    if (encoder_button.press()) {
      break_the_loop = true;
    }
    delayMicroseconds(400);
  }
  trash = rnd_whitened();
}

void setup(void) {
  gfx->begin();
  gfx->fillScreen(0x0000);
  gfx->setRotation(1);
  chosen_lock_screen = rnd_whitened() % 4;
  if (chosen_lock_screen == 0) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        gfx->drawPixel(i, j, Dallas[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 1) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        gfx->drawPixel(i, j, Tel_Aviv[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 2) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        gfx->drawPixel(i, j, Montreal[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 3) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        gfx->drawPixel(i, j, Salt_Lake_City[i][j]);
      }
    }
  }
  delay(1000);
  m = 2; // Set AES to 256-bit mode
  clb_m = 4;
  keyboard.begin(DATAPIN, IRQPIN);
  Serial.begin(115200);
  //Serial.println(F("Inizializing FS..."));
  if (LittleFS.begin()) {
    //Serial.println(F("done."));
  } else {
    //Serial.println(F("fail."));
  }

  for (int i = 0; i < 306; i++) {
    for (int j = 0; j < 77; j++) {
      if (mdb_per[i][j] == 1)
        gfx->drawPixel(i + 7, j + 87, 0xf7de);
    }
  }
  delay(1000);
  gfx->setTextSize(2);
  gfx->setTextColor(0xf7de);
  disp_centered_text("Press Any Key", 205);
  bool cont_to_next = false;
  k = 0;
  shift_letter_background();
  continue_to_unlock();
}

void loop() {
  enc0.tick();
  if (enc0.left())
    curr_key--;
  if (enc0.right())
    curr_key++;

  if (curr_key < 0)
    curr_key = 6;

  if (curr_key > 6)
    curr_key = 0;

  if (enc0.turn()) {
    main_menu(curr_key);
  }
  trash = rnd_whitened();
  delayMicroseconds(400);

  a_button.tick();
  if (a_button.press()) {
    if (curr_key == 0)
      action_for_data_in_flash("Logins Menu", curr_key);

    if (curr_key == 1)
      action_for_data_in_flash("Credit Cards Menu", curr_key);

    if (curr_key == 2)
      action_for_data_in_flash("Notes Menu", curr_key);

    if (curr_key == 3)
      action_for_data_in_flash("Phone Numbers Menu", curr_key);

    if (curr_key == 4)
      encryption_algorithms();

    if (curr_key == 5)
      hash_functions();

    if (curr_key == 6)
      Factory_Reset();
  }

  delayMicroseconds(400);
  if (keyboard.available()) {
    c = keyboard.read();
    if (c > 0 && ((c & 0xFF) != 6)) {
      if (c >> 8 == 129 && (c & PS2_BREAK)) {

        if (c == 33047)
          curr_key--;

        if (c == 33048)
          curr_key++;

        if (curr_key < 0)
          curr_key = 6;

        if (curr_key > 6)
          curr_key = 0;

        if ((c & 0xFF) == 30) {
          if (curr_key == 0)
            action_for_data_in_flash("Logins Menu", curr_key);

          if (curr_key == 1)
            action_for_data_in_flash("Credit Cards Menu", curr_key);

          if (curr_key == 2)
            action_for_data_in_flash("Notes Menu", curr_key);

          if (curr_key == 3)
            action_for_data_in_flash("Phone Numbers Menu", curr_key);

          if (curr_key == 4)
            encryption_algorithms();

          if (curr_key == 5)
            hash_functions();

          if (curr_key == 6)
            Factory_Reset();
        }
        main_menu(curr_key);
      }
    }
  }
  delayMicroseconds(400);
}
