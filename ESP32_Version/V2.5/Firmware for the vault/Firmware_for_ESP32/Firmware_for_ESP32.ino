/*
Midbar
Distributed under the MIT License
© Copyright Maxim Bortnikov 2023
For more information please visit
https://sourceforge.net/projects/midbar/
https://osdn.net/projects/midbar/F
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
https://github.com/PaulStoffregen/PS2Keyboard
https://github.com/siara-cc/esp32_arduino_sqlite3_lib
https://github.com/intrbiz/arduino-crypto
https://github.com/GyverLibs/EncButton
https://github.com/Chris--A/Keypad
https://github.com/platisd/nokia-5110-lcd-library
*/
// !!! Before uploading this sketch -
// Switch the partition scheme to the
// "No OTA (2MB APP/2MB SPIFFS)" !!!
#include <esp_now.h>
#include <WiFi.h>
#include <Adafruit_GFX.h>
#include <Adafruit_ILI9341.h>
#include <SoftwareSerial.h>
#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <SPI.h>
#include <FS.h>
#include "SPIFFS.h"
#include <sys/random.h>
#include <EEPROM.h>
#include <EncButton2.h>
#include "DES.h"
#include "aes.h"
#include "blowfish.h"
#include "serpent.h"
#include "Crypto.h"
#include "midbaricon.h"
#include "sha512.h"

#define EEPROM_SIZE 511
#define TFT_CS    15                                                        // TFT CS  pin is connected to ESP32 pin D15
#define TFT_RST   4                                                         // TFT RST pin is connected to ESP32 pin D4
#define TFT_DC    2                                                         // TFT DC  pin is connected to ESP32 pin D2
                                                                            // SCK (CLK) ---> ESP32 pin D18
                                                                            // MOSI(DIN) ---> ESP32 pin D23

Adafruit_ILI9341 tft = Adafruit_ILI9341(TFT_CS, TFT_DC, TFT_RST);
EncButton2 < EB_ENC > enc0(INPUT, 26, 27);
SoftwareSerial mySerial(34, 35); // RX, TX
EncButton2 < EB_BTN > encoder_button(INPUT, 33);
#include "GBUS.h"
GBUS bus(&mySerial, 3, 10);
int curr_key;
String encoder_input;

DES des;
Blowfish blowfish;

int m;
String dec_st;
String dec_tag;
byte tmp_st[8];
int pass_to_serp[16];
int decract;
byte array_for_CBC_mode[10];
bool finish_input;
bool act;
bool decrypt_tag;
const uint16_t current_inact_clr = 0x051b;
const uint16_t five_six_five_red_color = 0xf940;

struct myStruct {
  char x;
};

uint8_t broadcastAddress[] = {0x5C, 0xCF, 0x7F, 0xFD, 0x85, 0x1D}; // Receiver's MAC address

// Keys (Below)

String kderalgs = "76R5pwoA96Z8cel1r9t0";
int numofkincr = 857;
byte hmackey[] = {"SwCbiq1H01ymXSfZbpDgg86Jd9fi3Nm7zy2FJttxGzZ19cBklpZ2Ti00UAE07BElF68hHR9k02duSvzMBFZT2bGRky15YE9o15hSy2B5lzqspq3721"};
byte des_key[] = {
0x94,0x60,0x1e,0xce,0x7a,0x5b,0xed,0x8b,
0x2c,0x0c,0x3b,0x03,0x11,0x3b,0x51,0xf4,
0xfb,0x0c,0xca,0x5e,0x1e,0x6a,0xe5,0xaa
};
uint8_t AES_key[32] = {
0xd6,0x6e,0xff,0xb9,
0x1e,0xe1,0x6d,0xb0,
0xe5,0x2d,0xfc,0x9b,
0x8b,0xfc,0xe4,0x10,
0x46,0x2d,0x7f,0x49,
0x6f,0x5a,0xb3,0x38,
0xde,0x81,0x3b,0x45,
0x76,0xf6,0xa9,0x55
};
unsigned char Blwfsh_key[] = {
0xd8,0xc1,0xdc,0x2c,
0x7a,0x4c,0x33,0xbd,
0xd3,0xd8,0x1d,0xe1,
0xcf,0xbc,0xb3,0x53,
0x40,0x73,0x20,0xec,
0xff,0xb6,0xea,0x29
};
uint8_t serp_key[32] = {
0x19,0x92,0x78,0xfd,
0x41,0x4a,0xd4,0xcf,
0xf0,0xa2,0x74,0x8b,
0xc3,0x74,0xdb,0x5a,
0x79,0x93,0xd8,0x6e,
0xda,0xa5,0x9e,0xc5,
0x5f,0xcc,0xc5,0x8e,
0xcc,0xae,0xaf,0x61
};
uint8_t second_AES_key[32] = {
0xd2,0xb8,0xd6,0xca,
0x03,0x2d,0xb4,0xf0,
0x79,0x3e,0x02,0x50,
0x8e,0xad,0x0c,0x57,
0xbe,0x17,0xad,0xb8,
0xe9,0xe3,0x59,0xb7,
0xfc,0xb7,0xb1,0xa0,
0xda,0xe3,0x9d,0xe8
};
byte hmackey_for_session_key[] = {"427kAsGI8cC2A3r2iSy3CwYBPiIN1waLuVH22Ms8uGZ0T7y16r8VsR4u2q119OOQyiDYOc61Ooau8K4aBLG0683E30n481JTIO3uokf68vl8"};
uint8_t projection_key[32] = {
0xb1,0x27,0x3a,0xf3,
0xb7,0xd3,0xe9,0x4b,
0xe0,0x27,0x38,0x46,
0x92,0x70,0x75,0x1d,
0xa9,0x6c,0x93,0xc9,
0xe5,0xac,0xbc,0x87,
0x6d,0x73,0xd9,0xed,
0xde,0x5f,0xea,0x6c
};
uint8_t proj_serp_key[32] = {
0x9b,0x8d,0x8e,0x83,
0x83,0xec,0xd9,0xec,
0x19,0xe8,0x9a,0xe8,
0x50,0xc9,0xa0,0x5b,
0xde,0xaa,0xc8,0xad,
0x9b,0x7b,0x55,0x66,
0xb1,0x03,0xbf,0xcf,
0x7e,0x71,0x7e,0x2a
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
  encoder_input = "";
  dec_st = "";
  dec_tag = "";
  decract = 0;
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

  for (int i = 0; i < 10; i++){
    array_for_CBC_mode[i] = esp_random() % 256;
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
    res2[i] = esp_random() % 256;
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
     if (decract > 0){
        if (i < 10){
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
    if(decract > 10){
      for (int i = 0; i < 10; i++){
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
      for (int i = 0; i < 8; i++){
        out[i] ^= array_for_CBC_mode[i];
      }
      
      for (int i = 0; i < 2; i++){
        out2[i] ^= array_for_CBC_mode[i + 8];
      }

      if (decrypt_tag == false){
      
      for (i = 0; i < 8; ++i) {
        if (out[i] > 0)
          dec_st += char(out[i]);
      }

      for (i = 0; i < 2; ++i) {
        if (out2[i] > 0)
          dec_st += char(out2[i]);
      }

      }

      else{
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

    if (decract == -1){
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
  for (int i = 0; i < 128; i+=32){
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
    encr_for_aes[i] = esp_random() % 256;
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
    L_half[i] = esp_random() % 256;
    R_half[i] = esp_random() % 256;
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
    t_encr[i] = esp_random() % 256;
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
    L_half[i] = esp_random() % 256;
    R_half[i] = esp_random() % 256;
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
    encr_for_serp[i] = esp_random() % 256;
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
    res[i] = esp_random() % 256;
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
    L_half[i] = esp_random() % 256;
    R_half[i] = esp_random() % 256;
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
    res[i] = esp_random() % 256;
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
    res[i] = esp_random() % 256;
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

void disp() {
  //tft.fillScreen(0x0000);
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
  tft.print(encoder_input);
}

void disp_stars() {
  //tft.fillScreen(0x0000);
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
  int plnt = encoder_input.length();
  String stars = "";
  for (int i = 0; i < plnt; i++) {
    stars += "*";
  }
  tft.setTextColor(0xffff);
  tft.setTextSize(2);
  tft.setCursor(0, 48);
  tft.print(stars);
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

    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.x == 21)
        curr_key++;
      if (data.x == 8)
        curr_key--;

      if (curr_key < 32)
        curr_key = 126;

      if (curr_key > 126)
        curr_key = 32;

      if (data.x == 13) {
        //Serial.println(encoder_input);
        finish_input = true;
      }

      if (data.x == 131) {
        encoder_input += char(curr_key);
        //Serial.println(encoder_input);
      }

      if (data.x == 132 || data.x == 127) {
        if (encoder_input.length() > 0)
          encoder_input.remove(encoder_input.length() - 1, 1);
        //Serial.println(encoder_input);
        tft.fillRect(0, 48, 312, 192, 0x0000);
      }

      if (data.x > 31 && data.x < 127) {
        encoder_input += data.x;
        //Serial.println(encoder_input);
        curr_key = data.x;
      }

      if (data.x == 27) {
        //Serial.println(encoder_input);
        act = false;
        finish_input = true;
      }
      disp();
    }
    delayMicroseconds(400);
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      //Serial.println(encoder_input);
      finish_input = true;
    }
    if (encoder_button.hasClicks(5)) {
      //Serial.println(encoder_input);
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

    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.x == 21)
        curr_key++;
      if (data.x == 8)
        curr_key--;

      if (curr_key < 32)
        curr_key = 126;

      if (curr_key > 126)
        curr_key = 32;

      if (data.x == 13) {
        //Serial.println(encoder_input);
        finish_input = true;
      }

      if (data.x == 131) {
        encoder_input += char(curr_key);
        //Serial.println(encoder_input);
      }

      if (data.x == 132 || data.x == 127) {
        if (encoder_input.length() > 0)
          encoder_input.remove(encoder_input.length() - 1, 1);
        //Serial.println(encoder_input);
        tft.fillRect(0, 48, 312, 192, 0x0000);
      }

      if (data.x > 31 && data.x < 127) {
        encoder_input += data.x;
        //Serial.println(encoder_input);
        curr_key = data.x;
      }
      disp_stars();
    }
    delayMicroseconds(400);
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      //Serial.println(encoder_input);
      finish_input = true;
    }
    delayMicroseconds(400);
  }
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
  tft.setCursor(0, 24);
  tft.setTextSize(2);
  tft.setTextColor(current_inact_clr);
  tft.print(blue_inscr);
  tft.fillRect(312, 0, 8, 240, current_inact_clr);
  tft.setTextColor(0x07e0);
  tft.setCursor(216, 0);
  tft.print("ASCII:");
}

void continue_to_unlock() {
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
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Set Master Password");
  encdr_and_keyb_input();
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  for (int i = 0; i < 161; i++) {
    for (int j = 0; j < 40; j++) {
        tft.drawPixel(i + 79, j + 10, handwritten_midbar[i][j]);
    }
  }
  tft.setTextColor(0xffff);
  disp_centered_text("Setting password", 65);
  disp_centered_text("Please wait", 85);
  disp_centered_text("for a while", 105);
  //Serial.println(encoder_input);
  String bck = encoder_input;
  modify_keys();
  encoder_input = bck;
  set_psswd();
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  for (int i = 0; i < 161; i++) {
    for (int j = 0; j < 40; j++) {
        tft.drawPixel(i + 79, j + 10, handwritten_midbar[i][j]);
    }
  }
  tft.setTextColor(0xffff);
  disp_centered_text("Password set", 65);
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
    delay(1);
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.x == 13)
        cont1 = false;
    }
    delay(1);
  }
  call_main_menu();
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

  byte res[64];
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
  EEPROM.write(0, 0);
  for (int i = 0; i < 64; i++) {
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
  for (int i = 0; i < 5; i++) {
    second_AES_key[i] = ((int(res[i + 31]) * int(res[i + 11])) + int(res[50])) % 256;
  }
}

void unlock_midbar() {
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(2);
  set_stuff_for_input("Enter Master Password");
  star_encdr_and_keyb_input();
  tft.fillScreen(0x0000);
  for (int i = 0; i < 125; i++) {
    for (int j = 0; j < 40; j++) {
        tft.drawPixel(i + 97, j + 10, handwritten_midbar[i + 193][j]);
    }
  }
  tft.setTextSize(2);
  disp_centered_text("Unlocking Midbar", 65);
  disp_centered_text("Please wait", 85);
  disp_centered_text("for a while", 105);
  //Serial.println(encoder_input);
  String bck = encoder_input;
  modify_keys();
  encoder_input = bck;
  bool next_act = hash_psswd();
  clear_variables();
  tft.fillScreen(0x0000);
  for (int i = 0; i < 125; i++) {
    for (int j = 0; j < 40; j++) {
        tft.drawPixel(i + 97, j + 10, handwritten_midbar[i + 193][j]);
    }
  }
  if (next_act == true) {
    tft.setTextSize(2);
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
      delay(1);
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.x == 13)
          cont1 = false;
      }
      delay(1);
    }
    call_main_menu();
    return;
  } else {
    tft.setTextSize(2);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Wrong Password!", 65);
    tft.setTextColor(0xffff);
    disp_centered_text("Please reboot", 100);
    disp_centered_text("the device", 120);
    disp_centered_text("and try again", 140);
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
  for (int i = 1; i < 65; i++) {
    if (EEPROM.read(i) < 16)
      encr_h += "0";
    encr_h += String(EEPROM.read(i), HEX);
  }
  EEPROM.end();
  decrypt_tag_with_TDES_AES_Blowfish_Serp(encr_h);
  //Serial.println(dec_tag);
  return dec_tag.equals(res_hash);
}

void disp_centered_text(String text, int h) {
  int16_t x1;
  int16_t y1;
  uint16_t width;
  uint16_t height;

  tft.getTextBounds(text, 0, 0, & x1, & y1, & width, & height);
  tft.setCursor((320 - width) / 2, h);
  tft.print(text);
}

// Menu (below)

void disp_button_designation() {
  tft.setTextSize(1);
  tft.setTextColor(0x07e0);
  tft.setCursor(0, 232);
  tft.print("A button, 'Enter' - continue ");
  tft.setTextColor(five_six_five_red_color);
  tft.print("B button, 'Esc' - cancel");
}

void disp_button_designation_for_del() {
  tft.setTextSize(1);
  tft.setTextColor(five_six_five_red_color);
  tft.setCursor(0, 232);
  tft.print("A button, 'Enter' - continue ");
  tft.setTextColor(0x07e0);
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
  main_menu(curr_key);
}

void main_menu(int curr_pos) {
  tft.setTextSize(2);
  byte sdown = 65;
  if (curr_pos == 0) {
    tft.setTextColor(0xf7de);
    disp_centered_text("Data in ESP32's Flash", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Encryption Algorithms", sdown + 30);
    disp_centered_text("Hash Functions", sdown + 50);
    disp_centered_text("SQLite3", sdown + 70);
    disp_centered_text("Password Projection", sdown + 90);
    disp_centered_text("Other Options", sdown + 110);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Data in ESP32's Flash", sdown + 10);
    tft.setTextColor(0xf7de);
    disp_centered_text("Encryption Algorithms", sdown + 30);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Hash Functions", sdown + 50);
    disp_centered_text("SQLite3", sdown + 70);
    disp_centered_text("Password Projection", sdown + 90);
    disp_centered_text("Other Options", sdown + 110);
  }
  if (curr_pos == 2) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Data in ESP32's Flash", sdown + 10);
    disp_centered_text("Encryption Algorithms", sdown + 30);
    tft.setTextColor(0xf7de);
    disp_centered_text("Hash Functions", sdown + 50);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("SQLite3", sdown + 70);
    disp_centered_text("Password Projection", sdown + 90);
    disp_centered_text("Other Options", sdown + 110);
  }
  if (curr_pos == 3) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Data in ESP32's Flash", sdown + 10);
    disp_centered_text("Encryption Algorithms", sdown + 30);
    disp_centered_text("Hash Functions", sdown + 50);
    tft.setTextColor(0xf7de);
    disp_centered_text("SQLite3", sdown + 70);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Password Projection", sdown + 90);
    disp_centered_text("Other Options", sdown + 110);
  }
  if (curr_pos == 4) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Data in ESP32's Flash", sdown + 10);
    disp_centered_text("Encryption Algorithms", sdown + 30);
    disp_centered_text("Hash Functions", sdown + 50);
    disp_centered_text("SQLite3", sdown + 70);
    tft.setTextColor(0xf7de);
    disp_centered_text("Password Projection", sdown + 90);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Other Options", sdown + 110);
  }
  if (curr_pos == 5) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Data in ESP32's Flash", sdown + 10);
    disp_centered_text("Encryption Algorithms", sdown + 30);
    disp_centered_text("Hash Functions", sdown + 50);
    disp_centered_text("SQLite3", sdown + 70);
    disp_centered_text("Password Projection", sdown + 90);
    tft.setTextColor(0xf7de);
    disp_centered_text("Other Options", sdown + 110);
  }
}

void input_source_for_data_in_flash_menu(int curr_pos) {
  tft.setTextSize(2);
  byte sdown = 65;
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("Encoder + Keyboard", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Serial Terminal", sdown + 30);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Encoder + Keyboard", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Serial Terminal", sdown + 30);
  }
}

void input_source_for_data_in_flash(byte record_type) {
  tft.fillScreen(0x0000);
  tft.setTextColor(current_inact_clr);
  tft.setTextSize(2);
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
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.x == 10)
        curr_key++;
      if (data.x == 11)
        curr_key--;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        if (record_type == 0)
          Add_login();
        if (record_type == 1)
          Add_credit_card();
        if (record_type == 2)
          Add_note();
        if (record_type == 3)
          Add_phone_number();
        cont_to_next = true;
      }

      if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        if (record_type == 0)
          Add_login_from_Serial();
        if (record_type == 1)
          Add_credit_card_from_Serial();
        if (record_type == 2)
          Add_note_from_Serial();
        if (record_type == 3)
          Add_phone_number_from_Serial();
        cont_to_next = true;
      }

      if (data.x == 10 || data.x == 11)
        input_source_for_data_in_flash_menu(curr_key);

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98){ // Get back
        call_main_menu();
        cont_to_next = true;
      }
    }
  }
  return;
}

void action_for_data_in_flash_menu(int curr_pos) {
  tft.setTextSize(2);
  byte sdown = 65;
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("Add", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Edit", sdown + 30);
    disp_centered_text("Delete", sdown + 50);
    disp_centered_text("View", sdown + 70);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Edit", sdown + 30);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Delete", sdown + 50);
    disp_centered_text("View", sdown + 70);
  }
  if (curr_pos == 2) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add", sdown + 10);
    disp_centered_text("Edit", sdown + 30);
    tft.setTextColor(0xffff);
    disp_centered_text("Delete", sdown + 50);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View", sdown + 70);
  }
  if (curr_pos == 3) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add", sdown + 10);
    disp_centered_text("Edit", sdown + 30);
    disp_centered_text("Delete", sdown + 50);
    tft.setTextColor(0xffff);
    disp_centered_text("View", sdown + 70);
  }
}

void action_for_data_in_flash(String menu_title, byte record_type) {
  tft.fillScreen(0x0000);
  tft.setTextColor(current_inact_clr);
  tft.setTextSize(2);
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
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.x == 10)
        curr_key++;
      if (data.x == 11)
        curr_key--;

      if (curr_key < 0)
        curr_key = 3;

      if (curr_key > 3)
        curr_key = 0;

      if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        if (record_type == 0)
          input_source_for_data_in_flash(record_type);
        if (record_type == 1)
          input_source_for_data_in_flash(record_type);
        if (record_type == 2)
          input_source_for_data_in_flash(record_type);
        if (record_type == 3)
          input_source_for_data_in_flash(record_type);
        cont_to_next = true;
      }

      if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        if (record_type == 0)
          Edit_login();
        if (record_type == 1)
          Edit_credit_card();
        if (record_type == 2)
          Edit_note();
        if (record_type == 3)
          Edit_phone_number();
        cont_to_next = true;
      }

      if (curr_key == 2 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        if (record_type == 0)
          Delete_login();
        if (record_type == 1)
          Delete_credit_card();
        if (record_type == 2)
          Delete_note();
        if (record_type == 3)
          Delete_phone_number();
        cont_to_next = true;
      }

      if (curr_key == 3 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        if (record_type == 0)
          View_login();
        if (record_type == 1)
          View_credit_card();
        if (record_type == 2)
          View_note();
        if (record_type == 3)
          View_phone_number();
        cont_to_next = true;
      }

      if (data.x == 10 || data.x == 11)
        action_for_data_in_flash_menu(curr_key);

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98){ // Get back
        call_main_menu();
        cont_to_next = true;
      }
    }
  }
  return;
}

void data_in_flash_menu(int curr_pos) {
  tft.setTextSize(2);
  byte sdown = 65;
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("Logins", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Credit Cards", sdown + 30);
    disp_centered_text("Notes", sdown + 50);
    disp_centered_text("Phone Numbers", sdown + 70);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Credit Cards", sdown + 30);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Notes", sdown + 50);
    disp_centered_text("Phone Numbers", sdown + 70);
  }
  if (curr_pos == 2) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    disp_centered_text("Credit Cards", sdown + 30);
    tft.setTextColor(0xffff);
    disp_centered_text("Notes", sdown + 50);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Phone Numbers", sdown + 70);
  }
  if (curr_pos == 3) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    disp_centered_text("Credit Cards", sdown + 30);
    disp_centered_text("Notes", sdown + 50);
    tft.setTextColor(0xffff);
    disp_centered_text("Phone Numbers", sdown + 70);
  }
}

void data_in_flash() {
  tft.fillScreen(0x0000);
  tft.setTextColor(current_inact_clr);
  tft.setTextSize(2);
  disp_centered_text("Data in ESP32's Flash", 10);
  curr_key = 0;
  data_in_flash_menu(curr_key);
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
      data_in_flash_menu(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.x == 10)
        curr_key++;
      if (data.x == 11)
        curr_key--;

      if (curr_key < 0)
        curr_key = 3;

      if (curr_key > 3)
        curr_key = 0;

      if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        action_for_data_in_flash("Logins Menu", curr_key);
        cont_to_next = true;
      }

      if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        action_for_data_in_flash("Credit Cards Menu", curr_key);
        cont_to_next = true;
      }

      if (curr_key == 2 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        action_for_data_in_flash("Notes Menu", curr_key);
        cont_to_next = true;
      }

      if (curr_key == 3 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        action_for_data_in_flash("Phone Numbers Menu", curr_key);
        cont_to_next = true;
      }

      if (data.x == 10 || data.x == 11)
        data_in_flash_menu(curr_key);

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98){ // Get back
        call_main_menu();
        cont_to_next = true;
      }
    }
  }
  return;
}

void input_source_for_encr_algs_menu(int curr_pos) {
  tft.setTextSize(2);
  byte sdown = 65;
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("Encoder + Keyboard", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Serial Terminal", sdown + 30);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Encoder + Keyboard", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Serial Terminal", sdown + 30);
  }
}

void input_source_for_encr_algs(byte record_type) {
  tft.fillScreen(0x0000);
  tft.setTextColor(current_inact_clr);
  tft.setTextSize(2);
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
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.x == 10)
        curr_key++;
      if (data.x == 11)
        curr_key--;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
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

      if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
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

      if (data.x == 10 || data.x == 11)
        input_source_for_encr_algs_menu(curr_key);

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
        cont_to_next = true;
    }
  }
  call_main_menu();
}

void what_to_do_with_encr_alg_menu(int curr_pos) {
  tft.setTextSize(2);
  byte sdown = 65;
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("Encrypt String", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Decrypt String", sdown + 30);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Encrypt String", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Decrypt String", sdown + 30);
  }
}

void what_to_do_with_encr_alg(String menu_title, byte record_type) {
  tft.fillScreen(0x0000);
  tft.setTextColor(current_inact_clr);
  tft.setTextSize(2);
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
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.x == 10)
        curr_key++;
      if (data.x == 11)
        curr_key--;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if (data.x == 10 || data.x == 11)
        what_to_do_with_encr_alg_menu(curr_key);

      if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        input_source_for_encr_algs(record_type);
        cont_to_next = true;
      }

      if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        if (record_type == 0)
          decr_TDES_AES_BLF_Serp();
        if (record_type == 1)
          decr_blwfsh_aes_serpent_aes();
        if (record_type == 2)
          decr_aes_serpent_aes();
        if (record_type == 3)
          decr_blowfish_serpent();
        if (record_type == 4)
          decr_aes_serpent();
        if (record_type == 5)
          decr_serpent_only();
        if (record_type == 6)
          decr_tdes_only();
        cont_to_next = true;
      }

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
        cont_to_next = true;
    }
  }
  call_main_menu();
}

void encryption_algorithms_menu(int curr_pos) {
  tft.setTextSize(2);
  byte sdown = 45;
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("3DES+AES+Blwfish+Serp CBC", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Blowfish+AES+Serpent+AES", sdown + 30);
    disp_centered_text("AES+Serpent+AES", sdown + 50);
    disp_centered_text("Blowfish+Serpent", sdown + 70);
    disp_centered_text("AES+Serpent", sdown + 90);
    disp_centered_text("Serpent", sdown + 110);
    disp_centered_text("Triple DES", sdown + 130);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("3DES+AES+Blwfish+Serp CBC", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Blowfish+AES+Serpent+AES", sdown + 30);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("AES+Serpent+AES", sdown + 50);
    disp_centered_text("Blowfish+Serpent", sdown + 70);
    disp_centered_text("AES+Serpent", sdown + 90);
    disp_centered_text("Serpent", sdown + 110);
    disp_centered_text("Triple DES", sdown + 130);
  }
  if (curr_pos == 2) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("3DES+AES+Blwfish+Serp CBC", sdown + 10);
    disp_centered_text("Blowfish+AES+Serpent+AES", sdown + 30);
    tft.setTextColor(0xffff);
    disp_centered_text("AES+Serpent+AES", sdown + 50);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Blowfish+Serpent", sdown + 70);
    disp_centered_text("AES+Serpent", sdown + 90);
    disp_centered_text("Serpent", sdown + 110);
    disp_centered_text("Triple DES", sdown + 130);
  }
  if (curr_pos == 3) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("3DES+AES+Blwfish+Serp CBC", sdown + 10);
    disp_centered_text("Blowfish+AES+Serpent+AES", sdown + 30);
    disp_centered_text("AES+Serpent+AES", sdown + 50);
    tft.setTextColor(0xffff);
    disp_centered_text("Blowfish+Serpent", sdown + 70);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("AES+Serpent", sdown + 90);
    disp_centered_text("Serpent", sdown + 110);
    disp_centered_text("Triple DES", sdown + 130);
  }
  if (curr_pos == 4) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("3DES+AES+Blwfish+Serp CBC", sdown + 10);
    disp_centered_text("Blowfish+AES+Serpent+AES", sdown + 30);
    disp_centered_text("AES+Serpent+AES", sdown + 50);
    disp_centered_text("Blowfish+Serpent", sdown + 70);
    tft.setTextColor(0xffff);
    disp_centered_text("AES+Serpent", sdown + 90);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Serpent", sdown + 110);
    disp_centered_text("Triple DES", sdown + 130);
  }
  if (curr_pos == 5) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("3DES+AES+Blwfish+Serp CBC", sdown + 10);
    disp_centered_text("Blowfish+AES+Serpent+AES", sdown + 30);
    disp_centered_text("AES+Serpent+AES", sdown + 50);
    disp_centered_text("Blowfish+Serpent", sdown + 70);
    disp_centered_text("AES+Serpent", sdown + 90);
    tft.setTextColor(0xffff);
    disp_centered_text("Serpent", sdown + 110);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Triple DES", sdown + 130);
  }
  if (curr_pos == 6) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("3DES+AES+Blwfish+Serp CBC", sdown + 10);
    disp_centered_text("Blowfish+AES+Serpent+AES", sdown + 30);
    disp_centered_text("AES+Serpent+AES", sdown + 50);
    disp_centered_text("Blowfish+Serpent", sdown + 70);
    disp_centered_text("AES+Serpent", sdown + 90);
    disp_centered_text("Serpent", sdown + 110);
    tft.setTextColor(0xffff);
    disp_centered_text("Triple DES", sdown + 130);
  }
}

void encryption_algorithms() {
  tft.fillScreen(0x0000);
  tft.setTextColor(current_inact_clr);
  tft.setTextSize(2);
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
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.x == 10)
        curr_key++;
      if (data.x == 11)
        curr_key--;

      if (curr_key < 0)
        curr_key = 6;

      if (curr_key > 6)
        curr_key = 0;

      if (data.x == 10 || data.x == 11)
        encryption_algorithms_menu(curr_key);

      if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        what_to_do_with_encr_alg("3DES+AES+Blwfish+Serp CBC", curr_key);
        cont_to_next = true;
      }

      if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        what_to_do_with_encr_alg("Blowfish+AES+Serpent+AES", curr_key);
        cont_to_next = true;
      }

      if (curr_key == 2 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        what_to_do_with_encr_alg("AES+Serpent+AES", curr_key);
        cont_to_next = true;
      }

      if (curr_key == 3 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        what_to_do_with_encr_alg("Blowfish+Serpent", curr_key);
        cont_to_next = true;
      }

      if (curr_key == 4 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        what_to_do_with_encr_alg("AES+Serpent", curr_key);
        cont_to_next = true;
      }

      if (curr_key == 5 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        what_to_do_with_encr_alg("Serpent", curr_key);
        cont_to_next = true;
      }

      if (curr_key == 6 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        what_to_do_with_encr_alg("Triple DES", curr_key);
        cont_to_next = true;
      }

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
        cont_to_next = true;
    }
  }
  call_main_menu();
}

void hash_functions_menu(int curr_pos) {
  byte sdown = 30;
  tft.setTextSize(2);
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
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.x == 10)
        curr_key++;
      if (data.x == 11)
        curr_key--;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if (data.x == 10 || data.x == 11)
        hash_functions_menu(curr_key);

      if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        hash_string_with_sha(false);
        cont_to_next = true;
      }

      if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        hash_string_with_sha(true);
        cont_to_next = true;
      }

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
        cont_to_next = true;
    }
  }
  call_main_menu();
}

void hash_string_with_sha(bool vrsn) {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
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
  tft.fillScreen(0x0000);
  tft.setTextColor(current_inact_clr);
  tft.setTextSize(2);
  disp_centered_text("Resulted hash", 10);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 40);
  tft.println(res_hash);
  tft.fillRect(312, 0, 8, 240, current_inact_clr);
  bool cont_to_next1 = false;
  while (cont_to_next1 == false) {
    bus.tick();
    if (bus.gotData())
      cont_to_next1 = true;
    delay(1);
    encoder_button.tick();
    if (encoder_button.press())
      cont_to_next1 = true;
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
  tft.fillScreen(0x0000);
  tft.setTextColor(current_inact_clr);
  tft.setTextSize(2);
  disp_centered_text("Resulted hash", 10);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 40);
  tft.println(h);
  tft.fillRect(312, 0, 8, 240, current_inact_clr);
  bool cont_to_next1 = false;
  while (cont_to_next1 == false) {
    bus.tick();
    if (bus.gotData())
      cont_to_next1 = true;
    delay(1);
    encoder_button.tick();
    if (encoder_button.press())
      cont_to_next1 = true;
    delay(1);
  }
}

void input_source_for_sql_query(int curr_pos) {
  tft.setTextSize(2);
  byte sdown = 65;
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("Encoder + Keyboard", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Serial Terminal", sdown + 30);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Encoder + Keyboard", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Serial Terminal", sdown + 30);
  }
}

void input_source_for_sql_query() {
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(current_inact_clr);
  disp_centered_text("Choose Input Source", 10);
  curr_key = 0;
  input_source_for_sql_query(curr_key);
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
      input_source_for_sql_query(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.x == 10)
        curr_key++;
      if (data.x == 11)
        curr_key--;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        exec_sql_query_from_keyb_and_enc();
        cont_to_next = true;
      }

      if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        exec_sql_query_from_Serial();
        cont_to_next = true;
      }

      if (data.x == 10 || data.x == 11)
        input_source_for_sql_query(curr_key);

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
        cont_to_next = true;
    }
  }
  call_main_menu();
}

void sqlite3_menu() {
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(current_inact_clr);
  disp_centered_text("SQLite3", 10);
  curr_key = 0;
  tft.setTextColor(0xffff);
  disp_centered_text("Execute SQL query", 40);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);

      if (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97) {
        input_source_for_sql_query();
        cont_to_next = true;
      }

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
        cont_to_next = true;
    }
  }
  call_main_menu();
}

void input_source_for_password_proj(int curr_pos) {
  tft.setTextSize(2);
  byte sdown = 65;
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("Encoder + Keyboard", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Serial Terminal", sdown + 30);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Encoder + Keyboard", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Serial Terminal", sdown + 30);
  }
}

void input_source_for_password_proj() {
  tft.fillScreen(0x0000);
  tft.setTextColor(current_inact_clr);
  tft.setTextSize(2);
  disp_centered_text("Choose Input Source", 10);
  curr_key = 0;
  input_source_for_password_proj(curr_key);
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
      input_source_for_password_proj(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.x == 10)
        curr_key++;
      if (data.x == 11)
        curr_key--;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        project_password_to_receiver();
        cont_to_next = true;
      }

      if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        project_password_to_receiver_from_Serial();
        cont_to_next = true;
      }

      if (data.x == 10 || data.x == 11)
        input_source_for_password_proj(curr_key);

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
        cont_to_next = true;
    }
  }
  call_main_menu();
}

void password_projection_menu() {
  tft.fillScreen(0x0000);
  tft.setTextColor(current_inact_clr);
  disp_centered_text("Password Projection", 10);
  curr_key = 0;
  tft.setTextColor(0xffff);
  disp_centered_text("Project Password", 40);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);

      if (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97) {
        input_source_for_password_proj();
        cont_to_next = true;
      }

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
        cont_to_next = true;
    }
  }
  call_main_menu();
}

void other_options_menu(int curr_pos) {
  tft.setTextSize(2);
  byte sdown = 65;
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("Delete Midbar.db", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Factory Reset", sdown + 30);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Delete Midbar.db", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Factory Reset", sdown + 30);
  }
}

void other_options() {
  tft.fillScreen(0x0000);
  tft.setTextColor(current_inact_clr);
  disp_centered_text("Other Options", 10);
  curr_key = 0;
  other_options_menu(curr_key);
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
      other_options_menu(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.x == 10)
        curr_key++;
      if (data.x == 11)
        curr_key--;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if (data.x == 10 || data.x == 11)
        other_options_menu(curr_key);

      if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        delete_database_from_flash();
        cont_to_next = true;
      }

      if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
        Factory_Reset();
        cont_to_next = true;
      }

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
        cont_to_next = true;
    }
  }
  call_main_menu();
}

// Menu (above)

// Functions for encryption and decryption (Below)

void disp_paste_plt_inscr() {
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setTextSize(1);
  disp_centered_text("Paste plaintext to", 20);
  disp_centered_text("the Serial Terminal", 30);
  tft.setTextColor(five_six_five_red_color);
  disp_centered_text("Press any button", 50);
  disp_centered_text("to cancel", 60);
}

void disp_paste_cphrt_inscr() {
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setTextSize(1);
  disp_centered_text("Paste ciphertext to", 20);
  disp_centered_text("the Serial Terminal", 30);
  tft.setTextColor(five_six_five_red_color);
  disp_centered_text("Press any button", 50);
  disp_centered_text("to cancel", 60);
}

void disp_plt_on_oled(bool intgrt) {
  tft.fillScreen(0x0000);
  tft.setTextColor(current_inact_clr);
  tft.setTextSize(1);
  disp_centered_text("Plaintext", 10);
  if (intgrt == true)
    tft.setTextColor(0xffff);
  else{
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Integrity Verification failed!!!", 232);
  }
  disp_centered_text(dec_st, 30);
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
  if (act == true) {
    encrypt_string_with_tdes_aes_blf_srp(encoder_input);
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
    disp_paste_plt_inscr();
    Serial.println("\nPaste the string you want to encrypt here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
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

void decr_TDES_AES_BLF_Serp() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_cphrt_inscr();
    Serial.println("\nPaste the ciphertext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
    String ct = Serial.readString();
    decrypt_string_with_TDES_AES_Blowfish_Serp(ct);
    //Serial.println("Plaintext:");
    //Serial.println(dec_st);
    bool plt_integr = verify_integrity();
    disp_plt_on_oled(plt_integr);
    clear_variables();
    bool cont_to_next = false;
    while (cont_to_next == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
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
  if (act == true) {
    encrypt_with_blwfsh_aes_serpent_aes(encoder_input);
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
    disp_paste_plt_inscr();
    Serial.println("\nPaste the string you want to encrypt here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
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

void decr_blwfsh_aes_serpent_aes() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_cphrt_inscr();
    Serial.println("\nPaste the ciphertext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
    String ct = Serial.readString();
    decrypt_with_blwfsh_aes_serpent_aes(ct);
    //Serial.println("Plaintext:");
    //Serial.println(dec_st);
    bool plt_integr = verify_integrity_thirty_two();
    disp_plt_on_oled(plt_integr);
    clear_variables();
    bool cont_to_next = false;
    while (cont_to_next == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
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
  if (act == true) {
    encrypt_with_aes_serpent_aes(encoder_input);
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
    disp_paste_plt_inscr();
    Serial.println("\nPaste the string you want to encrypt here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
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

void decr_aes_serpent_aes() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_cphrt_inscr();
    Serial.println("\nPaste the ciphertext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
    String ct = Serial.readString();
    decrypt_with_aes_serpent_aes(ct);
    //Serial.println("Plaintext:");
    //Serial.println(dec_st);
    bool plt_integr = verify_integrity_thirty_two();
    disp_plt_on_oled(plt_integr);
    clear_variables();
    bool cont_to_next = false;
    while (cont_to_next == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
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
  if (act == true) {
    encrypt_with_blowfish_serpent(encoder_input);
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
    disp_paste_plt_inscr();
    Serial.println("\nPaste the string you want to encrypt here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
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

void decr_blowfish_serpent() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_cphrt_inscr();
    Serial.println("\nPaste the ciphertext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
    String ct = Serial.readString();
    decrypt_with_blowfish_serpent(ct);
    //Serial.println("Plaintext:");
    //Serial.println(dec_st);
    bool plt_integr = verify_integrity_thirty_two();
    disp_plt_on_oled(plt_integr);
    clear_variables();
    bool cont_to_next = false;
    while (cont_to_next == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
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
  if (act == true) {
    encrypt_with_aes_serpent(encoder_input);
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
    disp_paste_plt_inscr();
    Serial.println("\nPaste the string you want to encrypt here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
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

void decr_aes_serpent() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_cphrt_inscr();
    Serial.println("\nPaste the ciphertext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
    String ct = Serial.readString();
    decrypt_with_aes_serpent(ct);
    //Serial.println("Plaintext:");
    //Serial.println(dec_st);
    bool plt_integr = verify_integrity_thirty_two();
    disp_plt_on_oled(plt_integr);
    clear_variables();
    bool cont_to_next = false;
    while (cont_to_next == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
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
  if (act == true) {
    encrypt_with_serpent_only(encoder_input);
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
    disp_paste_plt_inscr();
    Serial.println("\nPaste the string you want to encrypt here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
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

void decr_serpent_only() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_cphrt_inscr();
    Serial.println("\nPaste the ciphertext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
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
    disp_plt_on_oled(plt_integr);
    clear_variables();
    bool cont_to_next = false;
    while (cont_to_next == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
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
  if (act == true) {
    encrypt_with_tdes_only(encoder_input);
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
    disp_paste_plt_inscr();
    Serial.println("\nPaste the string you want to encrypt here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
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

void decr_tdes_only() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_cphrt_inscr();
    Serial.println("\nPaste the ciphertext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
    String ct = Serial.readString();
    decrypt_with_tdes_only(ct);
    //Serial.println("Plaintext:");
    //Serial.println(dec_st);
    bool plt_integr = verify_integrity_thirty_two();
    disp_plt_on_oled(plt_integr);
    clear_variables();
    bool cont_to_next = false;
    while (cont_to_next == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
    }
    clear_variables();
    call_main_menu();
    return;
  }
}

// Functions for encryption and decryption (Above)

// SQL (Below)

String extr_data;
const String dbase_name = "/spiffs/Midbar.db";
int clb_m;
int num_of_IDs;
String rec_ID;

const char * data = "Callback function called";
static int callback(void * data, int argc, char ** argv, char ** azColName) {
  int i;
  if (clb_m == 0) //Print in serial
    Serial.printf("%s: ", (const char * ) data);
  if (clb_m == 1) { //Print on display
    tft.setTextColor(0xffff);
    tft.printf("%s:\n", (const char * ) data);
  }
  for (i = 0; i < argc; i++) {
    if (clb_m == 0) { //Print in serial
      Serial.printf("\n%s = %s", azColName[i], argv[i] ? argv[i] : "Empty");
      Serial.printf("\n\n");
    }
    if (clb_m == 1) { //Print in tft
      tft.setTextColor(0xffff);
      tft.printf("\n%s = %s\n", azColName[i], argv[i] ? argv[i] : "Empty");
    }
    if (clb_m == 2) { //Decrypt
      back_keys();
      int ct_len = strlen(argv[i]) + 1;
      char ct_array[ct_len];
      snprintf(ct_array, ct_len, "%s", argv[i]);
      /*
      for (int i = 0; i < ct_len; i++){
        Serial.print(ct_array[i]);
      }
      */
      int ext = 0;
      decract = -1;
      while (ct_len > ext) {
        split_for_decryption(ct_array, ct_len, 0 + ext);
        ext += 32;
        decract += 10;
      }
      rest_keys();
    }
    if (clb_m == 3) { //Extract IDs
      int ct_len = strlen(argv[i]) + 1;
      char ct_array[ct_len];
      snprintf(ct_array, ct_len, "%s", argv[i]);
      for (int i = 0; i < ct_len; i++) {
        dec_st += ct_array[i];
      }
      dec_st += "\n";
      num_of_IDs++;
    }
  }
  return 0;
}

int db_open(const char * filename, sqlite3 ** db) {
  int rc = sqlite3_open(filename, db);
  if (rc) {
    if (clb_m == 0) //Print in serial
      Serial.printf("Can't open database: %s\n", sqlite3_errmsg( * db));
    if (clb_m == 1) { //Print in tft
      tft.setTextColor(five_six_five_red_color);
      tft.printf("Can't open database: %s\n", sqlite3_errmsg( * db));
    }
    return rc;
  } else {
    if (clb_m == 0) //Print in serial
      Serial.printf("Opened database successfully\n");
    if (clb_m == 1) { //Print in tft
      tft.setTextColor(0xffff);
      tft.printf("Opened database successfully\n");
    }
  }
  return rc;
}

char * zErrMsg = 0;
int db_exec(sqlite3 * db,
  const char * sql) {
  int rc = sqlite3_exec(db, sql, callback, (void * ) data, & zErrMsg);
  if (rc != SQLITE_OK) {
    if (clb_m == 0) //Print in serial
      Serial.printf("SQL error: %s\n", zErrMsg);
    if (clb_m == 1) { //Print in tft
      tft.setTextColor(five_six_five_red_color);
      tft.printf("SQL error: %s\n", zErrMsg);
    }
    sqlite3_free(zErrMsg);
  } else {
    if (clb_m == 0) //Print in serial
      Serial.printf("Operation done successfully\n");
    if (clb_m == 1) { //Print in serial
      tft.setTextColor(0xffff);
      tft.printf("Operation done successfully");
    }
  }
  return rc;
}

void create_logins_table() {
  exeq_sql_statement("CREATE TABLE if not exists Logins (ID CHARACTER(12), Title TEXT, Username TEXT, Password TEXT, Website Text, Tag CHARACTER(128));");
}

void create_credit_cards_table() {
  exeq_sql_statement("CREATE TABLE if not exists Credit_cards (ID CHARACTER(14), Title TEXT, Cardholder TEXT, Card_Number TEXT, Expiration_date Text, CVN Text, PIN Text, ZIP_code Text, Tag CHARACTER(128));");
}

void create_notes_table() {
  exeq_sql_statement("CREATE TABLE if not exists Notes (ID CHARACTER(13), Title TEXT, Content TEXT, Tag CHARACTER(128));");
}

void create_phone_numbers_table() {
  exeq_sql_statement("CREATE TABLE if not exists Phone_Numbers (ID CHARACTER(13), Title TEXT, Phone TEXT, Tag CHARACTER(128));");
}

void exeq_sql_statement(char sql_statmnt[]) {
  sqlite3 * db1;
  int rc;
  int str_len = dbase_name.length() + 1;
  char input_arr[str_len];
  dbase_name.toCharArray(input_arr, str_len);
  if (db_open(input_arr, & db1))
    return;

  rc = db_exec(db1, sql_statmnt);
  if (rc != SQLITE_OK) {
    sqlite3_close(db1);
    return;
  }

  sqlite3_close(db1);
}

void exeq_sql_statement_from_string(String squery) {
  int squery_len = squery.length() + 1;
  char squery_array[squery_len];
  squery.toCharArray(squery_array, squery_len);
  exeq_sql_statement(squery_array);
  return;
}

void gen_rand_ID(int n_itr) {
  for (int i = 0; i < n_itr; i++) {
    int r_numb3r = esp_random() % 95;
    if (r_numb3r != 7)
      rec_ID += char(32 + r_numb3r);
    else
      rec_ID += char(33 + r_numb3r + esp_random() % 30);
  }
}

void exec_sql_query_from_keyb_and_enc() {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter sql query");
  encdr_and_keyb_input();
  if (act == true) {
    clb_m = 1;
    tft.setTextSize(1);
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    exeq_sql_statement_from_string(encoder_input);
    tft.setTextColor(0xffff);
    tft.fillRect(0, 230, 320, 10, 0x0000);
    disp_centered_text("Press any button to continue", 232);
    bool cont_to_next4 = false;
    while (cont_to_next4 == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next4 = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next4 = true;
      delay(1);
    }
  }
  clear_variables();
  call_main_menu();
  return;
}

void exec_sql_query_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setTextSize(2);
    disp_centered_text("Paste sql query to", 20);
    disp_centered_text("the Serial Terminal", 40);
    tft.setTextColor(five_six_five_red_color);
    tft.setTextSize(1);
    disp_centered_text("Press any button to cancel", 232);
    Serial.println("\nPaste sql query here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
    clb_m = 0;
    String sql_query_t_exect = Serial.readString();
    exeq_sql_statement_from_string(sql_query_t_exect);
    cont_to_next = true;
    clear_variables();
    call_main_menu();
    return;
  }
}

void Add_login() {
  rec_ID = "";
  gen_rand_ID(12);
  clb_m = 1;
  add_title_into_login();
}

void add_title_into_login() {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter Title");
  encdr_and_keyb_input();
  if (act == true) {
    encrypt_with_TDES_AES_Blowfish_Serp(encoder_input);
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.setTextSize(1);
    tft.println("Adding ID and Title into Logins");
    exeq_sql_statement_from_string("INSERT INTO Logins (ID, Title) VALUES( '" + rec_ID + "','" + dec_st + "');");
    add_username_into_login();
  }
  clear_variables();
  call_main_menu();
  return;
}

void add_username_into_login() {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter Username");
  encdr_and_keyb_input();
  if (act == true) {
    encrypt_with_TDES_AES_Blowfish_Serp(encoder_input);
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.setTextSize(1);
    tft.println("Adding Username into Logins");
    exeq_sql_statement_from_string("UPDATE Logins set Username = '" + dec_st + "' where ID = '" + rec_ID + "';");
    add_password_into_login();
  }
  clear_variables();

  return;
}

void add_password_into_login() {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter Password");
  encdr_and_keyb_input();
  if (act == true) {
    encrypt_with_TDES_AES_Blowfish_Serp(encoder_input);
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.setTextSize(1);
    tft.println("Adding Password into Logins");
    exeq_sql_statement_from_string("UPDATE Logins set Password = '" + dec_st + "' where ID = '" + rec_ID + "';");
    add_website_into_login();
  }
  clear_variables();

  return;
}

void add_website_into_login() {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter Website");
  encdr_and_keyb_input();
  if (act == true) {
    encrypt_with_TDES_AES_Blowfish_Serp(encoder_input);
    clb_m = 1;
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.setTextSize(1);
    tft.println("Adding Website into Logins");
    exeq_sql_statement_from_string("UPDATE Logins set Website = '" + dec_st + "' where ID = '" + rec_ID + "';");
    compute_tag_for_login();
  }
  clear_variables();

  return;
}

void compute_tag_for_login(){
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.setTextSize(1);
    tft.println("Extracting newly added values and computing the tag");
    clb_m = 2;
    decrypt_tag = false;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + rec_ID + "'");
    String decrypted_title = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Username FROM Logins WHERE ID = '" + rec_ID + "'");
    String decrypted_username = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Password FROM Logins WHERE ID = '" + rec_ID + "'");
    String decrypted_password = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Website FROM Logins WHERE ID = '" + rec_ID + "'");
    String decrypted_website = dec_st;
    clear_variables();
    clb_m = 1;
    //Serial.println(decrypted_title + decrypted_username + decrypted_password + decrypted_website);
    encr_hash_for_tdes_aes_blf_srp(decrypted_title + decrypted_username + decrypted_password + decrypted_website);
    exeq_sql_statement_from_string("UPDATE Logins set Tag = '" + dec_st + "' where ID = '" + rec_ID + "';");
    tft.setTextColor(0xffff);
    tft.fillRect(0, 230, 320, 10, 0x0000);
    disp_centered_text("Press any button to continue", 232);
    bool cont_to_next4 = false;
    while (cont_to_next4 == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next4 = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next4 = true;
      delay(1);
    }
}

void Add_login_from_Serial() {
  rec_ID = "";
  gen_rand_ID(12);
  add_title_into_login_from_Serial();
  clb_m = 1;
}

void add_title_into_login_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setTextSize(2);
    disp_centered_text("Paste title", 40);
    disp_centered_text("to the Serial Terminal", 60);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Press any button to cancel", 220);
    Serial.println("\nPaste title here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
    String plt = Serial.readString();
    encrypt_with_TDES_AES_Blowfish_Serp(plt);
    exeq_sql_statement_from_string("INSERT INTO Logins (ID, Title) VALUES( '" + rec_ID + "','" + dec_st + "');");
    add_username_into_login_from_Serial();
    cont_to_next = true;
    clear_variables();
  }
  call_main_menu();
  return;
}

void add_username_into_login_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setTextSize(2);
    disp_centered_text("Paste username", 40);
    disp_centered_text("to the Serial Terminal", 60);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Press any button to cancel", 220);
    Serial.println("\nPaste username here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
    String plt = Serial.readString();
    encrypt_with_TDES_AES_Blowfish_Serp(plt);
    exeq_sql_statement_from_string("UPDATE Logins set Username = '" + dec_st + "' where ID = '" + rec_ID + "';");
    add_password_into_login_from_Serial();
    cont_to_next = true;
    clear_variables();

    return;
  }
}

void add_password_into_login_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setTextSize(2);
    disp_centered_text("Paste password", 40);
    disp_centered_text("to the Serial Terminal", 60);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Press any button to cancel", 220);
    Serial.println("\nPaste password here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
    String plt = Serial.readString();
    encrypt_with_TDES_AES_Blowfish_Serp(plt);
    exeq_sql_statement_from_string("UPDATE Logins set Password = '" + dec_st + "' where ID = '" + rec_ID + "';");
    add_website_into_login_from_Serial();
    cont_to_next = true;
    clear_variables();

    return;
  }
}

void add_website_into_login_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setTextSize(2);
    disp_centered_text("Paste website", 40);
    disp_centered_text("to the Serial Terminal", 60);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Press any button to cancel", 220);
    Serial.println("\nPaste website here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
    String plt = Serial.readString();
    encrypt_with_TDES_AES_Blowfish_Serp(plt);
    exeq_sql_statement_from_string("UPDATE Logins set Website = '" + dec_st + "' where ID = '" + rec_ID + "';");
    compute_tag_for_login_without_disp();
    cont_to_next = true;
    clear_variables();

    return;
  }
}

void compute_tag_for_login_without_disp(){
    clb_m = 2;
    decrypt_tag = false;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + rec_ID + "'");
    String decrypted_title = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Username FROM Logins WHERE ID = '" + rec_ID + "'");
    String decrypted_username = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Password FROM Logins WHERE ID = '" + rec_ID + "'");
    String decrypted_password = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Website FROM Logins WHERE ID = '" + rec_ID + "'");
    String decrypted_website = dec_st;
    clb_m = 1;
    clear_variables();
    //Serial.println(decrypted_title + decrypted_username + decrypted_password + decrypted_website);
    encr_hash_for_tdes_aes_blf_srp(decrypted_title + decrypted_username + decrypted_password + decrypted_website);
    exeq_sql_statement_from_string("UPDATE Logins set Tag = '" + dec_st + "' where ID = '" + rec_ID + "';");
    return;
}

void Edit_login() {
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Logins");
  if (num_of_IDs != 0) {
    String IDs[num_of_IDs];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i < dec_st.length() - 1; i++) {
      if (dec_st.charAt(i) != '\n')
        IDs[c_id] += dec_st.charAt(i);
      else {
        c_id++;
      }
    }
    for (int i = 0; i < num_of_IDs; i++) {
      if (IDs[i].length() > 0)
        IDs[i].remove(IDs[i].length() - 1, 1);
    }
    clear_variables();
    clb_m = 2;
    decrypt_tag = false;
    tft.fillScreen(0x0000);
    tft.setTextSize(2);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Edit Login 1/" + String(num_of_IDs), 10);
    tft.setTextColor(0xffff);
    clear_variables();
    exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + IDs[0] + "'");
    disp_centered_text(dec_st, 40);
    disp_button_designation();
    String selected_record;
    bool cont_to_next = false;
    int sel_rcrd = 0;
    while (cont_to_next == false) {
      enc0.tick();
      if (enc0.left())
        sel_rcrd--;
      if (enc0.right())
        sel_rcrd++;
      if (sel_rcrd > (num_of_IDs - 1))
        sel_rcrd = 0;
      if (sel_rcrd < 0)
        sel_rcrd = num_of_IDs - 1;
      if (enc0.turn()) {
        selected_record = String(sel_rcrd);
        tft.fillScreen(0x0000);
        tft.setTextSize(2);
        tft.setTextColor(current_inact_clr);
        disp_centered_text("Edit Login " + String(sel_rcrd + 1) + "/" + String(num_of_IDs), 10);
        tft.setTextColor(0xffff);
        clear_variables();
        exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + IDs[sel_rcrd] + "'");
        disp_centered_text(dec_st, 40);
        disp_button_designation();
      }
      delayMicroseconds(400);
      char chr;
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.x == 21)
          sel_rcrd++;
        if (data.x == 8)
          sel_rcrd--;

        if (sel_rcrd > (num_of_IDs - 1))
          sel_rcrd = 0;
        if (sel_rcrd < 0)
          sel_rcrd = num_of_IDs - 1;

        chr = data.x;
        selected_record = String(sel_rcrd);
        tft.fillScreen(0x0000);
        tft.setTextSize(2);
        tft.setTextColor(current_inact_clr);
        disp_centered_text("Edit Login " + String(sel_rcrd + 1) + "/" + String(num_of_IDs), 10);
        tft.setTextColor(0xffff);
        clear_variables();
        exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + IDs[sel_rcrd] + "'");
        disp_centered_text(dec_st, 40);
        disp_button_designation();
      }
      delayMicroseconds(400);
      if (chr == 13 || chr == 131) {

        tft.fillScreen(0x0000);
        tft.setTextColor(current_inact_clr);
        tft.setTextSize(2);
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
          bus.tick();
          if (bus.gotData()) {
            myStruct data;
            bus.readData(data);
            if (data.x == 10)
              curr_key++;
            if (data.x == 11)
              curr_key--;

            if (curr_key < 0)
              curr_key = 1;

            if (curr_key > 1)
              curr_key = 0;

            if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
              Edit_login_from_keyb_and_enc(IDs[selected_record.toInt()]);
              cont_to_next = true;
            }
            if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
              Edit_login_from_Serial(IDs[selected_record.toInt()]);
              cont_to_next = true;
            }

            if (data.x == 10 || data.x == 11)
              input_source_for_data_in_flash_menu(curr_key);

            if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
              cont_to_next = true;
          }
        }

        call_main_menu();
        return;
      }
      if (chr == 27 || chr == 132) {
        call_main_menu();
        selected_record = "";
        return;
      }
    }

  } else {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Press any button", 30);
    disp_centered_text("to continue", 50);
    bool cont_to_next5 = false;
    while (cont_to_next5 == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next5 = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next5 = true;
      delay(1);
    }
    call_main_menu();
    return;
  }
}

void Edit_login_from_keyb_and_enc(String selected_record) {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  set_stuff_for_input("Enter new password");
  encdr_and_keyb_input();
  if (act == true) {
    encrypt_with_TDES_AES_Blowfish_Serp(encoder_input);
    clb_m = 2;
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setTextSize(1);
    tft.setCursor(0, 0);
    tft.println("Setting new password");
    exeq_sql_statement_from_string("UPDATE Logins set Password = '" + dec_st + "' where ID = '" + selected_record + "';");
    rec_ID = selected_record;
    compute_tag_for_login_without_disp();
    tft.setTextColor(0xffff);
    tft.fillRect(0, 230, 320, 10, 0x0000);
    disp_centered_text("Press any button to continue", 232);
    bool cont_to_next4 = false;
    while (cont_to_next4 == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next4 = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next4 = true;
      delay(1);
    }
  }
  clear_variables();
}

void Edit_login_from_Serial(String selected_record) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setTextSize(2);
    disp_centered_text("Paste new password", 20);
    disp_centered_text("to the Serial Terminal", 40);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Press any button to cancel", 220);
    Serial.println("\nPaste new password here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
    String plt = Serial.readString();
    encrypt_with_TDES_AES_Blowfish_Serp(plt);
    exeq_sql_statement_from_string("UPDATE Logins set Password = '" + dec_st + "' where ID = '" + selected_record + "';");
    rec_ID = selected_record;
    compute_tag_for_login_without_disp();
    cont_to_next = true;
    clear_variables();
    return;
  }
}

void Delete_login() {
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Logins");
  if (num_of_IDs != 0) {
    String IDs[num_of_IDs];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i < dec_st.length() - 1; i++) {
      if (dec_st.charAt(i) != '\n')
        IDs[c_id] += dec_st.charAt(i);
      else {
        c_id++;
      }
    }
    for (int i = 0; i < num_of_IDs; i++) {
      if (IDs[i].length() > 0)
        IDs[i].remove(IDs[i].length() - 1, 1);
    }
    clear_variables();
    clb_m = 2;
    decrypt_tag = false;
    tft.fillScreen(0x0000);
    tft.setTextSize(2);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Delete Login 1/" + String(num_of_IDs), 10);
    tft.setTextColor(0xffff);
    clear_variables();
    exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + IDs[0] + "'");
    disp_centered_text(dec_st, 40);
    disp_button_designation_for_del();
    String selected_record;
    bool cont_to_next = false;
    int sel_rcrd = 0;
    while (cont_to_next == false) {
      enc0.tick();
      if (enc0.left())
        sel_rcrd--;
      if (enc0.right())
        sel_rcrd++;
      if (sel_rcrd > (num_of_IDs - 1))
        sel_rcrd = 0;
      if (sel_rcrd < 0)
        sel_rcrd = num_of_IDs - 1;
      if (enc0.turn()) {
        selected_record = String(sel_rcrd);
        tft.fillScreen(0x0000);
        tft.setTextColor(five_six_five_red_color);
        tft.setTextSize(2);
        disp_centered_text("Delete Login " + String(sel_rcrd + 1) + "/" + String(num_of_IDs), 10);
        tft.setTextColor(0xffff);
        clear_variables();
        exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + IDs[sel_rcrd] + "'");
        disp_centered_text(dec_st, 40);
        disp_button_designation_for_del();
      }
      delayMicroseconds(400);
      char chr;
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.x == 21)
          sel_rcrd++;
        if (data.x == 8)
          sel_rcrd--;

        if (sel_rcrd > (num_of_IDs - 1))
          sel_rcrd = 0;
        if (sel_rcrd < 0)
          sel_rcrd = num_of_IDs - 1;

        chr = data.x;
        selected_record = String(sel_rcrd);
        tft.fillScreen(0x0000);
        tft.setTextColor(five_six_five_red_color);
        tft.setTextSize(2);
        disp_centered_text("Delete Login " + String(sel_rcrd + 1) + "/" + String(num_of_IDs), 10);
        tft.setTextColor(0xffff);
        clear_variables();
        exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + IDs[sel_rcrd] + "'");
        disp_centered_text(dec_st, 40);
        disp_button_designation_for_del();
      }
      delayMicroseconds(400);
      if (chr == 13 || chr == 131) {
        clb_m = 1;
        /*
        Serial.println(IDs[selected_record.toInt()][0]);
        String tdel = "DELETE FROM Logins WHERE ID = '";
        for (int i = 0; i < IDs[selected_record.toInt()][0].length(); i++){
          tdel += (IDs[selected_record.toInt()][0].charAt(i));
        }
        tdel += "'";
        exeq_sql_statement_from_string(tdel);
        */
        tft.fillScreen(0x0000);
        tft.setTextColor(0xffff);
        tft.setCursor(0, 0);
        exeq_sql_statement_from_string("DELETE FROM Logins WHERE ID = '" + IDs[selected_record.toInt()] + "'");
        tft.setTextColor(0xffff);
        tft.fillRect(0, 230, 320, 10, 0x0000);
        disp_centered_text("Press any button to continue", 232);
        bool cont_to_next4 = false;
        while (cont_to_next4 == false) {
          bus.tick();
          if (bus.gotData())
            cont_to_next4 = true;
          delay(1);
          encoder_button.tick();
          if (encoder_button.press())
            cont_to_next4 = true;
          delay(1);
        }
        call_main_menu();
        return;
      }
      if (chr == 27 || chr == 132) {
        selected_record = "";
        call_main_menu();
        return;
      }
    }

  } else {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Press any button", 40);
    disp_centered_text("to continue", 60);
    bool cont_to_next5 = false;
    while (cont_to_next5 == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next5 = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next5 = true;
      delay(1);
    }
    call_main_menu();
    return;
  }
}

void View_login() {
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Logins");
  if (num_of_IDs != 0) {
    String IDs[num_of_IDs];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i < dec_st.length() - 1; i++) {
      if (dec_st.charAt(i) != '\n')
        IDs[c_id] += dec_st.charAt(i);
      else {
        c_id++;
      }
    }
    for (int i = 0; i < num_of_IDs; i++) {
      if (IDs[i].length() > 0)
        IDs[i].remove(IDs[i].length() - 1, 1);
    }
    clear_variables();
    tft.fillScreen(0x0000);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View Login 1/" + String(num_of_IDs), 0);
    tft.fillRect(312, 0, 8, 240, current_inact_clr);
    tft.setTextColor(0xffff);
    clb_m = 2;
    decrypt_tag = false;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + IDs[0] + "'");
    String decrypted_title = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Username FROM Logins WHERE ID = '" + IDs[0] + "'");
    String decrypted_username = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Password FROM Logins WHERE ID = '" + IDs[0] + "'");
    String decrypted_password = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Website FROM Logins WHERE ID = '" + IDs[0] + "'");
    String decrypted_website = dec_st;
    clear_variables();
    decrypt_tag = true;
    exeq_sql_statement_from_string("SELECT Tag FROM Logins WHERE ID = '" + IDs[0] + "'");
    dec_st = decrypted_title + decrypted_username + decrypted_password + decrypted_website;
    bool login_integrity = verify_integrity();
    if (login_integrity == false){
      tft.fillRect(312, 0, 8, 240, five_six_five_red_color);
      tft.setTextSize(1);
      tft.setTextColor(five_six_five_red_color);
      disp_centered_text("Integrity Verification Failed!!!", 232);
    }
    tft.setTextSize(2);
    tft.setCursor(0,16);
    tft.setTextColor(current_inact_clr);
    tft.print("Title:");
    if (login_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_title);
    tft.setTextColor(current_inact_clr);
    tft.print("Username:");
    if (login_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_username);
    tft.setTextColor(current_inact_clr);
    tft.print("Password:");
    if (login_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_password);
    tft.setTextColor(current_inact_clr);
    tft.print("Website:");
    if (login_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_website);
    String selected_record;
    bool cont_to_next = false;
    int sel_rcrd = 0;
    while (cont_to_next == false) {
      enc0.tick();
      if (enc0.left())
        sel_rcrd--;
      if (enc0.right())
        sel_rcrd++;
      if (sel_rcrd > (num_of_IDs - 1))
        sel_rcrd = 0;
      if (sel_rcrd < 0)
        sel_rcrd = num_of_IDs - 1;
      if (enc0.turn()) {
        selected_record = String(sel_rcrd);
        tft.fillScreen(0x0000);
        tft.setTextColor(current_inact_clr);
        disp_centered_text("View Login " + String(sel_rcrd + 1) + "/" + String(num_of_IDs), 0);
        tft.fillRect(312, 0, 8, 240, current_inact_clr);
        tft.setTextColor(0xffff);
    clb_m = 2;
    decrypt_tag = false;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_title = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Username FROM Logins WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_username = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Password FROM Logins WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_password = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Website FROM Logins WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_website = dec_st;
    clear_variables();
    decrypt_tag = true;
    exeq_sql_statement_from_string("SELECT Tag FROM Logins WHERE ID = '" + IDs[sel_rcrd] + "'");
    dec_st = decrypted_title + decrypted_username + decrypted_password + decrypted_website;
    bool login_integrity = verify_integrity();
    if (login_integrity == false){
      tft.fillRect(312, 0, 8, 240, five_six_five_red_color);
      tft.setTextSize(1);
      tft.setTextColor(five_six_five_red_color);
      disp_centered_text("Integrity Verification Failed!!!", 232);
    }
    tft.setTextSize(2);
    tft.setCursor(0,16);
    tft.setTextColor(current_inact_clr);
    tft.print("Title:");
    if (login_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_title);
    tft.setTextColor(current_inact_clr);
    tft.print("Username:");
    if (login_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_username);
    tft.setTextColor(current_inact_clr);
    tft.print("Password:");
    if (login_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_password);
    tft.setTextColor(current_inact_clr);
    tft.print("Website:");
    if (login_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_website);
      }
      delayMicroseconds(400);
      char chr;
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.x == 21)
          sel_rcrd++;
        if (data.x == 8)
          sel_rcrd--;

        if (data.x != 21 && data.x != 8){
          selected_record = "";
          call_main_menu();
          return;
        }

        if (sel_rcrd > (num_of_IDs - 1))
          sel_rcrd = 0;
        if (sel_rcrd < 0)
          sel_rcrd = num_of_IDs - 1;

        chr = data.x;
        selected_record = String(sel_rcrd);
        tft.fillScreen(0x0000);
        tft.setTextColor(current_inact_clr);
        disp_centered_text("View Login " + String(sel_rcrd + 1) + "/" + String(num_of_IDs), 0);
        tft.fillRect(312, 0, 8, 240, current_inact_clr);
        tft.setTextColor(0xffff);
    clb_m = 2;
    decrypt_tag = false;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_title = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Username FROM Logins WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_username = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Password FROM Logins WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_password = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Website FROM Logins WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_website = dec_st;
    clear_variables();
    decrypt_tag = true;
    exeq_sql_statement_from_string("SELECT Tag FROM Logins WHERE ID = '" + IDs[sel_rcrd] + "'");
    dec_st = decrypted_title + decrypted_username + decrypted_password + decrypted_website;
    bool login_integrity = verify_integrity();
    if (login_integrity == false){
      tft.fillRect(312, 0, 8, 240, five_six_five_red_color);
      tft.setTextSize(1);
      tft.setTextColor(five_six_five_red_color);
      disp_centered_text("Integrity Verification Failed!!!", 232);
    }
    tft.setTextSize(2);
    tft.setCursor(0,16);
    tft.setTextColor(current_inact_clr);
    tft.print("Title:");
    if (login_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_title);
    tft.setTextColor(current_inact_clr);
    tft.print("Username:");
    if (login_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_username);
    tft.setTextColor(current_inact_clr);
    tft.print("Password:");
    if (login_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_password);
    tft.setTextColor(current_inact_clr);
    tft.print("Website:");
    if (login_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_website);
      }
    }

  } else {
    tft.setTextSize(2);
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Press any button", 40);
    disp_centered_text("to continue", 60);
    bool cont_to_next5 = false;
    while (cont_to_next5 == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next5 = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next5 = true;
      delay(1);
    }
    call_main_menu();
    return;
  }
}

void Add_credit_card() {
  rec_ID = "";
  gen_rand_ID(14);
  clb_m = 1;
  add_title_into_credit_card();
}

void add_title_into_credit_card() {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter Title");
  encdr_and_keyb_input();
  if (act == true) {
    encrypt_with_TDES_AES_Blowfish_Serp(encoder_input);
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.setTextSize(1);
    tft.println("Adding ID and Title into Credit Cards");
    exeq_sql_statement_from_string("INSERT INTO Credit_cards (ID, Title) VALUES( '" + rec_ID + "','" + dec_st + "');");
    add_cardholder_into_credit_card();
  }
  clear_variables();
  call_main_menu();
  return;
}

void add_cardholder_into_credit_card() {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter Cardholder Name");
  encdr_and_keyb_input();
  if (act == true) {
    encrypt_with_TDES_AES_Blowfish_Serp(encoder_input);
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.setTextSize(1);
    tft.println("Adding Cardholder Name into Credit Cards");
    exeq_sql_statement_from_string("UPDATE Credit_cards set Cardholder = '" + dec_st + "' where ID = '" + rec_ID + "';");
    add_cardnumber_into_credit_card();
  }
  clear_variables();

  return;
}

void add_cardnumber_into_credit_card() {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter Card Number");
  encdr_and_keyb_input();
  if (act == true) {
    encrypt_with_TDES_AES_Blowfish_Serp(encoder_input);
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.setTextSize(1);
    tft.println("Adding Card Number into Credit Cards");
    exeq_sql_statement_from_string("UPDATE Credit_cards set Card_Number = '" + dec_st + "' where ID = '" + rec_ID + "';");
    add_expiration_date_into_credit_card();
  }
  clear_variables();

  return;
}

void add_expiration_date_into_credit_card() {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter Expiration Date");
  encdr_and_keyb_input();
  if (act == true) {
    encrypt_with_TDES_AES_Blowfish_Serp(encoder_input);
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.setTextSize(1);
    tft.println("Adding Expiration Date into Credit Cards");
    exeq_sql_statement_from_string("UPDATE Credit_cards set Expiration_date = '" + dec_st + "' where ID = '" + rec_ID + "';");
    add_cvn_into_credit_card();
  }
  clear_variables();

  return;
}

void add_cvn_into_credit_card() {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter CVN");
  encdr_and_keyb_input();
  if (act == true) {
    encrypt_with_TDES_AES_Blowfish_Serp(encoder_input);
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.setTextSize(1);
    tft.println("Adding CVN into Credit Cards");
    exeq_sql_statement_from_string("UPDATE Credit_cards set CVN = '" + dec_st + "' where ID = '" + rec_ID + "';");
    add_pin_into_credit_card();
  }
  clear_variables();

  return;
}

void add_pin_into_credit_card() {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter PIN");
  encdr_and_keyb_input();
  if (act == true) {
    encrypt_with_TDES_AES_Blowfish_Serp(encoder_input);
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.setTextSize(1);
    tft.println("Adding PIN into Credit Cards");
    exeq_sql_statement_from_string("UPDATE Credit_cards set PIN = '" + dec_st + "' where ID = '" + rec_ID + "';");
    add_zip_code_into_credit_card();
  }
  clear_variables();

  return;
}

void add_zip_code_into_credit_card() {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter ZIP Code");
  encdr_and_keyb_input();
  if (act == true) {
    encrypt_with_TDES_AES_Blowfish_Serp(encoder_input);
    clb_m = 1;
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.setTextSize(1);
    tft.println("Adding ZIP Code into Credit_cards");
    exeq_sql_statement_from_string("UPDATE Credit_cards set ZIP_code = '" + dec_st + "' where ID = '" + rec_ID + "';");
    compute_tag_for_credit_card();
  }
  clear_variables();

  return;
}

void compute_tag_for_credit_card(){
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.setTextSize(1);
    tft.println("Extracting newly added values and computing the tag");
    clb_m = 2;
    decrypt_tag = false;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Title FROM Credit_cards WHERE ID = '" + rec_ID + "'");
    String decrypted_title = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Cardholder FROM Credit_cards WHERE ID = '" + rec_ID + "'");
    String decrypted_cardholder = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Card_Number FROM Credit_cards WHERE ID = '" + rec_ID + "'");
    String decrypted_card_number = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Expiration_date FROM Credit_cards WHERE ID = '" + rec_ID + "'");
    String decrypted_exp_date = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT CVN FROM Credit_cards WHERE ID = '" + rec_ID + "'");
    String decrypted_cvn = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT PIN FROM Credit_cards WHERE ID = '" + rec_ID + "'");
    String decrypted_pin = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT ZIP_code FROM Credit_cards WHERE ID = '" + rec_ID + "'");
    String decrypted_zip = dec_st;
    clear_variables();
    clb_m = 1;
    encr_hash_for_tdes_aes_blf_srp(decrypted_title + decrypted_cardholder + decrypted_card_number + decrypted_exp_date + decrypted_cvn + decrypted_pin + decrypted_zip);
    exeq_sql_statement_from_string("UPDATE Credit_cards set Tag = '" + dec_st + "' where ID = '" + rec_ID + "';");
    tft.setTextColor(0xffff);
    tft.fillRect(0, 230, 320, 10, 0x0000);
    disp_centered_text("Press any button to continue", 232);
    bool cont_to_next4 = false;
    while (cont_to_next4 == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next4 = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next4 = true;
      delay(1);
    }
}

void Add_credit_card_from_Serial() {
  rec_ID = "";
  gen_rand_ID(14);
  add_title_into_credit_card_from_Serial();
  clb_m = 1;
}

void add_title_into_credit_card_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setTextSize(2);
    disp_centered_text("Paste title", 40);
    disp_centered_text("to the Serial Terminal", 60);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Press any button to cancel", 220);
    Serial.println("\nPaste Title here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
    String plt = Serial.readString();
    encrypt_with_TDES_AES_Blowfish_Serp(plt);
    exeq_sql_statement_from_string("INSERT INTO Credit_cards (ID, Title) VALUES( '" + rec_ID + "','" + dec_st + "');");
    add_cardholder_into_credit_card_from_Serial();
    cont_to_next = true;
    clear_variables();
  }
  call_main_menu();
  return;
}

void add_cardholder_into_credit_card_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setTextSize(2);
    disp_centered_text("Paste Cardholder Name", 40);
    disp_centered_text("to the Serial Terminal", 60);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Press any button to cancel", 220);
    Serial.println("\nPaste Cardholder Name here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
    String plt = Serial.readString();
    encrypt_with_TDES_AES_Blowfish_Serp(plt);
    exeq_sql_statement_from_string("UPDATE Credit_cards set Cardholder = '" + dec_st + "' where ID = '" + rec_ID + "';");
    add_card_number_into_credit_card_from_Serial();
    cont_to_next = true;
    clear_variables();

    return;
  }
}

void add_card_number_into_credit_card_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setTextSize(2);
    disp_centered_text("Paste Card number", 40);
    disp_centered_text("to the Serial Terminal", 60);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Press any button to cancel", 220);
    Serial.println("\nPaste Card Number here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
    String plt = Serial.readString();
    encrypt_with_TDES_AES_Blowfish_Serp(plt);
    exeq_sql_statement_from_string("UPDATE Credit_cards set Card_Number = '" + dec_st + "' where ID = '" + rec_ID + "';");
    add_expiration_date_into_credit_card_from_Serial();
    cont_to_next = true;
    clear_variables();

    return;
  }
}

void add_expiration_date_into_credit_card_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setTextSize(2);
    disp_centered_text("Paste Expiration Date", 40);
    disp_centered_text("to the Serial Terminal", 60);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Press any button to cancel", 220);
    Serial.println("\nPaste Expiration Date here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
    String plt = Serial.readString();
    encrypt_with_TDES_AES_Blowfish_Serp(plt);
    exeq_sql_statement_from_string("UPDATE Credit_cards set Expiration_date = '" + dec_st + "' where ID = '" + rec_ID + "';");
    add_cvn_into_credit_card_from_Serial();
    cont_to_next = true;
    clear_variables();

    return;
  }
}

void add_cvn_into_credit_card_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setTextSize(2);
    disp_centered_text("Paste CVN", 40);
    disp_centered_text("to the Serial Terminal", 60);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Press any button to cancel", 220);
    Serial.println("\nPaste CVN here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
    String plt = Serial.readString();
    encrypt_with_TDES_AES_Blowfish_Serp(plt);
    exeq_sql_statement_from_string("UPDATE Credit_cards set CVN = '" + dec_st + "' where ID = '" + rec_ID + "';");
    add_pin_into_credit_card_from_Serial();
    cont_to_next = true;
    clear_variables();

    return;
  }
}

void add_pin_into_credit_card_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setTextSize(2);
    disp_centered_text("Paste PIN", 40);
    disp_centered_text("to the Serial Terminal", 60);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Press any button to cancel", 220);
    Serial.println("\nPaste PIN here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
    String plt = Serial.readString();
    encrypt_with_TDES_AES_Blowfish_Serp(plt);
    exeq_sql_statement_from_string("UPDATE Credit_cards set PIN = '" + dec_st + "' where ID = '" + rec_ID + "';");
    add_zip_code_into_credit_card_from_Serial();
    cont_to_next = true;
    clear_variables();

    return;
  }
}

void add_zip_code_into_credit_card_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setTextSize(2);
    disp_centered_text("Paste ZIP Code", 40);
    disp_centered_text("to the Serial Terminal", 60);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Press any button to cancel", 220);
    Serial.println("\nPaste ZIP Code here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
    String plt = Serial.readString();
    encrypt_with_TDES_AES_Blowfish_Serp(plt);
    exeq_sql_statement_from_string("UPDATE Credit_cards set ZIP_code = '" + dec_st + "' where ID = '" + rec_ID + "';");
    compute_tag_for_credit_card_without_disp();
    cont_to_next = true;
    clear_variables();

    return;
  }
}

void compute_tag_for_credit_card_without_disp(){
    clb_m = 2;
    decrypt_tag = false;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Title FROM Credit_cards WHERE ID = '" + rec_ID + "'");
    String decrypted_title = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Cardholder FROM Credit_cards WHERE ID = '" + rec_ID + "'");
    String decrypted_cardholder = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Card_Number FROM Credit_cards WHERE ID = '" + rec_ID + "'");
    String decrypted_card_number = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Expiration_date FROM Credit_cards WHERE ID = '" + rec_ID + "'");
    String decrypted_exp_date = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT CVN FROM Credit_cards WHERE ID = '" + rec_ID + "'");
    String decrypted_cvn = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT PIN FROM Credit_cards WHERE ID = '" + rec_ID + "'");
    String decrypted_pin = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT ZIP_code FROM Credit_cards WHERE ID = '" + rec_ID + "'");
    String decrypted_zip = dec_st;
    clear_variables();
    clb_m = 1;
    encr_hash_for_tdes_aes_blf_srp(decrypted_title + decrypted_cardholder + decrypted_card_number + decrypted_exp_date + decrypted_cvn + decrypted_pin + decrypted_zip);
    exeq_sql_statement_from_string("UPDATE Credit_cards set Tag = '" + dec_st + "' where ID = '" + rec_ID + "';");
    return;
}

void Edit_credit_card() {
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Credit_cards");
  if (num_of_IDs != 0) {
    String IDs[num_of_IDs];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i < dec_st.length() - 1; i++) {
      if (dec_st.charAt(i) != '\n')
        IDs[c_id] += dec_st.charAt(i);
      else {
        c_id++;
      }
    }
    for (int i = 0; i < num_of_IDs; i++) {
      if (IDs[i].length() > 0)
        IDs[i].remove(IDs[i].length() - 1, 1);
    }
    clear_variables();
    clb_m = 2;
    decrypt_tag = false;
    tft.fillScreen(0x0000);
    tft.setTextSize(2);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Edit Credit Card 1/" + String(num_of_IDs), 10);
    tft.setTextColor(0xffff);
    clear_variables();
    exeq_sql_statement_from_string("SELECT Title FROM Credit_cards WHERE ID = '" + IDs[0] + "'");
    disp_centered_text(dec_st, 40);
    disp_button_designation();
    String selected_record;
    bool cont_to_next = false;
    int sel_rcrd = 0;
    while (cont_to_next == false) {
      enc0.tick();
      if (enc0.left())
        sel_rcrd--;
      if (enc0.right())
        sel_rcrd++;
      if (sel_rcrd > (num_of_IDs - 1))
        sel_rcrd = 0;
      if (sel_rcrd < 0)
        sel_rcrd = num_of_IDs - 1;
      if (enc0.turn()) {
        selected_record = String(sel_rcrd);
        tft.fillScreen(0x0000);
        tft.setTextSize(2);
        tft.setTextColor(current_inact_clr);
        disp_centered_text("Edit Credit Card " + String(sel_rcrd + 1) + "/" + String(num_of_IDs), 10);
        tft.setTextColor(0xffff);
        clear_variables();
        exeq_sql_statement_from_string("SELECT Title FROM Credit_cards WHERE ID = '" + IDs[sel_rcrd] + "'");
        disp_centered_text(dec_st, 40);
        disp_button_designation();
      }
      delayMicroseconds(400);
      char chr;
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.x == 21)
          sel_rcrd++;
        if (data.x == 8)
          sel_rcrd--;

        if (sel_rcrd > (num_of_IDs - 1))
          sel_rcrd = 0;
        if (sel_rcrd < 0)
          sel_rcrd = num_of_IDs - 1;

        chr = data.x;
        selected_record = String(sel_rcrd);
        tft.fillScreen(0x0000);
        tft.setTextSize(2);
        tft.setTextColor(current_inact_clr);
        disp_centered_text("Edit Credit Card " + String(sel_rcrd + 1) + "/" + String(num_of_IDs), 10);
        tft.setTextColor(0xffff);
        clear_variables();
        exeq_sql_statement_from_string("SELECT Title FROM Credit_cards WHERE ID = '" + IDs[sel_rcrd] + "'");
        disp_centered_text(dec_st, 40);
        disp_button_designation();
      }
      delayMicroseconds(400);
      if (chr == 13 || chr == 131) {

        tft.fillScreen(0x0000);
        tft.setTextColor(current_inact_clr);
        tft.setTextSize(2);
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
          bus.tick();
          if (bus.gotData()) {
            myStruct data;
            bus.readData(data);
            if (data.x == 10)
              curr_key++;
            if (data.x == 11)
              curr_key--;

            if (curr_key < 0)
              curr_key = 1;

            if (curr_key > 1)
              curr_key = 0;

            if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
              Edit_credit_card_from_keyb_and_enc(IDs[selected_record.toInt()]);
              cont_to_next = true;
            }
            if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
              Edit_credit_card_from_Serial(IDs[selected_record.toInt()]);
              cont_to_next = true;
            }

            if (data.x == 10 || data.x == 11)
              input_source_for_data_in_flash_menu(curr_key);

            if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
              cont_to_next = true;
          }
        }

        call_main_menu();
        return;
      }
      if (chr == 27 || chr == 132) {
        call_main_menu();
        selected_record = "";
        return;
      }
    }

  } else {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Press any button", 30);
    disp_centered_text("to continue", 50);
    bool cont_to_next5 = false;
    while (cont_to_next5 == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next5 = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next5 = true;
      delay(1);
    }
    call_main_menu();
    return;
  }
}

void Edit_credit_card_from_keyb_and_enc(String selected_record) {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  set_stuff_for_input("Enter new PIN");
  encdr_and_keyb_input();
  if (act == true) {
    encrypt_with_TDES_AES_Blowfish_Serp(encoder_input);
    clb_m = 2;
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setTextSize(1);
    tft.setCursor(0, 0);
    tft.println("Setting new PIN");
    exeq_sql_statement_from_string("UPDATE Credit_cards set PIN = '" + dec_st + "' where ID = '" + selected_record + "';");
    rec_ID = selected_record;
    compute_tag_for_credit_card_without_disp();
    tft.setTextColor(0xffff);
    tft.fillRect(0, 230, 320, 10, 0x0000);
    disp_centered_text("Press any button to continue", 232);
    bool cont_to_next4 = false;
    while (cont_to_next4 == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next4 = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next4 = true;
      delay(1);
    }
  }
  clear_variables();
}

void Edit_credit_card_from_Serial(String selected_record) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setTextSize(2);
    disp_centered_text("Paste new PIN", 20);
    disp_centered_text("to the Serial Terminal", 40);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Press any button to cancel", 220);
    Serial.println("\nPaste new PIN here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
    String plt = Serial.readString();
    encrypt_with_TDES_AES_Blowfish_Serp(plt);
    exeq_sql_statement_from_string("UPDATE Credit_cards set PIN = '" + dec_st + "' where ID = '" + selected_record + "';");
    rec_ID = selected_record;
    compute_tag_for_credit_card_without_disp();
    cont_to_next = true;
    clear_variables();
    return;
  }
}

void Delete_credit_card() {
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Credit_cards");
  if (num_of_IDs != 0) {
    String IDs[num_of_IDs];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i < dec_st.length() - 1; i++) {
      if (dec_st.charAt(i) != '\n')
        IDs[c_id] += dec_st.charAt(i);
      else {
        c_id++;
      }
    }
    for (int i = 0; i < num_of_IDs; i++) {
      if (IDs[i].length() > 0)
        IDs[i].remove(IDs[i].length() - 1, 1);
    }
    clear_variables();
    clb_m = 2;
    decrypt_tag = false;
    tft.fillScreen(0x0000);
    tft.setTextSize(2);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Delete Credit Card 1/" + String(num_of_IDs), 10);
    tft.setTextColor(0xffff);
    clear_variables();
    exeq_sql_statement_from_string("SELECT Title FROM Credit_cards WHERE ID = '" + IDs[0] + "'");
    disp_centered_text(dec_st, 40);
    disp_button_designation_for_del();
    String selected_record;
    bool cont_to_next = false;
    int sel_rcrd = 0;
    while (cont_to_next == false) {
      enc0.tick();
      if (enc0.left())
        sel_rcrd--;
      if (enc0.right())
        sel_rcrd++;
      if (sel_rcrd > (num_of_IDs - 1))
        sel_rcrd = 0;
      if (sel_rcrd < 0)
        sel_rcrd = num_of_IDs - 1;
      if (enc0.turn()) {
        selected_record = String(sel_rcrd);
        tft.fillScreen(0x0000);
        tft.setTextColor(five_six_five_red_color);
        tft.setTextSize(2);
        disp_centered_text("Delete Credit Card " + String(sel_rcrd + 1) + "/" + String(num_of_IDs), 10);
        tft.setTextColor(0xffff);
        clear_variables();
        exeq_sql_statement_from_string("SELECT Title FROM Credit_cards WHERE ID = '" + IDs[sel_rcrd] + "'");
        disp_centered_text(dec_st, 40);
        disp_button_designation_for_del();
      }
      delayMicroseconds(400);
      char chr;
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.x == 21)
          sel_rcrd++;
        if (data.x == 8)
          sel_rcrd--;

        if (sel_rcrd > (num_of_IDs - 1))
          sel_rcrd = 0;
        if (sel_rcrd < 0)
          sel_rcrd = num_of_IDs - 1;

        chr = data.x;
        selected_record = String(sel_rcrd);
        tft.fillScreen(0x0000);
        tft.setTextColor(five_six_five_red_color);
        tft.setTextSize(2);
        disp_centered_text("Delete Credit Card " + String(sel_rcrd + 1) + "/" + String(num_of_IDs), 10);
        tft.setTextColor(0xffff);
        clear_variables();
        exeq_sql_statement_from_string("SELECT Title FROM Credit_cards WHERE ID = '" + IDs[sel_rcrd] + "'");
        disp_centered_text(dec_st, 40);
        disp_button_designation_for_del();
      }
      delayMicroseconds(400);
      if (chr == 13 || chr == 131) {
        clb_m = 1;
        /*
        Serial.println(IDs[selected_record.toInt()][0]);
        String tdel = "DELETE FROM Credit_cards WHERE ID = '";
        for (int i = 0; i < IDs[selected_record.toInt()][0].length(); i++){
          tdel += (IDs[selected_record.toInt()][0].charAt(i));
        }
        tdel += "'";
        exeq_sql_statement_from_string(tdel);
        */
        tft.fillScreen(0x0000);
        tft.setTextColor(0xffff);
        tft.setCursor(0, 0);
        exeq_sql_statement_from_string("DELETE FROM Credit_cards WHERE ID = '" + IDs[selected_record.toInt()] + "'");
        tft.setTextColor(0xffff);
        tft.fillRect(0, 230, 320, 10, 0x0000);
        disp_centered_text("Press any button to continue", 232);
        bool cont_to_next4 = false;
        while (cont_to_next4 == false) {
          bus.tick();
          if (bus.gotData())
            cont_to_next4 = true;
          delay(1);
          encoder_button.tick();
          if (encoder_button.press())
            cont_to_next4 = true;
          delay(1);
        }
        call_main_menu();
        return;
      }
      if (chr == 27 || chr == 132) {
        selected_record = "";
        call_main_menu();
        return;
      }
    }

  } else {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Press any button", 40);
    disp_centered_text("to continue", 60);
    bool cont_to_next5 = false;
    while (cont_to_next5 == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next5 = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next5 = true;
      delay(1);
    }
    call_main_menu();
    return;
  }
}

void View_credit_card() {
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Credit_cards");
  if (num_of_IDs != 0) {
    String IDs[num_of_IDs];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i < dec_st.length() - 1; i++) {
      if (dec_st.charAt(i) != '\n')
        IDs[c_id] += dec_st.charAt(i);
      else {
        c_id++;
      }
    }
    for (int i = 0; i < num_of_IDs; i++) {
      if (IDs[i].length() > 0)
        IDs[i].remove(IDs[i].length() - 1, 1);
    }
    clear_variables();
    tft.fillScreen(0x0000);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View Credit Card 1/" + String(num_of_IDs), 0);
    tft.fillRect(312, 0, 8, 240, current_inact_clr);
    tft.setTextColor(0xffff);
    clb_m = 2;
    decrypt_tag = false;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Title FROM Credit_cards WHERE ID = '" + IDs[0] + "'");
    String decrypted_title = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Cardholder FROM Credit_cards WHERE ID = '" + IDs[0] + "'");
    String decrypted_cardholder = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Card_Number FROM Credit_cards WHERE ID = '" + IDs[0] + "'");
    String decrypted_card_number = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Expiration_date FROM Credit_cards WHERE ID = '" + IDs[0] + "'");
    String decrypted_expiration_date = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT CVN FROM Credit_cards WHERE ID = '" + IDs[0] + "'");
    String decrypted_cvn = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT PIN FROM Credit_cards WHERE ID = '" + IDs[0] + "'");
    String decrypted_pin = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT ZIP_code FROM Credit_cards WHERE ID = '" + IDs[0] + "'");
    String decrypted_zip_code = dec_st;
    clear_variables();
    decrypt_tag = true;
    exeq_sql_statement_from_string("SELECT Tag FROM Credit_cards WHERE ID = '" + IDs[0] + "'");
    dec_st = decrypted_title + decrypted_cardholder + decrypted_card_number + decrypted_expiration_date + decrypted_cvn + decrypted_pin + decrypted_zip_code;
    bool credit_card_integrity = verify_integrity();
    if (credit_card_integrity == false){
      tft.fillRect(312, 0, 8, 240, five_six_five_red_color);
      tft.setTextSize(1);
      tft.setTextColor(five_six_five_red_color);
      disp_centered_text("Integrity Verification Failed!!!", 232);
    }
    tft.setTextSize(2);
    tft.setCursor(0,16);
    tft.setTextColor(current_inact_clr);
    tft.print("Title:");
    if (credit_card_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_title);
    tft.setTextColor(current_inact_clr);
    tft.print("Cardholder:");
    if (credit_card_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_cardholder);
    tft.setTextColor(current_inact_clr);
    tft.print("Card Number:");
    if (credit_card_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_card_number);
    tft.setTextColor(current_inact_clr);
    tft.print("Expiration Date:");
    if (credit_card_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_expiration_date);
    tft.setTextColor(current_inact_clr);
    tft.print("CVN:");
    if (credit_card_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_cvn);
    tft.setTextColor(current_inact_clr);
    tft.print("PIN:");
    if (credit_card_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_pin);
    tft.setTextColor(current_inact_clr);
    tft.print("ZIP Code:");
    if (credit_card_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_zip_code);
    String selected_record;
    bool cont_to_next = false;
    int sel_rcrd = 0;
    while (cont_to_next == false) {
      enc0.tick();
      if (enc0.left())
        sel_rcrd--;
      if (enc0.right())
        sel_rcrd++;
      if (sel_rcrd > (num_of_IDs - 1))
        sel_rcrd = 0;
      if (sel_rcrd < 0)
        sel_rcrd = num_of_IDs - 1;
      if (enc0.turn()) {
        selected_record = String(sel_rcrd);
        tft.fillScreen(0x0000);
        tft.setTextColor(current_inact_clr);
        disp_centered_text("View Credit Card " + String(sel_rcrd + 1) + "/" + String(num_of_IDs), 0);
        tft.fillRect(312, 0, 8, 240, current_inact_clr);
        tft.setTextColor(0xffff);
    clb_m = 2;
    decrypt_tag = false;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Title FROM Credit_cards WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_title = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Cardholder FROM Credit_cards WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_cardholder = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Card_Number FROM Credit_cards WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_card_number = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Expiration_date FROM Credit_cards WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_expiration_date = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT CVN FROM Credit_cards WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_cvn = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT PIN FROM Credit_cards WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_pin = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT ZIP_code FROM Credit_cards WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_zip_code = dec_st;
    clear_variables();
    decrypt_tag = true;
    exeq_sql_statement_from_string("SELECT Tag FROM Credit_cards WHERE ID = '" + IDs[sel_rcrd] + "'");
    dec_st = decrypted_title + decrypted_cardholder + decrypted_card_number + decrypted_expiration_date + decrypted_cvn + decrypted_pin + decrypted_zip_code;
    bool credit_card_integrity = verify_integrity();
    if (credit_card_integrity == false){
      tft.fillRect(312, 0, 8, 240, five_six_five_red_color);
      tft.setTextSize(1);
      tft.setTextColor(five_six_five_red_color);
      disp_centered_text("Integrity Verification Failed!!!", 232);
    }
    tft.setTextSize(2);
    tft.setCursor(0,16);
    tft.setTextColor(current_inact_clr);
    tft.print("Title:");
    if (credit_card_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_title);
    tft.setTextColor(current_inact_clr);
    tft.print("Cardholder:");
    if (credit_card_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_cardholder);
    tft.setTextColor(current_inact_clr);
    tft.print("Card Number:");
    if (credit_card_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_card_number);
    tft.setTextColor(current_inact_clr);
    tft.print("Expiration Date:");
    if (credit_card_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_expiration_date);
    tft.setTextColor(current_inact_clr);
    tft.print("CVN:");
    if (credit_card_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_cvn);
    tft.setTextColor(current_inact_clr);
    tft.print("PIN:");
    if (credit_card_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_pin);
    tft.setTextColor(current_inact_clr);
    tft.print("ZIP Code:");
    if (credit_card_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_zip_code);
      }
      delayMicroseconds(400);
      char chr;
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.x == 21)
          sel_rcrd++;
        if (data.x == 8)
          sel_rcrd--;

        if (data.x != 21 && data.x != 8){
          selected_record = "";
          call_main_menu();
          return;
        }

        if (sel_rcrd > (num_of_IDs - 1))
          sel_rcrd = 0;
        if (sel_rcrd < 0)
          sel_rcrd = num_of_IDs - 1;

        chr = data.x;
        selected_record = String(sel_rcrd);
        tft.fillScreen(0x0000);
        tft.setTextColor(current_inact_clr);
        disp_centered_text("View Credit Card " + String(sel_rcrd + 1) + "/" + String(num_of_IDs), 0);
        tft.fillRect(312, 0, 8, 240, current_inact_clr);
        tft.setTextColor(0xffff);
    clb_m = 2;
    decrypt_tag = false;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Title FROM Credit_cards WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_title = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Cardholder FROM Credit_cards WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_cardholder = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Card_Number FROM Credit_cards WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_card_number = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Expiration_date FROM Credit_cards WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_expiration_date = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT CVN FROM Credit_cards WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_cvn = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT PIN FROM Credit_cards WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_pin = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT ZIP_code FROM Credit_cards WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_zip_code = dec_st;
    clear_variables();
    decrypt_tag = true;
    exeq_sql_statement_from_string("SELECT Tag FROM Credit_cards WHERE ID = '" + IDs[sel_rcrd] + "'");
    dec_st = decrypted_title + decrypted_cardholder + decrypted_card_number + decrypted_expiration_date + decrypted_cvn + decrypted_pin + decrypted_zip_code;
    bool credit_card_integrity = verify_integrity();
    if (credit_card_integrity == false){
      tft.fillRect(312, 0, 8, 240, five_six_five_red_color);
      tft.setTextSize(1);
      tft.setTextColor(five_six_five_red_color);
      disp_centered_text("Integrity Verification Failed!!!", 232);
    }
    tft.setTextSize(2);
    tft.setCursor(0,16);
    tft.setTextColor(current_inact_clr);
    tft.print("Title:");
    if (credit_card_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_title);
    tft.setTextColor(current_inact_clr);
    tft.print("Cardholder:");
    if (credit_card_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_cardholder);
    tft.setTextColor(current_inact_clr);
    tft.print("Card Number:");
    if (credit_card_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_card_number);
    tft.setTextColor(current_inact_clr);
    tft.print("Expiration Date:");
    if (credit_card_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_expiration_date);
    tft.setTextColor(current_inact_clr);
    tft.print("CVN:");
    if (credit_card_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_cvn);
    tft.setTextColor(current_inact_clr);
    tft.print("PIN:");
    if (credit_card_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_pin);
    tft.setTextColor(current_inact_clr);
    tft.print("ZIP Code:");
    if (credit_card_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_zip_code);
      }
    }

  } else {
    tft.setTextSize(2);
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Press any button", 40);
    disp_centered_text("to continue", 60);
    bool cont_to_next5 = false;
    while (cont_to_next5 == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next5 = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next5 = true;
      delay(1);
    }
    call_main_menu();
    return;
  }
}

void Add_note() {
  rec_ID = "";
  gen_rand_ID(13);
  clb_m = 1;
  add_title_into_note();
}

void add_title_into_note() {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter Title");
  encdr_and_keyb_input();
  if (act == true) {
    encrypt_with_TDES_AES_Blowfish_Serp(encoder_input);
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.setTextSize(1);
    tft.println("Adding ID and Title into Notes");
    exeq_sql_statement_from_string("INSERT INTO Notes (ID, Title) VALUES( '" + rec_ID + "','" + dec_st + "');");
    add_content_into_note();
  }
  clear_variables();
  call_main_menu();
  return;
}

void add_content_into_note() {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter Content");
  encdr_and_keyb_input();
  if (act == true) {
    encrypt_with_TDES_AES_Blowfish_Serp(encoder_input);
    clb_m = 1;
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.setTextSize(1);
    tft.println("Adding Content into Notes");
    exeq_sql_statement_from_string("UPDATE Notes set Content = '" + dec_st + "' where ID = '" + rec_ID + "';");
    compute_tag_for_note();
  }
  clear_variables();

  return;
}

void compute_tag_for_note(){
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.setTextSize(1);
    tft.println("Extracting newly added values and computing the tag");
    clb_m = 2;
    decrypt_tag = false;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Title FROM Notes WHERE ID = '" + rec_ID + "'");
    String decrypted_title = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Content FROM Notes WHERE ID = '" + rec_ID + "'");
    String decrypted_content = dec_st;
    clear_variables();
    clb_m = 1;
    encr_hash_for_tdes_aes_blf_srp(decrypted_title + decrypted_content);
    exeq_sql_statement_from_string("UPDATE Notes set Tag = '" + dec_st + "' where ID = '" + rec_ID + "';");
    tft.setTextColor(0xffff);
    tft.fillRect(0, 230, 320, 10, 0x0000);
    disp_centered_text("Press any button to continue", 232);
    bool cont_to_next4 = false;
    while (cont_to_next4 == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next4 = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next4 = true;
      delay(1);
    }
}

void Add_note_from_Serial() {
  rec_ID = "";
  gen_rand_ID(13);
  add_title_into_note_from_Serial();
  clb_m = 1;
}

void add_title_into_note_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setTextSize(2);
    disp_centered_text("Paste title", 40);
    disp_centered_text("to the Serial Terminal", 60);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Press any button to cancel", 220);
    Serial.println("\nPaste Title here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
    String plt = Serial.readString();
    encrypt_with_TDES_AES_Blowfish_Serp(plt);
    exeq_sql_statement_from_string("INSERT INTO Notes (ID, Title) VALUES( '" + rec_ID + "','" + dec_st + "');");
    add_content_into_note_from_Serial();
    cont_to_next = true;
    clear_variables();
  }
  call_main_menu();
  return;
}

void add_content_into_note_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setTextSize(2);
    disp_centered_text("Paste Content", 40);
    disp_centered_text("to the Serial Terminal", 60);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Press any button to cancel", 220);
    Serial.println("\nPaste Content here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
    String plt = Serial.readString();
    encrypt_with_TDES_AES_Blowfish_Serp(plt);
    exeq_sql_statement_from_string("UPDATE Notes set Content = '" + dec_st + "' where ID = '" + rec_ID + "';");
    compute_tag_for_note_without_disp();
    cont_to_next = true;
    clear_variables();

    return;
  }
}

void compute_tag_for_note_without_disp(){
    clb_m = 2;
    decrypt_tag = false;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Title FROM Notes WHERE ID = '" + rec_ID + "'");
    String decrypted_title = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Content FROM Notes WHERE ID = '" + rec_ID + "'");
    String decrypted_content = dec_st;
    clear_variables();
    clb_m = 1;
    encr_hash_for_tdes_aes_blf_srp(decrypted_title + decrypted_content);
    exeq_sql_statement_from_string("UPDATE Notes set Tag = '" + dec_st + "' where ID = '" + rec_ID + "';");
    return;
}

void Edit_note() {
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Notes");
  if (num_of_IDs != 0) {
    String IDs[num_of_IDs];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i < dec_st.length() - 1; i++) {
      if (dec_st.charAt(i) != '\n')
        IDs[c_id] += dec_st.charAt(i);
      else {
        c_id++;
      }
    }
    for (int i = 0; i < num_of_IDs; i++) {
      if (IDs[i].length() > 0)
        IDs[i].remove(IDs[i].length() - 1, 1);
    }
    clear_variables();
    clb_m = 2;
    decrypt_tag = false;
    tft.fillScreen(0x0000);
    tft.setTextSize(2);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Edit Note 1/" + String(num_of_IDs), 10);
    tft.setTextColor(0xffff);
    clear_variables();
    exeq_sql_statement_from_string("SELECT Title FROM Notes WHERE ID = '" + IDs[0] + "'");
    disp_centered_text(dec_st, 40);
    disp_button_designation();
    String selected_record;
    bool cont_to_next = false;
    int sel_rcrd = 0;
    while (cont_to_next == false) {
      enc0.tick();
      if (enc0.left())
        sel_rcrd--;
      if (enc0.right())
        sel_rcrd++;
      if (sel_rcrd > (num_of_IDs - 1))
        sel_rcrd = 0;
      if (sel_rcrd < 0)
        sel_rcrd = num_of_IDs - 1;
      if (enc0.turn()) {
        selected_record = String(sel_rcrd);
        tft.fillScreen(0x0000);
        tft.setTextSize(2);
        tft.setTextColor(current_inact_clr);
        disp_centered_text("Edit Note " + String(sel_rcrd + 1) + "/" + String(num_of_IDs), 10);
        tft.setTextColor(0xffff);
        clear_variables();
        exeq_sql_statement_from_string("SELECT Title FROM Notes WHERE ID = '" + IDs[sel_rcrd] + "'");
        disp_centered_text(dec_st, 40);
        disp_button_designation();
      }
      delayMicroseconds(400);
      char chr;
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.x == 21)
          sel_rcrd++;
        if (data.x == 8)
          sel_rcrd--;

        if (sel_rcrd > (num_of_IDs - 1))
          sel_rcrd = 0;
        if (sel_rcrd < 0)
          sel_rcrd = num_of_IDs - 1;

        chr = data.x;
        selected_record = String(sel_rcrd);
        tft.fillScreen(0x0000);
        tft.setTextSize(2);
        tft.setTextColor(current_inact_clr);
        disp_centered_text("Edit Note " + String(sel_rcrd + 1) + "/" + String(num_of_IDs), 10);
        tft.setTextColor(0xffff);
        clear_variables();
        exeq_sql_statement_from_string("SELECT Title FROM Notes WHERE ID = '" + IDs[sel_rcrd] + "'");
        disp_centered_text(dec_st, 40);
        disp_button_designation();
      }
      delayMicroseconds(400);
      if (chr == 13 || chr == 131) {

        tft.fillScreen(0x0000);
        tft.setTextColor(current_inact_clr);
        tft.setTextSize(2);
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
          bus.tick();
          if (bus.gotData()) {
            myStruct data;
            bus.readData(data);
            if (data.x == 10)
              curr_key++;
            if (data.x == 11)
              curr_key--;

            if (curr_key < 0)
              curr_key = 1;

            if (curr_key > 1)
              curr_key = 0;

            if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
              Edit_note_from_keyb_and_enc(IDs[selected_record.toInt()]);
              cont_to_next = true;
            }
            if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
              Edit_note_from_Serial(IDs[selected_record.toInt()]);
              cont_to_next = true;
            }

            if (data.x == 10 || data.x == 11)
              input_source_for_data_in_flash_menu(curr_key);

            if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
              cont_to_next = true;
          }
        }

        call_main_menu();
        return;
      }
      if (chr == 27 || chr == 132) {
        call_main_menu();
        selected_record = "";
        return;
      }
    }

  } else {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Press any button", 30);
    disp_centered_text("to continue", 50);
    bool cont_to_next5 = false;
    while (cont_to_next5 == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next5 = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next5 = true;
      delay(1);
    }
    call_main_menu();
    return;
  }
}

void Edit_note_from_keyb_and_enc(String selected_record) {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  set_stuff_for_input("Enter new Content");
  encdr_and_keyb_input();
  if (act == true) {
    encrypt_with_TDES_AES_Blowfish_Serp(encoder_input);
    clb_m = 2;
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setTextSize(1);
    tft.setCursor(0, 0);
    tft.println("Setting new Content");
    exeq_sql_statement_from_string("UPDATE Notes set Content = '" + dec_st + "' where ID = '" + selected_record + "';");
    rec_ID = selected_record;
    compute_tag_for_note_without_disp();
    tft.setTextColor(0xffff);
    tft.fillRect(0, 230, 320, 10, 0x0000);
    disp_centered_text("Press any button to continue", 232);
    bool cont_to_next4 = false;
    while (cont_to_next4 == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next4 = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next4 = true;
      delay(1);
    }
  }
  clear_variables();
}

void Edit_note_from_Serial(String selected_record) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setTextSize(2);
    disp_centered_text("Paste new Content", 20);
    disp_centered_text("to the Serial Terminal", 40);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Press any button to cancel", 220);
    Serial.println("\nPaste new Content here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
    String plt = Serial.readString();
    encrypt_with_TDES_AES_Blowfish_Serp(plt);
    exeq_sql_statement_from_string("UPDATE Notes set Content = '" + dec_st + "' where ID = '" + selected_record + "';");
    rec_ID = selected_record;
    compute_tag_for_note_without_disp();
    cont_to_next = true;
    clear_variables();
    return;
  }
}

void Delete_note() {
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Notes");
  if (num_of_IDs != 0) {
    String IDs[num_of_IDs];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i < dec_st.length() - 1; i++) {
      if (dec_st.charAt(i) != '\n')
        IDs[c_id] += dec_st.charAt(i);
      else {
        c_id++;
      }
    }
    for (int i = 0; i < num_of_IDs; i++) {
      if (IDs[i].length() > 0)
        IDs[i].remove(IDs[i].length() - 1, 1);
    }
    clear_variables();
    clb_m = 2;
    decrypt_tag = false;
    tft.fillScreen(0x0000);
    tft.setTextSize(2);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Delete Note 1/" + String(num_of_IDs), 10);
    tft.setTextColor(0xffff);
    clear_variables();
    exeq_sql_statement_from_string("SELECT Title FROM Notes WHERE ID = '" + IDs[0] + "'");
    disp_centered_text(dec_st, 40);
    disp_button_designation_for_del();
    String selected_record;
    bool cont_to_next = false;
    int sel_rcrd = 0;
    while (cont_to_next == false) {
      enc0.tick();
      if (enc0.left())
        sel_rcrd--;
      if (enc0.right())
        sel_rcrd++;
      if (sel_rcrd > (num_of_IDs - 1))
        sel_rcrd = 0;
      if (sel_rcrd < 0)
        sel_rcrd = num_of_IDs - 1;
      if (enc0.turn()) {
        selected_record = String(sel_rcrd);
        tft.fillScreen(0x0000);
        tft.setTextColor(five_six_five_red_color);
        tft.setTextSize(2);
        disp_centered_text("Delete Note " + String(sel_rcrd + 1) + "/" + String(num_of_IDs), 10);
        tft.setTextColor(0xffff);
        clear_variables();
        exeq_sql_statement_from_string("SELECT Title FROM Notes WHERE ID = '" + IDs[sel_rcrd] + "'");
        disp_centered_text(dec_st, 40);
        disp_button_designation_for_del();
      }
      delayMicroseconds(400);
      char chr;
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.x == 21)
          sel_rcrd++;
        if (data.x == 8)
          sel_rcrd--;

        if (sel_rcrd > (num_of_IDs - 1))
          sel_rcrd = 0;
        if (sel_rcrd < 0)
          sel_rcrd = num_of_IDs - 1;

        chr = data.x;
        selected_record = String(sel_rcrd);
        tft.fillScreen(0x0000);
        tft.setTextColor(five_six_five_red_color);
        tft.setTextSize(2);
        disp_centered_text("Delete Note " + String(sel_rcrd + 1) + "/" + String(num_of_IDs), 10);
        tft.setTextColor(0xffff);
        clear_variables();
        exeq_sql_statement_from_string("SELECT Title FROM Notes WHERE ID = '" + IDs[sel_rcrd] + "'");
        disp_centered_text(dec_st, 40);
        disp_button_designation_for_del();
      }
      delayMicroseconds(400);
      if (chr == 13 || chr == 131) {
        clb_m = 1;
        /*
        Serial.println(IDs[selected_record.toInt()][0]);
        String tdel = "DELETE FROM Notes WHERE ID = '";
        for (int i = 0; i < IDs[selected_record.toInt()][0].length(); i++){
          tdel += (IDs[selected_record.toInt()][0].charAt(i));
        }
        tdel += "'";
        exeq_sql_statement_from_string(tdel);
        */
        tft.fillScreen(0x0000);
        tft.setTextColor(0xffff);
        tft.setCursor(0, 0);
        exeq_sql_statement_from_string("DELETE FROM Notes WHERE ID = '" + IDs[selected_record.toInt()] + "'");
        tft.setTextColor(0xffff);
        tft.fillRect(0, 230, 320, 10, 0x0000);
        disp_centered_text("Press any button to continue", 232);
        bool cont_to_next4 = false;
        while (cont_to_next4 == false) {
          bus.tick();
          if (bus.gotData())
            cont_to_next4 = true;
          delay(1);
          encoder_button.tick();
          if (encoder_button.press())
            cont_to_next4 = true;
          delay(1);
        }
        call_main_menu();
        return;
      }
      if (chr == 27 || chr == 132) {
        selected_record = "";
        call_main_menu();
        return;
      }
    }

  } else {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Press any button", 40);
    disp_centered_text("to continue", 60);
    bool cont_to_next5 = false;
    while (cont_to_next5 == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next5 = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next5 = true;
      delay(1);
    }
    call_main_menu();
    return;
  }
}

void View_note() {
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Notes");
  if (num_of_IDs != 0) {
    String IDs[num_of_IDs];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i < dec_st.length() - 1; i++) {
      if (dec_st.charAt(i) != '\n')
        IDs[c_id] += dec_st.charAt(i);
      else {
        c_id++;
      }
    }
    for (int i = 0; i < num_of_IDs; i++) {
      if (IDs[i].length() > 0)
        IDs[i].remove(IDs[i].length() - 1, 1);
    }
    clear_variables();
    tft.fillScreen(0x0000);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View Note 1/" + String(num_of_IDs), 0);
    tft.fillRect(312, 0, 8, 240, current_inact_clr);
    tft.setTextColor(0xffff);
    clb_m = 2;
    decrypt_tag = false;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Title FROM Notes WHERE ID = '" + IDs[0] + "'");
    String decrypted_title = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Content FROM Notes WHERE ID = '" + IDs[0] + "'");
    String decrypted_content = dec_st;
    clear_variables();
    decrypt_tag = true;
    exeq_sql_statement_from_string("SELECT Tag FROM Notes WHERE ID = '" + IDs[0] + "'");
    dec_st = decrypted_title + decrypted_content;
    bool note_integrity = verify_integrity();
    if (note_integrity == false){
      tft.fillRect(312, 0, 8, 240, five_six_five_red_color);
      tft.setTextSize(1);
      tft.setTextColor(five_six_five_red_color);
      disp_centered_text("Integrity Verification Failed!!!", 232);
    }
    tft.setTextSize(2);
    tft.setCursor(0,16);
    tft.setTextColor(current_inact_clr);
    tft.print("Title:");
    if (note_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_title);
    tft.setTextColor(current_inact_clr);
    tft.print("Content:");
    if (note_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_content);
    String selected_record;
    bool cont_to_next = false;
    int sel_rcrd = 0;
    while (cont_to_next == false) {
      enc0.tick();
      if (enc0.left())
        sel_rcrd--;
      if (enc0.right())
        sel_rcrd++;
      if (sel_rcrd > (num_of_IDs - 1))
        sel_rcrd = 0;
      if (sel_rcrd < 0)
        sel_rcrd = num_of_IDs - 1;
      if (enc0.turn()) {
        selected_record = String(sel_rcrd);
        tft.fillScreen(0x0000);
        tft.setTextColor(current_inact_clr);
        disp_centered_text("View Note " + String(sel_rcrd + 1) + "/" + String(num_of_IDs), 0);
        tft.fillRect(312, 0, 8, 240, current_inact_clr);
        tft.setTextColor(0xffff);
    clb_m = 2;
    decrypt_tag = false;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Title FROM Notes WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_title = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Content FROM Notes WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_content = dec_st;
    clear_variables();
    decrypt_tag = true;
    exeq_sql_statement_from_string("SELECT Tag FROM Notes WHERE ID = '" + IDs[sel_rcrd] + "'");
    dec_st = decrypted_title + decrypted_content;
    bool note_integrity = verify_integrity();
    if (note_integrity == false){
      tft.fillRect(312, 0, 8, 240, five_six_five_red_color);
      tft.setTextSize(1);
      tft.setTextColor(five_six_five_red_color);
      disp_centered_text("Integrity Verification Failed!!!", 232);
    }
    tft.setTextSize(2);
    tft.setCursor(0,16);
    tft.setTextColor(current_inact_clr);
    tft.print("Title:");
    if (note_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_title);
    tft.setTextColor(current_inact_clr);
    tft.print("Content:");
    if (note_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_content);
      }
      delayMicroseconds(400);
      char chr;
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.x == 21)
          sel_rcrd++;
        if (data.x == 8)
          sel_rcrd--;

        if (data.x != 21 && data.x != 8){
          selected_record = "";
          call_main_menu();
          return;
        }

        if (sel_rcrd > (num_of_IDs - 1))
          sel_rcrd = 0;
        if (sel_rcrd < 0)
          sel_rcrd = num_of_IDs - 1;

        chr = data.x;
        selected_record = String(sel_rcrd);
        tft.fillScreen(0x0000);
        tft.setTextColor(current_inact_clr);
        disp_centered_text("View Note " + String(sel_rcrd + 1) + "/" + String(num_of_IDs), 0);
        tft.fillRect(312, 0, 8, 240, current_inact_clr);
        tft.setTextColor(0xffff);
    clb_m = 2;
    decrypt_tag = false;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Title FROM Notes WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_title = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Content FROM Notes WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_content = dec_st;
    clear_variables();
    decrypt_tag = true;
    exeq_sql_statement_from_string("SELECT Tag FROM Notes WHERE ID = '" + IDs[sel_rcrd] + "'");
    dec_st = decrypted_title + decrypted_content;
    bool note_integrity = verify_integrity();
    if (note_integrity == false){
      tft.fillRect(312, 0, 8, 240, five_six_five_red_color);
      tft.setTextSize(1);
      tft.setTextColor(five_six_five_red_color);
      disp_centered_text("Integrity Verification Failed!!!", 232);
    }
    tft.setTextSize(2);
    tft.setCursor(0,16);
    tft.setTextColor(current_inact_clr);
    tft.print("Title:");
    if (note_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_title);
    tft.setTextColor(current_inact_clr);
    tft.print("Content:");
    if (note_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_content);
      }
    }

  } else {
    tft.setTextSize(2);
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Press any button", 40);
    disp_centered_text("to continue", 60);
    bool cont_to_next5 = false;
    while (cont_to_next5 == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next5 = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next5 = true;
      delay(1);
    }
    call_main_menu();
    return;
  }
}

void Add_phone_number() {
  rec_ID = "";
  gen_rand_ID(13);
  clb_m = 1;
  add_title_into_phone_number();
}

void add_title_into_phone_number() {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter Title");
  encdr_and_keyb_input();
  if (act == true) {
    encrypt_with_TDES_AES_Blowfish_Serp(encoder_input);
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.setTextSize(1);
    tft.println("Adding ID and Title into Phone_Numbers");
    exeq_sql_statement_from_string("INSERT INTO Phone_Numbers (ID, Title) VALUES( '" + rec_ID + "','" + dec_st + "');");
    add_content_into_phone_number();
  }
  clear_variables();
  call_main_menu();
  return;
}

void add_content_into_phone_number() {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter Phone Number");
  encdr_and_keyb_input();
  if (act == true) {
    encrypt_with_TDES_AES_Blowfish_Serp(encoder_input);
    clb_m = 1;
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.setTextSize(1);
    tft.println("Adding Phone Number into Phone_Numbers");
    exeq_sql_statement_from_string("UPDATE Phone_Numbers set Phone = '" + dec_st + "' where ID = '" + rec_ID + "';");
    compute_tag_for_phone_number();
  }
  clear_variables();

  return;
}

void compute_tag_for_phone_number(){
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.setTextSize(1);
    tft.println("Extracting newly added values and computing the tag");
    clb_m = 2;
    decrypt_tag = false;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Title FROM Phone_Numbers WHERE ID = '" + rec_ID + "'");
    String decrypted_title = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Phone FROM Phone_Numbers WHERE ID = '" + rec_ID + "'");
    String decrypted_phone_number = dec_st;
    clear_variables();
    clb_m = 1;
    encr_hash_for_tdes_aes_blf_srp(decrypted_title + decrypted_phone_number);
    exeq_sql_statement_from_string("UPDATE Phone_Numbers set Tag = '" + dec_st + "' where ID = '" + rec_ID + "';");
    tft.setTextColor(0xffff);
    tft.fillRect(0, 230, 320, 10, 0x0000);
    disp_centered_text("Press any button to continue", 232);
    bool cont_to_next4 = false;
    while (cont_to_next4 == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next4 = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next4 = true;
      delay(1);
    }
}

void Add_phone_number_from_Serial() {
  rec_ID = "";
  gen_rand_ID(13);
  add_title_into_phone_number_from_Serial();
  clb_m = 1;
}

void add_title_into_phone_number_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setTextSize(2);
    disp_centered_text("Paste title", 40);
    disp_centered_text("to the Serial Terminal", 60);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Press any button to cancel", 220);
    Serial.println("\nPaste Title here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
    String plt = Serial.readString();
    encrypt_with_TDES_AES_Blowfish_Serp(plt);
    exeq_sql_statement_from_string("INSERT INTO Phone_Numbers (ID, Title) VALUES( '" + rec_ID + "','" + dec_st + "');");
    add_content_into_phone_number_from_Serial();
    cont_to_next = true;
    clear_variables();
  }
  call_main_menu();
  return;
}

void add_content_into_phone_number_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setTextSize(2);
    disp_centered_text("Paste Phone", 40);
    disp_centered_text("to the Serial Terminal", 60);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Press any button to cancel", 220);
    Serial.println("\nPaste Phone here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
    String plt = Serial.readString();
    encrypt_with_TDES_AES_Blowfish_Serp(plt);
    exeq_sql_statement_from_string("UPDATE Phone_Numbers set Phone = '" + dec_st + "' where ID = '" + rec_ID + "';");
    compute_tag_for_phone_number_without_disp();
    cont_to_next = true;
    clear_variables();

    return;
  }
}

void compute_tag_for_phone_number_without_disp(){
    clb_m = 2;
    decrypt_tag = false;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Title FROM Phone_Numbers WHERE ID = '" + rec_ID + "'");
    String decrypted_title = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Phone FROM Phone_Numbers WHERE ID = '" + rec_ID + "'");
    String decrypted_phone_number = dec_st;
    clear_variables();
    clb_m = 1;
    encr_hash_for_tdes_aes_blf_srp(decrypted_title + decrypted_phone_number);
    exeq_sql_statement_from_string("UPDATE Phone_Numbers set Tag = '" + dec_st + "' where ID = '" + rec_ID + "';");
    return;
}

void Edit_phone_number() {
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Phone_Numbers");
  if (num_of_IDs != 0) {
    String IDs[num_of_IDs];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i < dec_st.length() - 1; i++) {
      if (dec_st.charAt(i) != '\n')
        IDs[c_id] += dec_st.charAt(i);
      else {
        c_id++;
      }
    }
    for (int i = 0; i < num_of_IDs; i++) {
      if (IDs[i].length() > 0)
        IDs[i].remove(IDs[i].length() - 1, 1);
    }
    clear_variables();
    clb_m = 2;
    decrypt_tag = false;
    tft.fillScreen(0x0000);
    tft.setTextSize(2);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Edit Phone Number 1/" + String(num_of_IDs), 10);
    tft.setTextColor(0xffff);
    clear_variables();
    exeq_sql_statement_from_string("SELECT Title FROM Phone_Numbers WHERE ID = '" + IDs[0] + "'");
    disp_centered_text(dec_st, 40);
    disp_button_designation();
    String selected_record;
    bool cont_to_next = false;
    int sel_rcrd = 0;
    while (cont_to_next == false) {
      enc0.tick();
      if (enc0.left())
        sel_rcrd--;
      if (enc0.right())
        sel_rcrd++;
      if (sel_rcrd > (num_of_IDs - 1))
        sel_rcrd = 0;
      if (sel_rcrd < 0)
        sel_rcrd = num_of_IDs - 1;
      if (enc0.turn()) {
        selected_record = String(sel_rcrd);
        tft.fillScreen(0x0000);
        tft.setTextSize(2);
        tft.setTextColor(current_inact_clr);
        disp_centered_text("Edit Phone Number " + String(sel_rcrd + 1) + "/" + String(num_of_IDs), 10);
        tft.setTextColor(0xffff);
        clear_variables();
        exeq_sql_statement_from_string("SELECT Title FROM Phone_Numbers WHERE ID = '" + IDs[sel_rcrd] + "'");
        disp_centered_text(dec_st, 40);
        disp_button_designation();
      }
      delayMicroseconds(400);
      char chr;
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.x == 21)
          sel_rcrd++;
        if (data.x == 8)
          sel_rcrd--;

        if (sel_rcrd > (num_of_IDs - 1))
          sel_rcrd = 0;
        if (sel_rcrd < 0)
          sel_rcrd = num_of_IDs - 1;

        chr = data.x;
        selected_record = String(sel_rcrd);
        tft.fillScreen(0x0000);
        tft.setTextSize(2);
        tft.setTextColor(current_inact_clr);
        disp_centered_text("Edit Phone Number " + String(sel_rcrd + 1) + "/" + String(num_of_IDs), 10);
        tft.setTextColor(0xffff);
        clear_variables();
        exeq_sql_statement_from_string("SELECT Title FROM Phone_Numbers WHERE ID = '" + IDs[sel_rcrd] + "'");
        disp_centered_text(dec_st, 40);
        disp_button_designation();
      }
      delayMicroseconds(400);
      if (chr == 13 || chr == 131) {

        tft.fillScreen(0x0000);
        tft.setTextColor(current_inact_clr);
        tft.setTextSize(2);
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
          bus.tick();
          if (bus.gotData()) {
            myStruct data;
            bus.readData(data);
            if (data.x == 10)
              curr_key++;
            if (data.x == 11)
              curr_key--;

            if (curr_key < 0)
              curr_key = 1;

            if (curr_key > 1)
              curr_key = 0;

            if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
              Edit_phone_number_from_keyb_and_enc(IDs[selected_record.toInt()]);
              cont_to_next = true;
            }
            if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97)) {
              Edit_phone_number_from_Serial(IDs[selected_record.toInt()]);
              cont_to_next = true;
            }

            if (data.x == 10 || data.x == 11)
              input_source_for_data_in_flash_menu(curr_key);

            if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
              cont_to_next = true;
          }
        }

        call_main_menu();
        return;
      }
      if (chr == 27 || chr == 132) {
        call_main_menu();
        selected_record = "";
        return;
      }
    }

  } else {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Press any button", 30);
    disp_centered_text("to continue", 50);
    bool cont_to_next5 = false;
    while (cont_to_next5 == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next5 = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next5 = true;
      delay(1);
    }
    call_main_menu();
    return;
  }
}

void Edit_phone_number_from_keyb_and_enc(String selected_record) {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  set_stuff_for_input("Enter new Phone");
  encdr_and_keyb_input();
  if (act == true) {
    encrypt_with_TDES_AES_Blowfish_Serp(encoder_input);
    clb_m = 2;
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setTextSize(1);
    tft.setCursor(0, 0);
    tft.println("Setting new Phone Number");
    exeq_sql_statement_from_string("UPDATE Phone_Numbers set Phone = '" + dec_st + "' where ID = '" + selected_record + "';");
    rec_ID = selected_record;
    compute_tag_for_phone_number_without_disp();
    tft.setTextColor(0xffff);
    tft.fillRect(0, 230, 320, 10, 0x0000);
    disp_centered_text("Press any button to continue", 232);
    bool cont_to_next4 = false;
    while (cont_to_next4 == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next4 = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next4 = true;
      delay(1);
    }
  }
  clear_variables();
}

void Edit_phone_number_from_Serial(String selected_record) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setTextSize(2);
    disp_centered_text("Paste new Phone", 20);
    disp_centered_text("to the Serial Terminal", 40);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Press any button to cancel", 220);
    Serial.println("\nPaste new Phone here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
    String plt = Serial.readString();
    encrypt_with_TDES_AES_Blowfish_Serp(plt);
    exeq_sql_statement_from_string("UPDATE Phone_Numbers set Phone = '" + dec_st + "' where ID = '" + selected_record + "';");
    rec_ID = selected_record;
    compute_tag_for_phone_number_without_disp();
    cont_to_next = true;
    clear_variables();
    return;
  }
}

void Delete_phone_number() {
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Phone_Numbers");
  if (num_of_IDs != 0) {
    String IDs[num_of_IDs];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i < dec_st.length() - 1; i++) {
      if (dec_st.charAt(i) != '\n')
        IDs[c_id] += dec_st.charAt(i);
      else {
        c_id++;
      }
    }
    for (int i = 0; i < num_of_IDs; i++) {
      if (IDs[i].length() > 0)
        IDs[i].remove(IDs[i].length() - 1, 1);
    }
    clear_variables();
    clb_m = 2;
    decrypt_tag = false;
    tft.fillScreen(0x0000);
    tft.setTextSize(2);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Delete Phone Number 1/" + String(num_of_IDs), 10);
    tft.setTextColor(0xffff);
    clear_variables();
    exeq_sql_statement_from_string("SELECT Title FROM Phone_Numbers WHERE ID = '" + IDs[0] + "'");
    disp_centered_text(dec_st, 40);
    disp_button_designation_for_del();
    String selected_record;
    bool cont_to_next = false;
    int sel_rcrd = 0;
    while (cont_to_next == false) {
      enc0.tick();
      if (enc0.left())
        sel_rcrd--;
      if (enc0.right())
        sel_rcrd++;
      if (sel_rcrd > (num_of_IDs - 1))
        sel_rcrd = 0;
      if (sel_rcrd < 0)
        sel_rcrd = num_of_IDs - 1;
      if (enc0.turn()) {
        selected_record = String(sel_rcrd);
        tft.fillScreen(0x0000);
        tft.setTextColor(five_six_five_red_color);
        tft.setTextSize(2);
        disp_centered_text("Delete Phone Number " + String(sel_rcrd + 1) + "/" + String(num_of_IDs), 10);
        tft.setTextColor(0xffff);
        clear_variables();
        exeq_sql_statement_from_string("SELECT Title FROM Phone_Numbers WHERE ID = '" + IDs[sel_rcrd] + "'");
        disp_centered_text(dec_st, 40);
        disp_button_designation_for_del();
      }
      delayMicroseconds(400);
      char chr;
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.x == 21)
          sel_rcrd++;
        if (data.x == 8)
          sel_rcrd--;

        if (sel_rcrd > (num_of_IDs - 1))
          sel_rcrd = 0;
        if (sel_rcrd < 0)
          sel_rcrd = num_of_IDs - 1;

        chr = data.x;
        selected_record = String(sel_rcrd);
        tft.fillScreen(0x0000);
        tft.setTextColor(five_six_five_red_color);
        tft.setTextSize(2);
        disp_centered_text("Delete Phone Number " + String(sel_rcrd + 1) + "/" + String(num_of_IDs), 10);
        tft.setTextColor(0xffff);
        clear_variables();
        exeq_sql_statement_from_string("SELECT Title FROM Phone_Numbers WHERE ID = '" + IDs[sel_rcrd] + "'");
        disp_centered_text(dec_st, 40);
        disp_button_designation_for_del();
      }
      delayMicroseconds(400);
      if (chr == 13 || chr == 131) {
        clb_m = 1;
        /*
        Serial.println(IDs[selected_record.toInt()][0]);
        String tdel = "DELETE FROM Phone_Numbers WHERE ID = '";
        for (int i = 0; i < IDs[selected_record.toInt()][0].length(); i++){
          tdel += (IDs[selected_record.toInt()][0].charAt(i));
        }
        tdel += "'";
        exeq_sql_statement_from_string(tdel);
        */
        tft.fillScreen(0x0000);
        tft.setTextColor(0xffff);
        tft.setCursor(0, 0);
        exeq_sql_statement_from_string("DELETE FROM Phone_Numbers WHERE ID = '" + IDs[selected_record.toInt()] + "'");
        tft.setTextColor(0xffff);
        tft.fillRect(0, 230, 320, 10, 0x0000);
        disp_centered_text("Press any button to continue", 232);
        bool cont_to_next4 = false;
        while (cont_to_next4 == false) {
          bus.tick();
          if (bus.gotData())
            cont_to_next4 = true;
          delay(1);
          encoder_button.tick();
          if (encoder_button.press())
            cont_to_next4 = true;
          delay(1);
        }
        call_main_menu();
        return;
      }
      if (chr == 27 || chr == 132) {
        call_main_menu();
        selected_record = "";
        return;
      }
    }

  } else {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Press any button", 40);
    disp_centered_text("to continue", 60);
    bool cont_to_next5 = false;
    while (cont_to_next5 == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next5 = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next5 = true;
      delay(1);
    }
    call_main_menu();
    return;
  }
}

void View_phone_number() {
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Phone_Numbers");
  if (num_of_IDs != 0) {
    String IDs[num_of_IDs];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i < dec_st.length() - 1; i++) {
      if (dec_st.charAt(i) != '\n')
        IDs[c_id] += dec_st.charAt(i);
      else {
        c_id++;
      }
    }
    for (int i = 0; i < num_of_IDs; i++) {
      if (IDs[i].length() > 0)
        IDs[i].remove(IDs[i].length() - 1, 1);
    }
    clear_variables();
    tft.fillScreen(0x0000);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View Phone Number 1/" + String(num_of_IDs), 0);
    tft.fillRect(312, 0, 8, 240, current_inact_clr);
    tft.setTextColor(0xffff);
    clb_m = 2;
    decrypt_tag = false;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Title FROM Phone_Numbers WHERE ID = '" + IDs[0] + "'");
    String decrypted_title = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Phone FROM Phone_Numbers WHERE ID = '" + IDs[0] + "'");
    String decrypted_phone_number = dec_st;
    clear_variables();
    decrypt_tag = true;
    exeq_sql_statement_from_string("SELECT Tag FROM Phone_Numbers WHERE ID = '" + IDs[0] + "'");
    dec_st = decrypted_title + decrypted_phone_number;
    bool phone_number_integrity = verify_integrity();
    if (phone_number_integrity == false){
      tft.fillRect(312, 0, 8, 240, five_six_five_red_color);
      tft.setTextSize(1);
      tft.setTextColor(five_six_five_red_color);
      disp_centered_text("Integrity Verification Failed!!!", 232);
    }
    tft.setTextSize(2);
    tft.setCursor(0,16);
    tft.setTextColor(current_inact_clr);
    tft.print("Title:");
    if (phone_number_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_title);
    tft.setTextColor(current_inact_clr);
    tft.print("Phone:");
    if (phone_number_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_phone_number);
    String selected_record;
    bool cont_to_next = false;
    int sel_rcrd = 0;
    while (cont_to_next == false) {
      enc0.tick();
      if (enc0.left())
        sel_rcrd--;
      if (enc0.right())
        sel_rcrd++;
      if (sel_rcrd > (num_of_IDs - 1))
        sel_rcrd = 0;
      if (sel_rcrd < 0)
        sel_rcrd = num_of_IDs - 1;
      if (enc0.turn()) {
        selected_record = String(sel_rcrd);
        tft.fillScreen(0x0000);
        tft.setTextColor(current_inact_clr);
        disp_centered_text("View Phone Number " + String(sel_rcrd + 1) + "/" + String(num_of_IDs), 0);
        tft.fillRect(312, 0, 8, 240, current_inact_clr);
        tft.setTextColor(0xffff);
    clb_m = 2;
    decrypt_tag = false;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Title FROM Phone_Numbers WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_title = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Phone FROM Phone_Numbers WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_phone_number = dec_st;
    clear_variables();
    decrypt_tag = true;
    exeq_sql_statement_from_string("SELECT Tag FROM Phone_Numbers WHERE ID = '" + IDs[sel_rcrd] + "'");
    dec_st = decrypted_title + decrypted_phone_number;
    bool phone_number_integrity = verify_integrity();
    if (phone_number_integrity == false){
      tft.fillRect(312, 0, 8, 240, five_six_five_red_color);
      tft.setTextSize(1);
      tft.setTextColor(five_six_five_red_color);
      disp_centered_text("Integrity Verification Failed!!!", 232);
    }
    tft.setTextSize(2);
    tft.setCursor(0,16);
    tft.setTextColor(current_inact_clr);
    tft.print("Title:");
    if (phone_number_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_title);
    tft.setTextColor(current_inact_clr);
    tft.print("Phone:");
    if (phone_number_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_phone_number);
      }
      delayMicroseconds(400);
      char chr;
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.x == 21)
          sel_rcrd++;
        if (data.x == 8)
          sel_rcrd--;

        if (data.x != 21 && data.x != 8){
          selected_record = "";
          call_main_menu();
          return;
        }

        if (sel_rcrd > (num_of_IDs - 1))
          sel_rcrd = 0;
        if (sel_rcrd < 0)
          sel_rcrd = num_of_IDs - 1;

        chr = data.x;
        selected_record = String(sel_rcrd);
        tft.fillScreen(0x0000);
        tft.setTextColor(current_inact_clr);
        disp_centered_text("View Phone Number " + String(sel_rcrd + 1) + "/" + String(num_of_IDs), 0);
        tft.fillRect(312, 0, 8, 240, current_inact_clr);
        tft.setTextColor(0xffff);
    clb_m = 2;
    decrypt_tag = false;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Title FROM Phone_Numbers WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_title = dec_st;
    clear_variables();
    exeq_sql_statement_from_string("SELECT Phone FROM Phone_Numbers WHERE ID = '" + IDs[sel_rcrd] + "'");
    String decrypted_phone_number = dec_st;
    clear_variables();
    decrypt_tag = true;
    exeq_sql_statement_from_string("SELECT Tag FROM Phone_Numbers WHERE ID = '" + IDs[sel_rcrd] + "'");
    dec_st = decrypted_title + decrypted_phone_number;
    bool phone_number_integrity = verify_integrity();
    if (phone_number_integrity == false){
      tft.fillRect(312, 0, 8, 240, five_six_five_red_color);
      tft.setTextSize(1);
      tft.setTextColor(five_six_five_red_color);
      disp_centered_text("Integrity Verification Failed!!!", 232);
    }
    tft.setTextSize(2);
    tft.setCursor(0,16);
    tft.setTextColor(current_inact_clr);
    tft.print("Title:");
    if (phone_number_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_title);
    tft.setTextColor(current_inact_clr);
    tft.print("Phone:");
    if (phone_number_integrity == false){
      tft.setTextColor(five_six_five_red_color);
    }
    else{
      tft.setTextColor(0xffff);
    }
    tft.println(decrypted_phone_number);
      }
    }

  } else {
    tft.setTextSize(2);
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Press any button", 40);
    disp_centered_text("to continue", 60);
    bool cont_to_next5 = false;
    while (cont_to_next5 == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next5 = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next5 = true;
      delay(1);
    }
    call_main_menu();
    return;
  }
}

void delete_database_from_flash(){
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(five_six_five_red_color);
  disp_centered_text("Attention!!!", 10);
  tft.setTextColor(0xffff);
  disp_centered_text("If you delete the", 30);
  tft.setTextColor(0x07e0);
  disp_centered_text("\"Midbar.db\" file", 50);
  tft.setTextColor(0xffff);
  disp_centered_text("you lose all your", 70);
  disp_centered_text("data that's stored in", 90);
  disp_centered_text("the ESP32's flash.", 110);

  tft.setTextColor(0x1557);
  disp_centered_text("Are you sure you want", 180);
  disp_centered_text("to continue?", 200);
  tft.setTextSize(1);
  delay(5000);
  disp_button_designation_for_del();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);

      if (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97) {
        clb_m = 4;
        tft.fillScreen(0x0000);
        tft.setTextColor(0xffff);
        disp_centered_text("Deleting \"Midbar.db\"", 10);
        disp_centered_text("Please wait", 20);
        disp_centered_text("for a while", 30);
        SPIFFS.remove("/Midbar.db");
        delay(100);
        tft.fillScreen(0x0000);
        tft.setTextColor(0xffff);
        disp_centered_text("Recreating tables", 10);
        disp_centered_text("Please wait", 20);
        disp_centered_text("for a while", 30);
        create_logins_table();
        create_credit_cards_table();
        create_notes_table();
        create_phone_numbers_table();
        cont_to_next = true;
      }

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
        cont_to_next = true;
    }
  }
  clear_variables();
  call_main_menu();
  return;
}

// SQL (Above)

void Factory_Reset(){
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
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);

      if (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97) {
        clb_m = 4;
        tft.fillScreen(0x0000);
        tft.setTextSize(1);
        tft.setTextColor(0xffff);
        disp_centered_text("Deleting \"Midbar.db\"", 10);
        disp_centered_text("Please wait", 20);
        disp_centered_text("for a while", 30);
        SPIFFS.remove("/Midbar.db");
        delay(100);
        tft.fillScreen(0x0000);
        tft.setTextColor(0xffff);
        disp_centered_text("Recreating tables", 10);
        disp_centered_text("Please wait", 20);
        disp_centered_text("for a while", 30);
        create_logins_table();
        create_credit_cards_table();
        create_notes_table();
        create_phone_numbers_table();
        delay(100);
        tft.fillScreen(0x0000);
        tft.setTextColor(0xffff);
        disp_centered_text("Clearing EEPROM", 10);
        disp_centered_text("Please wait", 20);
        disp_centered_text("for a while", 30);
        EEPROM.begin(EEPROM_SIZE);
        for (int i = 0; i < EEPROM_SIZE; i++){
          EEPROM.write(i, 255);
        }
        EEPROM.end();
        delay(100);
        tft.fillScreen(0x0000);
        tft.setTextColor(0xffff);
        disp_centered_text("DONE!", 10);
        disp_centered_text("Please reboot", 30);
        disp_centered_text("the device", 40);
        delay(100);
        for (;;){
          
        }
        cont_to_next = true;
        }

      if (data.x == 132 || data.x == 27 || data.x == 66 || data.x == 98) // Get back
        cont_to_next = true;
    }
  }
  clear_variables();
  call_main_menu();
  return;
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

esp_now_peer_info_t peerInfo;

void OnDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
  Serial.print("\r\nLast Packet Send Status:\t");
  Serial.println(status == ESP_NOW_SEND_SUCCESS ? "Delivery Success" : "Delivery Fail");
}

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

void project_password_to_receiver(){
  if (send_setup == false)
    key_setup_for_send_feature();
  send_password();
}

void project_password_to_receiver_from_Serial(){
  if (send_setup == false)
    key_setup_for_send_feature();
  send_password_from_Serial();
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
    disp_centered_text("Press any button to continue", 232);
    bool cont_to_next5 = false;
    while (cont_to_next5 == false) {
      bus.tick();
      if (bus.gotData())
        cont_to_next5 = true;
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next5 = true;
      delay(1);
    }
}

void send_password() {
  n = false;
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Entr Password to send");
  encdr_and_keyb_input();
  if (act == true) {
    proj_pass(encoder_input);
  }
  clear_variables();
  call_main_menu();
  return;
}

void send_password_from_Serial() {
  n = false;
  bool cont_to_next = false;
  while (cont_to_next == false) {
    tft.fillScreen(0x0000);
    tft.setTextColor(0xffff);
    tft.setTextSize(1);
    disp_centered_text("Paste the password", 20);
    disp_centered_text("you'd like to send to", 30);
    disp_centered_text("the Serial Terminal", 40);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Press any button", 60);
    disp_centered_text("to cancel", 70);
    Serial.println("\nPaste the password you would like to send here:");
    bool canc_op = false;
    while (!Serial.available()) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        cont_to_next = true;
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
      if (cont_to_next == true) {
        canc_op = true;
        break;
      }
    }
    if (canc_op == true)
      break;
    String passtsd = Serial.readString();
    proj_pass(passtsd);
    cont_to_next = true;
    clear_variables();
    call_main_menu();
    return;
  }
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
    encoder_input = "";
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
  aes_set_key(&ctx, projection_key, key_bit[2]);
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

unsigned int k = 0;

void shift_letter_background(){
  for (int i = 0; i < 306; i++){
    for (int j = 0; j < 77; j++){
      if (mdb_icon[i][j] == 1)
        tft.drawPixel(i+7, j+87, conv_to_565_img[(i + 7 + k)%320][j+87]);
    }
  }
  k++;
}

void setup(void) {
  tft.begin();
  tft.setRotation(1);
  tft.fillScreen(0x0000);
  for (int i = 0; i < 320; i++){
    for (int j = 0; j < 240; j++){
      tft.drawPixel(i, j, conv_to_565_img[i][j]);
    }
  }
  delay(1000);
  m = 2; // Set AES to 256-bit mode
  clb_m = 4;
  send_setup = false;
  n = false;
  Serial.begin(115200);
  mySerial.begin(9600);
  if (SPIFFS.begin(true)) {} else {
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
  sqlite3_initialize();
  create_logins_table();
  create_credit_cards_table();
  create_notes_table();
  create_phone_numbers_table();
  for (int i = 0; i < 306; i++){
    for (int j = 0; j < 77; j++){
      if (mdb_per[i][j] == 1)
        tft.drawPixel(i+7, j+87, 0xf7de);
    }
  }
  // Set device as a Wi-Fi Station
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
  delay(1000);
  tft.setTextSize(2);
  tft.setTextColor(0xf7de);
  disp_centered_text("Hold Encoder Button", 205);
  bool cont_to_next = false;
  k = 0;
  while (cont_to_next == false) {
    shift_letter_background();
    
    encoder_button.tick();
    if (encoder_button.press())
      cont_to_next = true;

  }
  continue_to_unlock();
}

void loop() {
  enc0.tick();
  if (enc0.left())
    curr_key--;
  if (enc0.right())
    curr_key++;

  if (curr_key < 0)
    curr_key = 5;

  if (curr_key > 5)
    curr_key = 0;

  if (enc0.turn()) {
    main_menu(curr_key);
  }

  delayMicroseconds(500);
  bus.tick();

  if (bus.gotData()) {
    myStruct data;
    bus.readData(data);
    if (data.x == 10)
      curr_key++;
    if (data.x == 11)
      curr_key--;

    if (curr_key < 0)
      curr_key = 5;

    if (curr_key > 5)
      curr_key = 0;

    if (data.x == 10 || data.x == 11)
      main_menu(curr_key);

    if (curr_key == 0 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97))
      data_in_flash();

    if (curr_key == 1 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97))
      encryption_algorithms();

    if (curr_key == 2 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97))
      hash_functions();

    if (curr_key == 3 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97))
      sqlite3_menu();

    if (curr_key == 4 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97))
      password_projection_menu();

    if (curr_key == 5 && (data.x == 13 || data.x == 131 || data.x == 65 || data.x == 97))
      other_options();
  }
  delayMicroseconds(400);
}
