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
/*
Serpent_in_CBC_mode_for_microcontrollers
Based on the work of https://github.com/peterferrie/serpent
Parts of the code are distributed under the MIT License
© Copyright Maxim Bortnikov 2023
For more information please visit
https://github.com/Northstrix/Serpent_in_CBC_mode_for_microcontrollers/tree/master
https://sourceforge.net/projects/serpent-in-cbc-mode-for-mcus/
*/
#include "serpent.h"
#include "Crypto.h"

String dec_st;
String dec_tag;
byte tmp_st[8];
int decract;
char array_for_CBC_mode[16];

byte custm_key_hmack_key[32];
uint8_t custom_serp_in_cbc_key[32];

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

void clear_variables() {
  dec_tag = "";
  dec_st = "";
  decract = 0;
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

void decrypt_string_with_serpent_in_cbc(String ct) { // Function for decryption. Takes ciphertext as an input.

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

void encrypt_serpent_from_Serial() {
  set_key();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    Serial.println("\nPaste the string you want to encrypt here:");
    while (!Serial.available()) {
    }
    String plt = Serial.readString();
    int iv[16]; // Initialization vector
    for (int i = 0; i < 16; i++){
      iv[i] = random(256); // Fill iv array with random numbers. I suggest you use a more secure method of random number generation!!!
    }
    encrypt_string_with_serpent_in_cbc(plt, iv); // Function for encryption. Takes the plaintext and iv as the input.
    Serial.println("\nCiphertext");
    Serial.println(dec_st);
    clear_variables();
    return;
  }
}

void decrypt_serpent_from_Serial() {
  set_key();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    Serial.println("\nPaste the ciphertext here:");
    while (!Serial.available()) {
    }
    String ct = Serial.readString();
    decrypt_string_with_serpent_in_cbc(ct);
    Serial.println("Plaintext:");
    Serial.println(dec_st);
    Serial.println("Tag:");
    Serial.println(dec_tag);
    bool plt_integr = verify_integrity_32bytes();
    if (plt_integr == true)
      Serial.println("Integrity verified successfully!");
    else
      Serial.println("Integrity Verification failed!!!");
    clear_variables();
    return;
  }
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

void set_key(){
  byte enckey[64] = {'0'};
  for (int i = 0; i < 32; i++){
    custm_key_hmack_key[i] = enckey[i];
    custom_serp_in_cbc_key[i] = uint8_t(enckey[i + 32]);
  }
}

void setup() {
  Serial.begin(115200);
}

void loop() {
  Serial.println();
  Serial.println("What do you want to do?");
  Serial.println("1.Encrypt text in CBC Mode");
  Serial.println("2.Decrypt text in CBC Mode");
  while (!Serial.available()) {}
  int x = Serial.parseInt();
  if (x == 1) {
    encrypt_serpent_from_Serial();
  }
  if (x == 2){
    decrypt_serpent_from_Serial();
  }
}
