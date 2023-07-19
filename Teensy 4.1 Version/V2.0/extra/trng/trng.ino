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
https://github.com/adafruit/Adafruit_ILI9341
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/intrbiz/arduino-crypto
https://github.com/GyverLibs/EncButton
https://github.com/miguelbalboa/rfid
*/
// T4 TRNG from SDK, updated with imxrt.h symbols
// reading last entropy word, intiates a new generation cycle
// Taken from: https://github.com/manitou48/teensy4/blob/master/trng.ino

#define TRNG_ENT_COUNT 16

static uint32_t rng_index;

void trng_init() {
  CCM_CCGR6 |= CCM_CCGR6_TRNG(CCM_CCGR_ON);
  TRNG_MCTL = TRNG_MCTL_RST_DEF | TRNG_MCTL_PRGM; // reset to program mode
  TRNG_MCTL = TRNG_MCTL_SAMP_MODE(2); // start run mode, vonneumann
  TRNG_ENT15; // discard any stale data, start gen cycle
}

uint32_t trng_word() {
  uint32_t r;
  while ((TRNG_MCTL & TRNG_MCTL_ENT_VAL) == 0 &
         (TRNG_MCTL & TRNG_MCTL_ERR) == 0) ; // wait for entropy ready
  r = *(&TRNG_ENT0 + rng_index++);
  if (rng_index >= TRNG_ENT_COUNT) rng_index = 0;
  return r;
}


void setup() {
  Serial.begin(9600);
  while (!Serial);
  delay(2000);
  trng_init();
  //PRREG(TRNG_STATUS);
  //PRREG(TRNG_MCTL);
  //uint32_t * p = (uint32_t *) &TRNG_MCTL;
  //for (int i = 0; i < 16; i++) Serial.printf("%d %08X\n", i, p[i]);

  //logger();  // log to serial
  //words();  // timing test
}

void loop() {
  /*
  uint32_t t1, t2, t3, edata[4096];
  uint32_t data[16];   // 512 random bits

  t1 = micros();
  trng512(data);
  t1 = micros() - t1;
  t2 = micros();
  trng512(data);
  t2 = micros() - t2;
  t3 = micros();
  trng512(data);
  t3 = micros() - t3;
  Serial.printf("%d us  %d us  %d us   %0x\n", t1, t2, t3, data[3]);
  // collect lots of data for entropy calculation
  for (int i = 0; i < sizeof(edata) / 4; i += TRNG_ENT_COUNT) trng512(edata + i);
  //  for (int i = 0; i < sizeof(edata) / 4; i++)edata[i] = random();
  entropy(edata, sizeof(edata));

  delay(2000);
  */
  Serial.println(trng_word() % 256);
 }
