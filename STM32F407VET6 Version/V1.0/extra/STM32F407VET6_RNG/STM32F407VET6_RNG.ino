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
https://github.com/adafruit/Adafruit_ILI9341
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/intrbiz/arduino-crypto
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/techpaul/PS2KeyMap
https://github.com/pothos/arduino-n64-controller-library
https://github.com/ulwanski/sha512
*/
// https://www.stm32duino.com/viewtopic.php?t=2108
#include "hal_conf_extra.h" 

RNG_HandleTypeDef hrng;

/**
* @brief RNG MSP Initialization
* This function configures the hardware resources used in this example
* @param hrng: RNG handle pointer
* @retval None
*/
extern "C" void HAL_RNG_MspInit(RNG_HandleTypeDef* hrng) {
  /* Peripheral clock enable */
  __HAL_RCC_RNG_CLK_ENABLE();
}

/**
* @brief RNG MSP De-Initialization
* This function freeze the hardware resources used in this example
* @param hrng: RNG handle pointer
* @retval None
*/
extern "C" void HAL_RNG_MspDeInit(RNG_HandleTypeDef* hrng) {
  if (hrng->Instance == RNG) {
    /* Peripheral clock disable */
    __HAL_RCC_RNG_CLK_DISABLE();

    /* Enable RNG reset state */
    __HAL_RCC_RNG_FORCE_RESET();

    /* Release RNG from reset state */
    __HAL_RCC_RNG_RELEASE_RESET();
  }
}

void setup() {
  Serial.begin(115200);
  hrng.Instance = RNG;
  if (HAL_RNG_Init(&hrng) != HAL_OK) {
    Error_Handler();
  }
}

void loop() {
  uint32_t aRandom32bit;
  if (HAL_RNG_GenerateRandomNumber(&hrng, &aRandom32bit) != HAL_OK) {
    /* Random number generation error */
    Error_Handler();
  } else {
    Serial.println(aRandom32bit);
  }
  delay(1000);
}
