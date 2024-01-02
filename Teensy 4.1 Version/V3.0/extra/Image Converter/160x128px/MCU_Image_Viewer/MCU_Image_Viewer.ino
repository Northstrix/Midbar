#include <Adafruit_GFX.h>
#include <Adafruit_ST7735.h>
#define TFT_CS1    39                                                        // TFT CS  pin is connected to Teensy pin 39
#define TFT_RST1   40                                                        // TFT RST pin is connected to Teensy pin 40
#define TFT_DC1    41                                                        // TFT DC  pin is connected to Teensy pin 41
                                                                            // SCK (CLK) ---> Teensy pin 13
                                                                            // MOSI(DIN) ---> Teensy pin 11D4
Adafruit_ST7735 tft = Adafruit_ST7735(TFT_CS1, TFT_DC1, TFT_RST1);

#define DISPLAY_WIDTH 160
#define DISPLAY_HEIGHT 128

int i, j;

uint16_t packColor(byte r, byte g, byte b) {
    // Pack RGB components into 16-bit color (565 format)
    uint16_t color16bit = ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3);
    return color16bit;
}

void setup(void)
{
  tft.initR(INITR_BLACKTAB);
  tft.setRotation(1);
  tft.fillScreen(0x0000);
  Serial.begin(115200);
  i = 0;
  j = 0;
}

void loop() {
  if (Serial.available() >= 3) {
    // Read the RGB values of each pixel
    while (Serial.available() >= 3) {
      byte r = Serial.read();
      byte g = Serial.read();
      byte b = Serial.read();
      tft.drawPixel(i, j, packColor(r, g, b));
      i++;
      if (i == DISPLAY_WIDTH){
        i = 0;
        j++;
      }
      if (j == DISPLAY_HEIGHT){
        i = 0;
        j = 0; 
      }
    }
  }
}
