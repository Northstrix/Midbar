Advancements in cryptanalysis and hacking techniques are constantly reducing the cost of accessing your data without your authorization, making it easier and more attractive for different sides to get it.

I'm not going to get into details about the motivation of each side and the goals they're trying to achieve by obtaining your data. Instead, I would like to focus on the solution to that problem.

In my opinion, the only way to keep your data private is to raise the cost of unauthorized access to it as high as possible. Ideally - raise it so high that it would significantly outweigh any potential reward for the third party.

To raise the cost of unauthorized access to your data - I've developed Midbar.

Midbar is a hardware password vault. Unlike hardware authentication devices, it can store your login credentials, credit card information, notes, and phone numbers. Midbar encrypts your data and requires a master password and, in some cases, four additional RFID cards to access it. With Midbar, you don't have to worry about memorizing the login credentials and credit card information for the services you use. It does that for you.

Compared to software vaults, Midbar provides more security because it does not have thousands of other processes running alongside it, significantly contributing to making it almost invulnerable to side-channel attacks. Additionally, Midbar utilizes sophisticated integrity verification and superencryption features.

The integrity verification feature ensures that any corruption or unauthorized modification of your data will not go unnoticed. Superencryption is a safeguard that would be useful in case a highly improbable black swan event renders one of the major encryption algorithms (AES or Serpent) insecure. Even after such an event, your data would still be encrypted with one secure and two "somewhat semi-secure" encryption algorithms, providing an extra layer of protection.

</br></br></br>

ESP8266 version of Midbar utilizes the 3DES + AES + Blowfish + Serpent encryption algorithm alongside the ESP8266's built-in memory to store eight passwords and four credit cards in the encrypted form. It also utilizes the HMAC SHA-256 to verify the integrity of the stored logins, which means that if at least one bit of an encrypted login gets flipped, Midbar will inform you about it by displaying the following alert: "Integrity Verification Failed!!!"

Midbar V2.0 & V2.5 (ESP32 version) is a password vault, credit card vault, note vault, phone number vault, data encrypter/decrypter, data hasher, SQLite3 host, and one-way secure communication channel - all in one!
When it comes to the vault capability - Midbar V2.0 utilizes the 3DES + AES + Blowfish + Serpent encryption algorithm with an integrity verification feature alongside the SQLite3 serverless embedded relational database management system to keep your data safe and organized.

Midbar V1.0 (Raspberry Pi Pico Version) is a password vault, credit card vault, note vault, phone number vault, and data encrypter/decrypter - all in one. It utilizes the 3DES + AES + Blowfish + Serpent encryption algorithm in CBC mode with an integrity verification feature alongside the LittleFS to keep your data safe and organized.

Midbar V4.0 is an attempt to combine the best aspects of Midbar and Cipherbox.

Midbar (Raspberry Pi Pico Version) V2.0 is the Raspberry Pi Pico version of the Midbar V4.0.

Midbar V5.0 is the first version of Midbar that stores user data on an external SD card.

Midbar (STM32F401CCU6 Version) is the STM32F401CCU6 version of the Midbar V5.0.

Midbar (STM32F401CCU6 + Arduino Uno Version) is an attempt to combine the best aspects of Midbar V4.0 and Midbar V5.0 while eliminating the RNG problem present in the Midbar (STM32F401CCU6 Version).

Midbar (Teensy 4.1 Version) is the Teensy 4.1 version of the Midbar V5.0 that supports the USB keyboard.

Midbar (Teensy 4.1 Version) V2.0 is the first version of Midbar that can function as a USB keyboard.

Midbar (RTL8720DN Version) is a bit odd, but still a fully functional version of Midbar.

Midbar (RTL8720DN + Arduino Uno Version) is the first version of Midbar that can handle the Nintendo 64 controller.

Midbar (ESP8266 Version) V2.0 is the first version of Midbar that can handle the Nintendo Wii Nunchuk.

Midbar (STM32F407VET6 Version) is the first version of Midbar that can simultaneously handle the PS2 Keyboard and the Nintendo 64 Controller.

Midbar (STM32F407VET6 + Arduino Uno Version) is an RFID-lockable version of Midbar (STM32F407VET6 Version).

The purpose of Midbar is to significantly increase the cost of unauthorized access to its user's personal data.

You can find the tutorial for Midbar here:
</br>
ESP32 Version: https://www.instructables.com/Project-Midbar/
</br>
ESP8266 Version: https://www.instructables.com/Midbar-ESP8266-Version/
</br>
ESP32 Version 2.0: https://www.instructables.com/Midbar-V20/
</br>
ESP32 Version 2.5: https://www.instructables.com/Midbar-V25/
</br>
Raspberry Pi Pico V1.0: https://www.instructables.com/Midbar-Raspberry-Pi-Pico-Version/
</br>
ESP32 Version 3.0: https://www.instructables.com/Midbar-V30/
</br>
ESP32 Version 4.0: https://www.instructables.com/Midbar-V40/
</br>
Raspberry Pi Pico Version V2.0: https://www.instructables.com/Midbar-Raspberry-Pi-Pico-Version-V20/
</br>
ESP32 Version 5.0: https://www.instructables.com/Midbar-V50/
</br>
STM32F401CCU6 Version V1.0: https://www.instructables.com/Midbar-STM32F401CCU6-Version/
</br>
STM32F401CCU6 + Arduino Uno Version V1.0: https://www.instructables.com/Midbar-STM32F401CCU6-Arduino-Uno-Version/
</br>
Teensy 4.1 Version: https://www.instructables.com/Midbar-Teensy-41-Version/
</br>
Teensy 4.1 Version V2.0: https://www.instructables.com/Midbar-Teensy-41-Version-V20/
</br>
RTL8720DN Version: https://www.instructables.com/Midbar-RTL8720DN-Version/
</br>
RTL8720DN + Arduino Uno Version: https://www.instructables.com/Midbar-RTL8720DN-Arduino-Uno-Version/
</br>
ESP8266 Version V2.0: https://www.instructables.com/Midbar-ESP8266-Version-V20/
</br>
STM32F407VET6 Version: https://www.instructables.com/Midbar-STM32F407VET6-Version/
</br>
STM32F407VET6 + Arduino Uno Version V1.0: https://www.instructables.com/Midbar-STM32F407VET6-Arduino-Uno-Version/
</br></br>
![image text](https://github.com/Northstrix/Midbar/blob/main/STM32F407VET6_and_Arduino_Uno_Version/V1.0/Pictures/IMG_20230915_165315_hdr.jpg)
![image text](https://github.com/Northstrix/Midbar/blob/main/STM32F407VET6_and_Arduino_Uno_Version/V1.0/Pictures/Midbar%20Circuit%20Diagram.png)
![image text](https://github.com/Northstrix/Midbar/blob/main/STM32F407VET6%20Version/V1.0/Pictures/IMG_20230908_172638.jpg)
![image text](https://github.com/Northstrix/Midbar/blob/main/STM32F407VET6%20Version/V1.0/Pictures/Midbar%20Circuit%20Diagram.png)
![image text](https://github.com/Northstrix/Midbar/blob/main/ESP8266%20Version/V2.0/Pictures/IMG_20230830_133315.jpg)
![image text](https://github.com/Northstrix/Midbar/blob/main/ESP8266%20Version/V2.0/Pictures/Midbar%20Circuit%20Diagram.png)
![image text](https://github.com/Northstrix/Midbar/blob/main/RTL8720DN_and_Arduino_Uno_Version/V1.0/Pictures/IMG_20230821_174708.jpg)
![image text](https://github.com/Northstrix/Midbar/blob/main/RTL8720DN_and_Arduino_Uno_Version/V1.0/Pictures/Midbar%20Circuit%20Diagram.png)
![image text](https://github.com/Northstrix/Midbar/blob/main/RTL8720DN%20Version/V1.0/Pictures/IMG_20230801_161613_hdr.jpg)
![image text](https://github.com/Northstrix/Midbar/blob/main/RTL8720DN%20Version/V1.0/Pictures/Midbar%20Circuit%20Diagram.png)
![image text](https://github.com/Northstrix/Midbar/blob/main/Teensy%204.1%20Version/V2.0/Pictures/IMG_20230719_184125.jpg)
![image text](https://github.com/Northstrix/Midbar/blob/main/Teensy%204.1%20Version/V2.0/Pictures/Midbar%20Circuit%20Diagram.png)
![image text](https://github.com/Northstrix/Midbar/blob/main/Teensy%204.1%20Version/V1.0/Pictures/IMG_20230626_161557.jpg)
![image text](https://github.com/Northstrix/Midbar/blob/main/Teensy%204.1%20Version/V1.0/Pictures/Midbar%20Circuit%20Diagram.png)
![image text](https://github.com/Northstrix/Midbar/blob/main/STM32F401CCU6_and_Arduino_Uno_Version/V1.0/Pictures/IMG_20230504_145722.jpg)
![image text](https://github.com/Northstrix/Midbar/blob/main/STM32F401CCU6_and_Arduino_Uno_Version/V1.0/Pictures/Midbar%20Circuit%20Diagram.png)
![image text](https://github.com/Northstrix/Midbar/blob/main/STM32F401CCU6_Version/V1.0/Pictures/IMG_20230414_141811.jpg)
![image text](https://github.com/Northstrix/Midbar/blob/main/STM32F401CCU6_Version/V1.0/Pictures/Midbar%20Circuit%20Diagram.png)
![image text](https://github.com/Northstrix/Midbar/blob/main/ESP32_Version/V5.0/Pictures/IMG_20230409_141054.jpg)
![image text](https://github.com/Northstrix/Midbar/blob/main/ESP32_Version/V5.0/Pictures/Vault%20Circuit%20Diagram.png)
![image text](https://github.com/Northstrix/Midbar/blob/main/Raspberry_Pi_Pico_Version/V2.0/Pictures/IMG_20230324_151103.jpg)
![image text](https://github.com/Northstrix/Midbar/blob/main/Raspberry_Pi_Pico_Version/V2.0/Pictures/Midbar%20Circuit%20Diagram.png)
![image text](https://github.com/Northstrix/Midbar/blob/main/ESP32_Version/V4.0/Pictures/IMG_20230208_154744.jpg)
![image text](https://github.com/Northstrix/Midbar/blob/main/ESP32_Version/V4.0/Pictures/Vault%20Circuit%20Diagram.png)
![image text](https://github.com/Northstrix/Midbar/blob/main/ESP32_Version/V4.0/Pictures/Receiver%20Circuit%20Diagram.png)
![image text](https://github.com/Northstrix/Midbar/blob/main/ESP32_Version/V3.0/Pictures/IMG_20230121_112045_hdr.jpg)
![image text](https://github.com/Northstrix/Midbar/blob/main/ESP32_Version/V3.0/Pictures/Vault%20Circuit%20Diagram.png)
![image text](https://github.com/Northstrix/Midbar/blob/main/Raspberry_Pi_Pico_Version/V1.0/Pictures/IMG_20230111_112857_hdr.jpg)
![image text](https://github.com/Northstrix/Midbar/blob/main/Raspberry_Pi_Pico_Version/V1.0/Pictures/Midbar%20Circuit%20Diagram.png)
![image text](https://github.com/Northstrix/Midbar/blob/main/ESP32_Version/V2.5/Pictures/IMG_20230101_145716_hdr_edit.jpg)
![image text](https://github.com/Northstrix/Midbar/blob/main/ESP32_Version/V2.5/Pictures/IMG_20230101_170120.jpg)
![image text](https://github.com/Northstrix/Midbar/blob/main/ESP32_Version/V2.5/Pictures/IMG_20230101_171912.jpg)
![image text](https://github.com/Northstrix/Midbar/blob/main/ESP32_Version/V2.5/Pictures/Vault%20Circuit%20Diagram.png)
![image text](https://github.com/Northstrix/Midbar/blob/main/ESP32_Version/V2.0/Photos/IMG_20221217_134728.jpg)
![image text](https://github.com/Northstrix/Midbar/blob/main/ESP32_Version/V2.0/Photos/IMG_20221217_130321.jpg)
![image text](https://github.com/Northstrix/Midbar/blob/main/ESP32_Version/V2.0/Vault%20Circuit%20Diagram.png)
![image text](https://github.com/Northstrix/Midbar/blob/main/ESP32_Version/V2.0/Receiver%20Circuit%20Diagram.jpg)
![image text](https://github.com/Northstrix/Midbar/blob/main/ESP8266%20Version/V1.0/Pictures/IMG_20221126_120541.jpg)
![image text](https://github.com/Northstrix/Midbar/blob/main/ESP8266%20Version/V1.0/Pictures/IMG_20221126_121830.jpg)
![image text](https://github.com/Northstrix/Midbar/blob/main/ESP8266%20Version/V1.0/Pictures/IMG_20221126_121950.jpg)
![image text](https://github.com/Northstrix/Midbar/blob/main/ESP8266%20Version/V1.0/Pictures/IMG_20221126_122431.jpg)
![image text](https://github.com/Northstrix/Midbar/blob/main/ESP8266%20Version/V1.0/Pictures/Circuit%20Diagram.png)
![image text](https://github.com/Northstrix/Midbar/blob/main/ESP32_Version/V1.0/Pictures/IMG_20220501_120358.jpg)
