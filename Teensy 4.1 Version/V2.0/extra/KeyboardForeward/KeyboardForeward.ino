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
// Simple USB Keyboard Forwarder
//
// This example is in the public domain

#include "USBHost_t36.h"

// You can have this one only output to the USB type Keyboard and
// not show the keyboard data on Serial...
#define SHOW_KEYBOARD_DATA

USBHost myusb;
USBHub hub1(myusb);
KeyboardController keyboard1(myusb);
//BluetoothController bluet(myusb, true, "0000");   // Version does pairing to device
BluetoothController bluet(myusb);   // version assumes it already was paired

USBHIDParser hid1(myusb);
USBHIDParser hid2(myusb);
USBHIDParser hid3(myusb);

uint8_t keyboard_modifiers = 0;  // try to keep a reasonable value
#ifdef KEYBOARD_INTERFACE
uint8_t keyboard_last_leds = 0;
#elif !defined(SHOW_KEYBOARD_DATA)
#Warning: "USB type does not have Serial, so turning on SHOW_KEYBOARD_DATA"
#define SHOW_KEYBOARD_DATA
#endif

void setup()
{
#ifdef SHOW_KEYBOARD_DATA
	while (!Serial) ; // wait for Arduino Serial Monitor
	Serial.println("\n\nUSB Host Keyboard forward and Testing");
	Serial.println(sizeof(USBHub), DEC);
#endif
	myusb.begin();

	// Only needed to display...
#ifdef SHOW_KEYBOARD_DATA
	keyboard1.attachPress(OnPress);
#endif
	keyboard1.attachRawPress(OnRawPress);
	keyboard1.attachRawRelease(OnRawRelease);
	keyboard1.attachExtrasPress(OnHIDExtrasPress);
	keyboard1.attachExtrasRelease(OnHIDExtrasRelease);
}


void loop()
{
	myusb.Task();
	ShowUpdatedDeviceListInfo();
}


void OnHIDExtrasPress(uint32_t top, uint16_t key)
{
#ifdef KEYBOARD_INTERFACE
	if (top == 0xc0000) {
		Keyboard.press(0XE400 | key);
#ifndef KEYMEDIA_INTERFACE
#error "KEYMEDIA_INTERFACE is Not defined"
#endif
	}
#endif
#ifdef SHOW_KEYBOARD_DATA
	ShowHIDExtrasPress(top, key);
#endif
}

void OnHIDExtrasRelease(uint32_t top, uint16_t key)
{
#ifdef KEYBOARD_INTERFACE
	if (top == 0xc0000) {
		Keyboard.release(0XE400 | key);
	}
#endif
#ifdef SHOW_KEYBOARD_DATA
	Serial.print("HID (");
	Serial.print(top, HEX);
	Serial.print(") key release:");
	Serial.println(key, HEX);
#endif
}

void OnRawPress(uint8_t keycode) {
#ifdef KEYBOARD_INTERFACE
	if (keyboard_leds != keyboard_last_leds) {
		//Serial.printf("New LEDS: %x\n", keyboard_leds);
		keyboard_last_leds = keyboard_leds;
		keyboard1.LEDS(keyboard_leds);
	}
	if (keycode >= 103 && keycode < 111) {
		// one of the modifier keys was pressed, so lets turn it
		// on global..
		uint8_t keybit = 1 << (keycode - 103);
		keyboard_modifiers |= keybit;
		Keyboard.set_modifier(keyboard_modifiers);
	} else {
		if (keyboard1.getModifiers() != keyboard_modifiers) {
#ifdef SHOW_KEYBOARD_DATA
			Serial.printf("Mods mismatch: %x != %x\n", keyboard_modifiers, keyboard1.getModifiers());
#endif
			keyboard_modifiers = keyboard1.getModifiers();
			Keyboard.set_modifier(keyboard_modifiers);
		}
		Keyboard.press(0XF000 | keycode);
	}
#endif
#ifdef SHOW_KEYBOARD_DATA
	Serial.print("OnRawPress keycode: ");
	Serial.print(keycode, HEX);
	Serial.print(" Modifiers: ");
	Serial.println(keyboard_modifiers, HEX);
#endif
}
void OnRawRelease(uint8_t keycode) {
#ifdef KEYBOARD_INTERFACE
	if (keycode >= 103 && keycode < 111) {
		// one of the modifier keys was pressed, so lets turn it
		// on global..
		uint8_t keybit = 1 << (keycode - 103);
		keyboard_modifiers &= ~keybit;
		Keyboard.set_modifier(keyboard_modifiers);
	} else {
		Keyboard.release(0XF000 | keycode);
	}
#endif
#ifdef SHOW_KEYBOARD_DATA
	Serial.print("OnRawRelease keycode: ");
	Serial.print(keycode, HEX);
	Serial.print(" Modifiers: ");
	Serial.println(keyboard1.getModifiers(), HEX);
#endif
}

//=============================================================
// Device and Keyboard Output To Serial objects...
//=============================================================
#ifdef SHOW_KEYBOARD_DATA
USBDriver *drivers[] = {&hub1, &hid1, &hid2, &hid3, &bluet};
#define CNT_DEVICES (sizeof(drivers)/sizeof(drivers[0]))
const char * driver_names[CNT_DEVICES] = {"Hub1", "HID1" , "HID2", "HID3", "BlueTooth"};
bool driver_active[CNT_DEVICES] = {false, false, false};

// Lets also look at HID Input devices
USBHIDInput *hiddrivers[] = { &keyboard1 };
#define CNT_HIDDEVICES (sizeof(hiddrivers) / sizeof(hiddrivers[0]))
const char *hid_driver_names[CNT_DEVICES] = { "KB" };
bool hid_driver_active[CNT_DEVICES] = { false };

BTHIDInput *bthiddrivers[] = {&keyboard1};
#define CNT_BTHIDDEVICES (sizeof(bthiddrivers)/sizeof(bthiddrivers[0]))
const char * bthid_driver_names[CNT_HIDDEVICES] = {"KB(BT)"};
bool bthid_driver_active[CNT_HIDDEVICES] = {false};


#endif

void ShowUpdatedDeviceListInfo()
{
#ifdef SHOW_KEYBOARD_DATA
	for (uint8_t i = 0; i < CNT_DEVICES; i++) {
		if (*drivers[i] != driver_active[i]) {
			if (driver_active[i]) {
				Serial.printf("*** Device %s - disconnected ***\n", driver_names[i]);
				driver_active[i] = false;
			} else {
				Serial.printf("*** Device %s %x:%x - connected ***\n", driver_names[i], drivers[i]->idVendor(), drivers[i]->idProduct());
				driver_active[i] = true;

				const uint8_t *psz = drivers[i]->manufacturer();
				if (psz && *psz) Serial.printf("  manufacturer: %s\n", psz);
				psz = drivers[i]->product();
				if (psz && *psz) Serial.printf("  product: %s\n", psz);
				psz = drivers[i]->serialNumber();
				if (psz && *psz) Serial.printf("  Serial: %s\n", psz);

			}
		}
	}
	for (uint8_t i = 0; i < CNT_HIDDEVICES; i++) {
		if (*hiddrivers[i] != hid_driver_active[i]) {
			if (hid_driver_active[i]) {
				Serial.printf("*** HID Device %s - disconnected ***\n", hid_driver_names[i]);
				hid_driver_active[i] = false;
			} else {
				Serial.printf("*** HID Device %s %x:%x - connected ***\n", hid_driver_names[i], hiddrivers[i]->idVendor(), hiddrivers[i]->idProduct());
				hid_driver_active[i] = true;

				const uint8_t *psz = hiddrivers[i]->manufacturer();
				if (psz && *psz) Serial.printf("  manufacturer: %s\n", psz);
				psz = hiddrivers[i]->product();
				if (psz && *psz) Serial.printf("  product: %s\n", psz);
				psz = hiddrivers[i]->serialNumber();
				if (psz && *psz) Serial.printf("  Serial: %s\n", psz);
				// Note: with some keyboards there is an issue that they may not output in a format understand
				// either as in boot format or in a HID format that is recognized.  In that case you
				// can try forcing the keyboard into boot mode.
				if (hiddrivers[i] == &keyboard1) {
					// example Gigabyte uses N key rollover which should now work, but...
				}
			}
		}
	}
	for (uint8_t i = 0; i < CNT_BTHIDDEVICES; i++) {
		if (*bthiddrivers[i] != bthid_driver_active[i]) {
			if (bthid_driver_active[i]) {
				Serial.printf("*** BTHID Device %s - disconnected ***\n", bthid_driver_names[i]);
				bthid_driver_active[i] = false;
			} else {
				Serial.printf("*** BTHID Device %s %x:%x - connected ***\n", bthid_driver_names[i], bthiddrivers[i]->idVendor(), bthiddrivers[i]->idProduct());
				bthid_driver_active[i] = true;
				const uint8_t *psz = bthiddrivers[i]->manufacturer();
				if (psz && *psz) Serial.printf("  manufacturer: %s\n", psz);
				psz = bthiddrivers[i]->product();
				if (psz && *psz) Serial.printf("  product: %s\n", psz);
				psz = bthiddrivers[i]->serialNumber();
				if (psz && *psz) Serial.printf("  Serial: %s\n", psz);
				if (bthiddrivers[i] == &keyboard1) {
					// try force back to HID mode
					Serial.println("\n Try to force keyboard back into HID protocol");
					keyboard1.forceHIDProtocol();
				}
			}
		}
	}

#endif
}

#ifdef SHOW_KEYBOARD_DATA
void OnPress(int key)
{
	Serial.print("key '");
	switch (key) {
	case KEYD_UP       : Serial.print("UP"); break;
	case KEYD_DOWN    : Serial.print("DN"); break;
	case KEYD_LEFT     : Serial.print("LEFT"); break;
	case KEYD_RIGHT   : Serial.print("RIGHT"); break;
	case KEYD_INSERT   : Serial.print("Ins"); break;
	case KEYD_DELETE   : Serial.print("Del"); break;
	case KEYD_PAGE_UP  : Serial.print("PUP"); break;
	case KEYD_PAGE_DOWN: Serial.print("PDN"); break;
	case KEYD_HOME     : Serial.print("HOME"); break;
	case KEYD_END      : Serial.print("END"); break;
	case KEYD_F1       : Serial.print("F1"); break;
	case KEYD_F2       : Serial.print("F2"); break;
	case KEYD_F3       : Serial.print("F3"); break;
	case KEYD_F4       : Serial.print("F4"); break;
	case KEYD_F5       : Serial.print("F5"); break;
	case KEYD_F6       : Serial.print("F6"); break;
	case KEYD_F7       : Serial.print("F7"); break;
	case KEYD_F8       : Serial.print("F8"); break;
	case KEYD_F9       : Serial.print("F9"); break;
	case KEYD_F10      : Serial.print("F10"); break;
	case KEYD_F11      : Serial.print("F11"); break;
	case KEYD_F12      : Serial.print("F12"); break;
	default: Serial.print((char)key); break;
	}
	Serial.print("'  ");
	Serial.print(key);
	Serial.print(" MOD: ");
	Serial.print(keyboard1.getModifiers(), HEX);
	Serial.print(" OEM: ");
	Serial.print(keyboard1.getOemKey(), HEX);
	Serial.print(" LEDS: ");
	Serial.println(keyboard1.LEDS(), HEX);
	//Serial.print("key ");
	//Serial.print((char)keyboard1.getKey());
	//Serial.print("  ");
	//Serial.print((char)keyboard2.getKey());
	//Serial.println();
}
#endif

void ShowHIDExtrasPress(uint32_t top, uint16_t key)
{
#ifdef SHOW_KEYBOARD_DATA
	Serial.print("HID (");
	Serial.print(top, HEX);
	Serial.print(") key press:");
	Serial.print(key, HEX);
	if (top == 0xc0000) {
		switch (key) {
		case  0x20 : Serial.print(" - +10"); break;
		case  0x21 : Serial.print(" - +100"); break;
		case  0x22 : Serial.print(" - AM/PM"); break;
		case  0x30 : Serial.print(" - Power"); break;
		case  0x31 : Serial.print(" - Reset"); break;
		case  0x32 : Serial.print(" - Sleep"); break;
		case  0x33 : Serial.print(" - Sleep After"); break;
		case  0x34 : Serial.print(" - Sleep Mode"); break;
		case  0x35 : Serial.print(" - Illumination"); break;
		case  0x36 : Serial.print(" - Function Buttons"); break;
		case  0x40 : Serial.print(" - Menu"); break;
		case  0x41 : Serial.print(" - Menu  Pick"); break;
		case  0x42 : Serial.print(" - Menu Up"); break;
		case  0x43 : Serial.print(" - Menu Down"); break;
		case  0x44 : Serial.print(" - Menu Left"); break;
		case  0x45 : Serial.print(" - Menu Right"); break;
		case  0x46 : Serial.print(" - Menu Escape"); break;
		case  0x47 : Serial.print(" - Menu Value Increase"); break;
		case  0x48 : Serial.print(" - Menu Value Decrease"); break;
		case  0x60 : Serial.print(" - Data On Screen"); break;
		case  0x61 : Serial.print(" - Closed Caption"); break;
		case  0x62 : Serial.print(" - Closed Caption Select"); break;
		case  0x63 : Serial.print(" - VCR/TV"); break;
		case  0x64 : Serial.print(" - Broadcast Mode"); break;
		case  0x65 : Serial.print(" - Snapshot"); break;
		case  0x66 : Serial.print(" - Still"); break;
		case  0x80 : Serial.print(" - Selection"); break;
		case  0x81 : Serial.print(" - Assign Selection"); break;
		case  0x82 : Serial.print(" - Mode Step"); break;
		case  0x83 : Serial.print(" - Recall Last"); break;
		case  0x84 : Serial.print(" - Enter Channel"); break;
		case  0x85 : Serial.print(" - Order Movie"); break;
		case  0x86 : Serial.print(" - Channel"); break;
		case  0x87 : Serial.print(" - Media Selection"); break;
		case  0x88 : Serial.print(" - Media Select Computer"); break;
		case  0x89 : Serial.print(" - Media Select TV"); break;
		case  0x8A : Serial.print(" - Media Select WWW"); break;
		case  0x8B : Serial.print(" - Media Select DVD"); break;
		case  0x8C : Serial.print(" - Media Select Telephone"); break;
		case  0x8D : Serial.print(" - Media Select Program Guide"); break;
		case  0x8E : Serial.print(" - Media Select Video Phone"); break;
		case  0x8F : Serial.print(" - Media Select Games"); break;
		case  0x90 : Serial.print(" - Media Select Messages"); break;
		case  0x91 : Serial.print(" - Media Select CD"); break;
		case  0x92 : Serial.print(" - Media Select VCR"); break;
		case  0x93 : Serial.print(" - Media Select Tuner"); break;
		case  0x94 : Serial.print(" - Quit"); break;
		case  0x95 : Serial.print(" - Help"); break;
		case  0x96 : Serial.print(" - Media Select Tape"); break;
		case  0x97 : Serial.print(" - Media Select Cable"); break;
		case  0x98 : Serial.print(" - Media Select Satellite"); break;
		case  0x99 : Serial.print(" - Media Select Security"); break;
		case  0x9A : Serial.print(" - Media Select Home"); break;
		case  0x9B : Serial.print(" - Media Select Call"); break;
		case  0x9C : Serial.print(" - Channel Increment"); break;
		case  0x9D : Serial.print(" - Channel Decrement"); break;
		case  0x9E : Serial.print(" - Media Select SAP"); break;
		case  0xA0 : Serial.print(" - VCR Plus"); break;
		case  0xA1 : Serial.print(" - Once"); break;
		case  0xA2 : Serial.print(" - Daily"); break;
		case  0xA3 : Serial.print(" - Weekly"); break;
		case  0xA4 : Serial.print(" - Monthly"); break;
		case  0xB0 : Serial.print(" - Play"); break;
		case  0xB1 : Serial.print(" - Pause"); break;
		case  0xB2 : Serial.print(" - Record"); break;
		case  0xB3 : Serial.print(" - Fast Forward"); break;
		case  0xB4 : Serial.print(" - Rewind"); break;
		case  0xB5 : Serial.print(" - Scan Next Track"); break;
		case  0xB6 : Serial.print(" - Scan Previous Track"); break;
		case  0xB7 : Serial.print(" - Stop"); break;
		case  0xB8 : Serial.print(" - Eject"); break;
		case  0xB9 : Serial.print(" - Random Play"); break;
		case  0xBA : Serial.print(" - Select DisC"); break;
		case  0xBB : Serial.print(" - Enter Disc"); break;
		case  0xBC : Serial.print(" - Repeat"); break;
		case  0xBD : Serial.print(" - Tracking"); break;
		case  0xBE : Serial.print(" - Track Normal"); break;
		case  0xBF : Serial.print(" - Slow Tracking"); break;
		case  0xC0 : Serial.print(" - Frame Forward"); break;
		case  0xC1 : Serial.print(" - Frame Back"); break;
		case  0xC2 : Serial.print(" - Mark"); break;
		case  0xC3 : Serial.print(" - Clear Mark"); break;
		case  0xC4 : Serial.print(" - Repeat From Mark"); break;
		case  0xC5 : Serial.print(" - Return To Mark"); break;
		case  0xC6 : Serial.print(" - Search Mark Forward"); break;
		case  0xC7 : Serial.print(" - Search Mark Backwards"); break;
		case  0xC8 : Serial.print(" - Counter Reset"); break;
		case  0xC9 : Serial.print(" - Show Counter"); break;
		case  0xCA : Serial.print(" - Tracking Increment"); break;
		case  0xCB : Serial.print(" - Tracking Decrement"); break;
		case  0xCD : Serial.print(" - Pause/Continue"); break;
		case  0xE0 : Serial.print(" - Volume"); break;
		case  0xE1 : Serial.print(" - Balance"); break;
		case  0xE2 : Serial.print(" - Mute"); break;
		case  0xE3 : Serial.print(" - Bass"); break;
		case  0xE4 : Serial.print(" - Treble"); break;
		case  0xE5 : Serial.print(" - Bass Boost"); break;
		case  0xE6 : Serial.print(" - Surround Mode"); break;
		case  0xE7 : Serial.print(" - Loudness"); break;
		case  0xE8 : Serial.print(" - MPX"); break;
		case  0xE9 : Serial.print(" - Volume Up"); break;
		case  0xEA : Serial.print(" - Volume Down"); break;
		case  0xF0 : Serial.print(" - Speed Select"); break;
		case  0xF1 : Serial.print(" - Playback Speed"); break;
		case  0xF2 : Serial.print(" - Standard Play"); break;
		case  0xF3 : Serial.print(" - Long Play"); break;
		case  0xF4 : Serial.print(" - Extended Play"); break;
		case  0xF5 : Serial.print(" - Slow"); break;
		case  0x100: Serial.print(" - Fan Enable"); break;
		case  0x101: Serial.print(" - Fan Speed"); break;
		case  0x102: Serial.print(" - Light"); break;
		case  0x103: Serial.print(" - Light Illumination Level"); break;
		case  0x104: Serial.print(" - Climate Control Enable"); break;
		case  0x105: Serial.print(" - Room Temperature"); break;
		case  0x106: Serial.print(" - Security Enable"); break;
		case  0x107: Serial.print(" - Fire Alarm"); break;
		case  0x108: Serial.print(" - Police Alarm"); break;
		case  0x150: Serial.print(" - Balance Right"); break;
		case  0x151: Serial.print(" - Balance Left"); break;
		case  0x152: Serial.print(" - Bass Increment"); break;
		case  0x153: Serial.print(" - Bass Decrement"); break;
		case  0x154: Serial.print(" - Treble Increment"); break;
		case  0x155: Serial.print(" - Treble Decrement"); break;
		case  0x160: Serial.print(" - Speaker System"); break;
		case  0x161: Serial.print(" - Channel Left"); break;
		case  0x162: Serial.print(" - Channel Right"); break;
		case  0x163: Serial.print(" - Channel Center"); break;
		case  0x164: Serial.print(" - Channel Front"); break;
		case  0x165: Serial.print(" - Channel Center Front"); break;
		case  0x166: Serial.print(" - Channel Side"); break;
		case  0x167: Serial.print(" - Channel Surround"); break;
		case  0x168: Serial.print(" - Channel Low Frequency Enhancement"); break;
		case  0x169: Serial.print(" - Channel Top"); break;
		case  0x16A: Serial.print(" - Channel Unknown"); break;
		case  0x170: Serial.print(" - Sub-channel"); break;
		case  0x171: Serial.print(" - Sub-channel Increment"); break;
		case  0x172: Serial.print(" - Sub-channel Decrement"); break;
		case  0x173: Serial.print(" - Alternate Audio Increment"); break;
		case  0x174: Serial.print(" - Alternate Audio Decrement"); break;
		case  0x180: Serial.print(" - Application Launch Buttons"); break;
		case  0x181: Serial.print(" - AL Launch Button Configuration Tool"); break;
		case  0x182: Serial.print(" - AL Programmable Button Configuration"); break;
		case  0x183: Serial.print(" - AL Consumer Control Configuration"); break;
		case  0x184: Serial.print(" - AL Word Processor"); break;
		case  0x185: Serial.print(" - AL Text Editor"); break;
		case  0x186: Serial.print(" - AL Spreadsheet"); break;
		case  0x187: Serial.print(" - AL Graphics Editor"); break;
		case  0x188: Serial.print(" - AL Presentation App"); break;
		case  0x189: Serial.print(" - AL Database App"); break;
		case  0x18A: Serial.print(" - AL Email Reader"); break;
		case  0x18B: Serial.print(" - AL Newsreader"); break;
		case  0x18C: Serial.print(" - AL Voicemail"); break;
		case  0x18D: Serial.print(" - AL Contacts/Address Book"); break;
		case  0x18E: Serial.print(" - AL Calendar/Schedule"); break;
		case  0x18F: Serial.print(" - AL Task/Project Manager"); break;
		case  0x190: Serial.print(" - AL Log/Journal/Timecard"); break;
		case  0x191: Serial.print(" - AL Checkbook/Finance"); break;
		case  0x192: Serial.print(" - AL Calculator"); break;
		case  0x193: Serial.print(" - AL A/V Capture/Playback"); break;
		case  0x194: Serial.print(" - AL Local Machine Browser"); break;
		case  0x195: Serial.print(" - AL LAN/WAN Browser"); break;
		case  0x196: Serial.print(" - AL Internet Browser"); break;
		case  0x197: Serial.print(" - AL Remote Networking/ISP Connect"); break;
		case  0x198: Serial.print(" - AL Network Conference"); break;
		case  0x199: Serial.print(" - AL Network Chat"); break;
		case  0x19A: Serial.print(" - AL Telephony/Dialer"); break;
		case  0x19B: Serial.print(" - AL Logon"); break;
		case  0x19C: Serial.print(" - AL Logoff"); break;
		case  0x19D: Serial.print(" - AL Logon/Logoff"); break;
		case  0x19E: Serial.print(" - AL Terminal Lock/Screensaver"); break;
		case  0x19F: Serial.print(" - AL Control Panel"); break;
		case  0x1A0: Serial.print(" - AL Command Line Processor/Run"); break;
		case  0x1A1: Serial.print(" - AL Process/Task Manager"); break;
		case  0x1A2: Serial.print(" - AL Select Tast/Application"); break;
		case  0x1A3: Serial.print(" - AL Next Task/Application"); break;
		case  0x1A4: Serial.print(" - AL Previous Task/Application"); break;
		case  0x1A5: Serial.print(" - AL Preemptive Halt Task/Application"); break;
		case  0x200: Serial.print(" - Generic GUI Application Controls"); break;
		case  0x201: Serial.print(" - AC New"); break;
		case  0x202: Serial.print(" - AC Open"); break;
		case  0x203: Serial.print(" - AC Close"); break;
		case  0x204: Serial.print(" - AC Exit"); break;
		case  0x205: Serial.print(" - AC Maximize"); break;
		case  0x206: Serial.print(" - AC Minimize"); break;
		case  0x207: Serial.print(" - AC Save"); break;
		case  0x208: Serial.print(" - AC Print"); break;
		case  0x209: Serial.print(" - AC Properties"); break;
		case  0x21A: Serial.print(" - AC Undo"); break;
		case  0x21B: Serial.print(" - AC Copy"); break;
		case  0x21C: Serial.print(" - AC Cut"); break;
		case  0x21D: Serial.print(" - AC Paste"); break;
		case  0x21E: Serial.print(" - AC Select All"); break;
		case  0x21F: Serial.print(" - AC Find"); break;
		case  0x220: Serial.print(" - AC Find and Replace"); break;
		case  0x221: Serial.print(" - AC Search"); break;
		case  0x222: Serial.print(" - AC Go To"); break;
		case  0x223: Serial.print(" - AC Home"); break;
		case  0x224: Serial.print(" - AC Back"); break;
		case  0x225: Serial.print(" - AC Forward"); break;
		case  0x226: Serial.print(" - AC Stop"); break;
		case  0x227: Serial.print(" - AC Refresh"); break;
		case  0x228: Serial.print(" - AC Previous Link"); break;
		case  0x229: Serial.print(" - AC Next Link"); break;
		case  0x22A: Serial.print(" - AC Bookmarks"); break;
		case  0x22B: Serial.print(" - AC History"); break;
		case  0x22C: Serial.print(" - AC Subscriptions"); break;
		case  0x22D: Serial.print(" - AC Zoom In"); break;
		case  0x22E: Serial.print(" - AC Zoom Out"); break;
		case  0x22F: Serial.print(" - AC Zoom"); break;
		case  0x230: Serial.print(" - AC Full Screen View"); break;
		case  0x231: Serial.print(" - AC Normal View"); break;
		case  0x232: Serial.print(" - AC View Toggle"); break;
		case  0x233: Serial.print(" - AC Scroll Up"); break;
		case  0x234: Serial.print(" - AC Scroll Down"); break;
		case  0x235: Serial.print(" - AC Scroll"); break;
		case  0x236: Serial.print(" - AC Pan Left"); break;
		case  0x237: Serial.print(" - AC Pan Right"); break;
		case  0x238: Serial.print(" - AC Pan"); break;
		case  0x239: Serial.print(" - AC New Window"); break;
		case  0x23A: Serial.print(" - AC Tile Horizontally"); break;
		case  0x23B: Serial.print(" - AC Tile Vertically"); break;
		case  0x23C: Serial.print(" - AC Format"); break;
		}
	}
	Serial.println();
#endif
}
