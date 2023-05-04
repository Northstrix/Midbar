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
https://github.com/Bodmer/TFT_eSPI
https://github.com/miguelbalboa/rfid
https://github.com/intrbiz/arduino-crypto
https://github.com/GyverLibs/EncButton
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/techpaul/PS2KeyMap
https://github.com/adafruit/SdFat
*/
/*
Twinkle
Distributed under the MIT License
© Copyright Maxim Bortnikov 2023
For more information please visit
https://github.com/Northstrix/Twinkle
Credit:
Implementation of DES by David Simmons was taken from here https://github.com/simmons/desdemo
* Copyright 2011 David Simmons
* http://cafbit.com/
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
import java.awt.GraphicsEnvironment;
import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.BadLocationException;  
import javax.swing.text.Document;  
import javax.swing.text.SimpleAttributeSet;  
import javax.swing.text.StyleConstants;
import java.io.*;
import java.lang.*;
import java.awt.BorderLayout;  
import java.awt.Color;  
import java.awt.Container;
import java.security.SecureRandom;
import java.security.Security;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;  
import javax.crypto.SecretKey;  
import javax.crypto.SecretKeyFactory;  
import javax.crypto.spec.IvParameterSpec;  
import javax.crypto.spec.PBEKeySpec;  
import javax.crypto.spec.SecretKeySpec;  
import java.nio.charset.StandardCharsets;  
import java.security.InvalidAlgorithmParameterException;  
import java.security.InvalidKeyException;  
import java.security.NoSuchAlgorithmException;  
import java.security.spec.InvalidKeySpecException;  
import java.security.spec.KeySpec;  
import java.util.Base64;  
import javax.crypto.BadPaddingException;  
import javax.crypto.IllegalBlockSizeException;  
import javax.crypto.NoSuchPaddingException; 

public class MainClass {
    static JMenuBar mb;
    static JMenu m,m1;
    static JMenuItem c, o, sv, q, gk, sk;
    static JTextPane pane;
        public static String X;
        public static int end;
        public static int s;
        public static String stf;
        public static String ck;
        public static String div;
        private static String SECRET_KEY = "";  
        private static String SALTVALUE = "";
        private static byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        public static int Forward_S_Box[][] = {  
        	    {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},  
        	    {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},  
        	    {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},  
        	    {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},  
        	    {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},  
        	    {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},  
        	    {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},  
        	    {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},  
        	    {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},  
        	    {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},  
        	    {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},  
        	    {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},  
        	    {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},  
        	    {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},  
        	    {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},  
        	    {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}  
        	};
        
        public static int Inv_S_Box[][] = {  
        	    {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},  
        	    {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},  
        	    {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},  
        	    {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},  
        	    {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},  
        	    {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},  
        	    {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},  
        	    {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},  
        	    {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},  
        	    {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},  
        	    {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},  
        	    {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},  
        	    {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},  
        	    {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},  
        	    {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},  
        	    {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}  
        	};
    
    public static void cf() {
        
        SimpleAttributeSet attributeSet = new SimpleAttributeSet();  
        StyleConstants.setFontFamily(attributeSet, X);
        StyleConstants.setFontSize(attributeSet, s);
    	pane.selectAll();
        pane.setCharacterAttributes(attributeSet, true);  
        
        Document doc = pane.getStyledDocument();  
        try {
			doc.insertString(doc.getLength(), "", attributeSet);
		} catch (BadLocationException e1) {
			e1.printStackTrace();
		} 
  
    }
    
    public static void disp_rec(String T) {
        
        SimpleAttributeSet attributeSet = new SimpleAttributeSet();  
        StyleConstants.setFontFamily(attributeSet, X);
        StyleConstants.setFontSize(attributeSet, s); 
        pane.setCharacterAttributes(attributeSet, true);  
        
        Document doc = pane.getStyledDocument();  
        try {
			doc.insertString(doc.getLength(), T, attributeSet);
		} catch (BadLocationException e1) {
			e1.printStackTrace();
		} 
  
    }
    
    static int split(char ct[], int i){
    		int res = 0;
    	    if(ct[i] != 0 && ct[i+1] != 0)
    	    res = 16*getNum(ct[i])+getNum(ct[i+1]);
    	    if(ct[i] != 0 && ct[i+1] == 0)
    	    res = 16*getNum(ct[i]);
    	    if(ct[i] == 0 && ct[i+1] != 0)
    	    res = getNum(ct[i+1]);
    	    if(ct[i] == 0 && ct[i+1] == 0)
    	    res = 0;
    	    return res;
    	}
    
    static int getNum(char ch)
    {
        int num=0;
        if(ch>='0' && ch<='9')
        {
            num=ch-0x30;
        }
        else
        {
            switch(ch)
            {
                case 'A': case 'a': num=10; break;
                case 'B': case 'b': num=11; break;
                case 'C': case 'c': num=12; break;
                case 'D': case 'd': num=13; break;
                case 'E': case 'e': num=14; break;
                case 'F': case 'f': num=15; break;
                default: num=0;
            }
        }
        return num;
    }
    
    public static void cl(){
    	pane.selectAll();
        pane.replaceSelection("");
    }
    
    private static final byte[] IP = {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
    };

    private static final byte[] FP = {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
    };

    private static final byte[] E = {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
    };

    private static final byte[][] S = {{
            14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
            0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
            4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
            15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
    }, {
            15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
            3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
            0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
            13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
    }, {
            10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
            13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
            13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
            1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
    }, {
            7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
            13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
            10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
            3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
    }, {
            2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
            14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
            4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
            11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
    }, {
            12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
            10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
            9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
            4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
    }, {
            4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
            13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
            1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
            6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
    }, {
            13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
            1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
            7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
            2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
    }};

    private static final byte[] P = {
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25
    };

    private static final byte[] PC1 = {
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
    };

    private static final byte[] PC2 = {
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
    };

    private static final byte[] rotations = {
            1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    };

    private static long IP(long src) {
        return permute(IP, 64, src);
    } // 64-bit output

    private static long FP(long src) {
        return permute(FP, 64, src);
    } // 64-bit output

    private static long E(int src) {
        return permute(E, 32, src & 0xFFFFFFFFL);
    } // 48-bit output

    private static int P(int src) {
        return (int) permute(P, 32, src & 0xFFFFFFFFL);
    } // 32-bit output

    private static long PC1(long src) {
        return permute(PC1, 64, src);
    } // 56-bit output

    private static long PC2(long src) {
        return permute(PC2, 56, src);
    } // 48-bit output

    private static long permute(byte[] table, int srcWidth, long src) {
        long dst = 0;
        for (int i = 0; i < table.length; i++) {
            int srcPos = srcWidth - table[i];
            dst = (dst << 1) | (src >> srcPos & 0x01);
        }
        return dst;
    }

    private static byte S(int boxNumber, byte src) {
        // The first aindex based on the following bit shuffle:
        // abcdef => afbcde
        src = (byte) (src & 0x20 | ((src & 0x01) << 4) | ((src & 0x1E) >> 1));
        return S[boxNumber - 1][src];
    }

    private static long getLongFromBytes(byte[] ba, int offset) {
        long l = 0;
        for (int i = 0; i < 8; i++) {
            byte value;
            if ((offset + i) < ba.length) {
                // and last bits determine which 16-value row to
                // reference, so we transform the 6-bit input into an
                // absolute
                value = ba[offset + i];
            } else {
                value = 0;
            }
            l = l << 8 | (value & 0xFFL);
        }
        return l;
    }

    private static void getBytesFromLong(byte[] ba, int offset, long l) {
        for (int i = 7; i > -1; i--) {
            if ((offset + i) < ba.length) {
                ba[offset + i] = (byte) (l & 0xFF);
                l = l >> 8;
            } else {
                break;
            }
        }
    }

    private static int feistel(int r, /* 48 bits */ long subkey) {
        // 1. expansion
        long e = E(r);
        // 2. key mixing
        long x = e ^ subkey;
        // 3. substitution
        int dst = 0;
        for (int i = 0; i < 8; i++) {
            dst >>>= 4;
            int s = S(8 - i, (byte) (x & 0x3F));
            dst |= s << 28;
            x >>= 6;
        }
        // 4. permutation
        return P(dst);
    }

    private static long[] createSubkeys(/* 64 bits */ long key) {
        long subkeys[] = new long[16];

        // perform the PC1 permutation
        key = PC1(key);

        // split into 28-bit left and right (c and d) pairs.
        int c = (int) (key >> 28);
        int d = (int) (key & 0x0FFFFFFF);

        // for each of the 16 needed subkeys, perform a bit
        // rotation on each 28-bit keystuff half, then join
        // the halves together and permute to generate the
        // subkey.
        for (int i = 0; i < 16; i++) {
            // rotate the 28-bit values
            if (rotations[i] == 1) {
                // rotate by 1 bit
                c = ((c << 1) & 0x0FFFFFFF) | (c >> 27);
                d = ((d << 1) & 0x0FFFFFFF) | (d >> 27);
            } else {
                // rotate by 2 bits
                c = ((c << 2) & 0x0FFFFFFF) | (c >> 26);
                d = ((d << 2) & 0x0FFFFFFF) | (d >> 26);
            }

            // join the two keystuff halves together.
            long cd = (c & 0xFFFFFFFFL) << 28 | (d & 0xFFFFFFFFL);

            // perform the PC2 permutation
            subkeys[i] = PC2(cd);
        }

        return subkeys; /* 48-bit values */
    }

    public static long encryptBlock(long m, /* 64 bits */ long key) {
        // generate the 16 subkeys
        long subkeys[] = createSubkeys(key);

        // perform the initial permutation
        long ip = IP(m);

        // split the 32-bit value into 16-bit left and right halves.
        int l = (int) (ip >> 32);
        int r = (int) (ip & 0xFFFFFFFFL);

        // perform 16 rounds
        for (int i = 0; i < 16; i++) {
            int previous_l = l;
            // the right half becomes the new left half.
            l = r;
            // the Feistel function is applied to the old left half
            // and the resulting value is stored in the right half.
            r = previous_l ^ feistel(r, subkeys[i]);
        }

        // reverse the two 32-bit segments (left to right; right to left)
        long rl = (r & 0xFFFFFFFFL) << 32 | (l & 0xFFFFFFFFL);

        // apply the final permutation
        long fp = FP(rl);

        // return the ciphertext
        return fp;
    }

    public static void encryptBlock(
            byte[] message,
            int messageOffset,
            byte[] ciphertext,
            int ciphertextOffset,
            byte[] key
    ) {
        long m = getLongFromBytes(message, messageOffset);
        long k = getLongFromBytes(key, 0);
        long c = encryptBlock(m, k);
        getBytesFromLong(ciphertext, ciphertextOffset, c);
    }

    public static byte[] encrypt(byte[] message, byte[] key) {
        byte[] ciphertext = new byte[message.length];

        // encrypt each 8-byte (64-bit) block of the message.
        for (int i = 0; i < message.length; i += 8) {
            encryptBlock(message, i, ciphertext, i, key);
        }

        return ciphertext;
    }

    public static byte[] encrypt(byte[] challenge, String password) {
        return encrypt(challenge, passwordToKey(password));
    }

    private static byte[] passwordToKey(String password) {
        byte[] pwbytes = password.getBytes();
        byte[] key = new byte[8];
        for (int i = 0; i < 8; i++) {
            if (i < pwbytes.length) {
                byte b = pwbytes[i];
                // flip the byte
                byte b2 = 0;
                for (int j = 0; j < 8; j++) {
                    b2 <<= 1;
                    b2 |= (b & 0x01);
                    b >>>= 1;
                }
                key[i] = b2;
            } else {
                key[i] = 0;
            }
        }
        return key;
    }

    private static int charToNibble(char c) {
        if (c >= '0' && c <= '9') {
            return (c - '0');
        } else if (c >= 'a' && c <= 'f') {
            return (10 + c - 'a');
        } else if (c >= 'A' && c <= 'F') {
            return (10 + c - 'A');
        } else {
            return 0;
        }
    }

    private static byte[] parseBytes(String s) {
        s = s.replace(" ", "");
        byte[] ba = new byte[s.length() / 2];
        if (s.length() % 2 > 0) {
            s = s + '0';
        }
        for (int i = 0; i < s.length(); i += 2) {
            ba[i / 2] = (byte) (charToNibble(s.charAt(i)) << 4 | charToNibble(s.charAt(i + 1)));
        }
        return ba;
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%02X ", bytes[i]));
        }
        return sb.toString();
    }
     
    private static long IV;

    public static long getIv() {
        return IV;
    }

    public static void setIv(long iv) {
        IV = iv;
    }

    public static byte[] encryptCBC(byte[] message, byte[] key) {
        byte[] ciphertext = new byte[message.length];
        long k = getLongFromBytes(key, 0);
        long previousCipherBlock = IV;

        for (int i = 0; i < message.length; i += 8) {
            // get the message block to be encrypted (8bytes = 64bits)
            long messageBlock = getLongFromBytes(message, i);

            // XOR message block with previous cipherblock and encrypt
            // First previousCiphertext = Initial Vector (IV)
            long cipherBlock = encryptBlock(messageBlock ^ previousCipherBlock, k);

            // Store the cipherBlock in the correct position in ciphertext
            getBytesFromLong(ciphertext, i, cipherBlock);

            // Update previousCipherBlock
            previousCipherBlock = cipherBlock;
        }

        return ciphertext;
    }

    public static long decryptBlock(long c, /* 64 bits */ long key) {
        // generate the 16 subkeys
        long[] subkeys = createSubkeys(key);

        // perform the initial permutation
        long ip = IP(c);

        // split the 32-bit value into 16-bit left and right halves.
        int l = (int) (ip >> 32);
        int r = (int) (ip & 0xFFFFFFFFL);

        // perform 16 rounds
        // NOTE: reverse order of subkeys used!
        for (int i = 15; i > -1; i--) {
            int previous_l = l;
            // the right half becomes the new left half.
            l = r;
            // the Feistel function is applied to the old left half
            // and the resulting value is stored in the right half.
            r = previous_l ^ feistel(r, subkeys[i]);
        }

        // reverse the two 32-bit segments (left to right; right to left)
        long rl = (r & 0xFFFFFFFFL) << 32 | (l & 0xFFFFFFFFL);

        // apply the final permutation
        long fp = FP(rl);

        // return the message
        return fp;
    }

    public static void decryptBlock(
            byte[] ciphertext,
            int ciphertextOffset,
            byte[] message,
            int messageOffset,
            byte[] key
    ) {
        long c = getLongFromBytes(ciphertext, ciphertextOffset);
        long k = getLongFromBytes(key, 0);
        long m = decryptBlock(c, k);
        getBytesFromLong(message, messageOffset, m);
    }

    public static byte[] decrypt(byte[] ciphertext, byte[] key) {
        byte[] message = new byte[ciphertext.length];

        // encrypt each 8-byte (64-bit) block of the message.
        for (int i = 0; i < ciphertext.length; i += 8) {
            decryptBlock(ciphertext, i, message, i, key);
        }

        return message;
    }

    public static byte[] decryptCBC(byte[] ciphertext, byte[] key) {
        byte[] message = new byte[ciphertext.length];
        long k = getLongFromBytes(key, 0);
        long previousCipherBlock = IV;

        for (int i = 0; i < ciphertext.length; i += 8) {
            // get the cipher block to be decrypted (8bytes = 64bits)
            long cipherBlock = getLongFromBytes(ciphertext, i);

            // Decrypt the cipher block and XOR with previousCipherBlock
            // First previousCiphertext = Initial Vector (IV)
            long messageBlock = decryptBlock(cipherBlock, k);
            messageBlock = messageBlock ^ previousCipherBlock;

            // Store the messageBlock in the correct position in message
            getBytesFromLong(message, i, messageBlock);

            // Update previousCipherBlock
            previousCipherBlock = cipherBlock;
        }

        return message;
    }
    
    public static void ctostr(char[] vrbls, int pos) {
    	String tf = "";
    	for (int i = 0; i < 8; i++) {
    	tf += vrbls[i+pos];
    	}
  	  SecureRandom number = new SecureRandom();
  	  for (int i = 0; i < 4; i++) {
  		  String r ="";
  		  r += number.nextInt(256);
  		  Integer inv =Integer.valueOf(r);  
  		  tf += String.format("%02x", inv);  
  		  }
  	  
  	  //System.out.println(tf);
	  String key = ck;
  	  byte[] enc = encrypt(parseBytes(tf), parseBytes(key));
  	  for (int i = 0; i < 8; i++) {
  		  stf += String.format("%02x", enc[i]);
  		  }
  	  
    }

	private static void dec_str(char[] tdec, int pos) {
    	String tf = "";
    	for (int i = 0; i < 16; i++) {
    	tf += tdec[i+pos];
    	}
    	//System.out.println(tf);
		String key = ck;
    	byte[] dec_t = decrypt(parseBytes(tf), parseBytes(key));
    	String tsb = "";
        //System.out.println("\tDecrypted: " + hex(dec)); 
      	  for (int i = 0; i < 4; i++) {
      		  tsb += String.format("%02x", dec_t[i]);
      		  }
      	//System.out.println(tsb); 
      	String ir1 = "";
		char[] chtd = tsb.toCharArray();
		for(int i = 0; i < 8 ; i+=2){ 
			int fs = getNum(chtd[i]);
			int ss = getNum(chtd[i+1]);
      	  	Integer intObject = Integer.valueOf(Inv_S_Box[fs][ss]);
      	  	String cv = "";
      	  	cv += (String.format("%02x", intObject));
      	  	//System.out.println(cv);
      	  	int rc = Integer.valueOf(cv, 16);
      	  	//System.out.println(rc);
      	  	char ctp = (char)rc;  
      	  	ir1 += ctp;
			}
			disp_rec(ir1);
			
	}
	
	private static void dec_ivs(char[] tdec, int pos) {
    	String tf = "";
    	for (int i = 0; i < 16; i++) {
    	tf += tdec[i+pos];
    	}
    	//System.out.println(tf);
		String key = ck;
    	byte[] dec_t = decrypt(parseBytes(tf), parseBytes(key));
    	String tsb = "";
        //System.out.println("\tDecrypted: " + hex(dec)); 
      	  for (int i = 0; i < 4; i++) {
      		  tsb += String.format("%02x", dec_t[i]);
      		  }
      	//System.out.println(tsb); 
      	String ir = "";
		char[] chtd = tsb.toCharArray();
		for(int i = 0; i < 8 ; i+=2){ 
			int fs = getNum(chtd[i]);
			int ss = getNum(chtd[i+1]);
      	  	Integer intObject = Integer.valueOf(Inv_S_Box[fs][ss]);
      	  	String cv = "";
      	  	cv += (String.format("%02x", intObject));
      	  	//System.out.println(cv);
      	  	int rc = Integer.valueOf(cv, 16);
      	  	//System.out.println(rc);
      	  	char ctp = (char)rc;  
      	  	ir += ctp;
			}
			div += ir;	
	}

   
    /* Encryption Method */  
    public static String encrypt_AES(String strToEncrypt)   
    {  
    try   
    {  
      IvParameterSpec ivspec = new IvParameterSpec(iv);        
      /* Create factory for secret keys. */  
      SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");  
      /* PBEKeySpec class implements KeySpec interface. */  
      KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALTVALUE.getBytes(), 65536, 256);  
      SecretKey tmp = factory.generateSecret(spec);  
      SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");  
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");  
      cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);  
      /* Retruns encrypted value. */  
      return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));  
    }   
    catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e)   
    {  
      System.out.println("Error occured during encryption: " + e.toString());  
    }  
    return null;  
    }  
    
    /* Decryption Method */  
    public static String decrypt_AES(String strToDecrypt)   
    {  
    try   
    {  
      IvParameterSpec ivspec = new IvParameterSpec(iv);  
      /* Create factory for secret keys. */  
      SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");  
      /* PBEKeySpec class implements KeySpec interface. */  
      KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALTVALUE.getBytes(), 65536, 256);  
      SecretKey tmp = factory.generateSecret(spec);  
      SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");  
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");  
      cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);  
      /* Retruns decrypted value. */  
      return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));  
    }   
    catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e)   
    {  
      System.out.println("Error occured during decryption: " + e.toString());  
    }  
    return null;  
    }  
    
    public static void generate_key() {
  	  	SecureRandom desk = new SecureRandom();
  	  	SecureRandom slct = new SecureRandom();
  	  	StringBuilder dk = new StringBuilder();
  		for(int i = 0; i < 16; i++) {
  			if(slct.nextInt(2) == 1) {
  				dk.append((char) (48 + desk.nextInt(10)));
  			}
  			else {
  				dk.append((char) (65 + desk.nextInt(6)));
  			}
  		}
  		//System.out.println(dk.toString());
  	  	int gv = 0;
  	  	SecureRandom aesk = new SecureRandom();
  	  	StringBuilder aeskey = new StringBuilder();
  	  	gv = 0;
  	  	int adl = aesk.nextInt(200);
  		for(int i = 0; i < 320 + adl; i++) {
  			gv = 32 + aesk.nextInt(94);
  			if(gv != 44)
  				aeskey.append((char) gv);
  			else {
  				aeskey.append((char) gv + 2 + aesk.nextInt(74));
  			}
  		}
  		//System.out.println(aeskey.toString());
    	JFrame parentFrame = new JFrame();
    	JFileChooser fileChooser = new JFileChooser();
    	fileChooser.setDialogTitle("Choose where to save newly generated key");   
    	int userSelection = fileChooser.showSaveDialog(parentFrame);
    	if (userSelection == JFileChooser.APPROVE_OPTION) {
    	    File fileToSave = fileChooser.getSelectedFile();
        		FileWriter myWriter;
				try {
					myWriter = new FileWriter(fileToSave.getAbsolutePath());
                    myWriter.write(dk.toString() + "," + aeskey.toString());
                    myWriter.close();
				} catch (IOException e1) {
					e1.printStackTrace();
				}

                //System.out.println("Successfully wrote to the file.");
      	  	  	SecureRandom numb1 = new SecureRandom();
      	  	  	for (int i = 0; i < 16; i++) {
    	  		  	iv[i]= (byte) numb1.nextInt(256); 
      	  	  	}
              }
    }
    
    public static void gen_keys() {
    	cl();
		int m = 0;
		int m1 = 0;
		
		disp_rec("String kderalgs = \"");
		SecureRandom sk0hk1 = new SecureRandom();
		int num_of_chars_in_hk1 = 20 + sk0hk1.nextInt(30);
		for (int i = 0; i < num_of_chars_in_hk1; i++) {
			SecureRandom sk011 = new SecureRandom();
				m = sk011.nextInt(3);
				m1 = sk011.nextInt(2);
				StringBuilder str01 = new StringBuilder();
				if (m == 0)
					str01.append((char)(65 + (sk011.nextInt(26))));
				if (m == 1)
					str01.append((char)(97 + (sk011.nextInt(26))));
				if (m == 2)
					str01.append((char)(48 + (sk011.nextInt(10))));
				disp_rec(str01.toString());
		}
		disp_rec("\";\n");
		
		disp_rec("int numofkincr = ");
		SecureRandom nofincrem = new SecureRandom();
		for (int i = 0; i < 3; i++) {
				StringBuilder str22 = new StringBuilder();
				if (i == 0)
					str22.append((char)(50 + (nofincrem.nextInt(8))));
				else
					str22.append((char)(48 + (nofincrem.nextInt(10))));
				disp_rec(str22.toString());
		}
		disp_rec(";\n");
		
		disp_rec("byte hmackey[] = {\"");
		SecureRandom sk0hk = new SecureRandom();
		int num_of_chars_in_hk = 99 + sk0hk.nextInt(50);
		for (int i = 0; i < num_of_chars_in_hk; i++) {
			SecureRandom sk01 = new SecureRandom();
				m = sk01.nextInt(3);
				m1 = sk01.nextInt(2);
				StringBuilder str0 = new StringBuilder();
				if (m == 0)
					str0.append((char)(65 + (sk01.nextInt(26))));
				if (m == 1)
					str0.append((char)(97 + (sk01.nextInt(26))));
				if (m == 2)
					str0.append((char)(48 + (sk01.nextInt(10))));
				disp_rec(str0.toString());
		}
		disp_rec("\"};\n");
		
		disp_rec("byte des_key[] = {\n");
		for (int i = 0; i < 3; i++) {
			SecureRandom sk6 = new SecureRandom();
			for (int j = 0; j < 8; j++) {
				m = sk6.nextInt(2);
				m1 = sk6.nextInt(2);
				disp_rec("0x");
				StringBuilder str6 = new StringBuilder();
				if (m == 0)
					str6.append((char)(97 + (sk6.nextInt(6))));
				if (m == 1)
					str6.append((char)(48 + (sk6.nextInt(10))));
				if (m1 == 0)
					str6.append((char)(97 + (sk6.nextInt(6))));
				if (m1 == 1)
					str6.append((char)(48 + (sk6.nextInt(10))));
				str6.append(",");
				if (i == 2 && j == 7)
					str6.setLength(str6.length() - 1);
				disp_rec(str6.toString());
			}
			disp_rec("\n");
		}
		disp_rec("};\n");
		
		disp_rec("uint8_t AES_key[32] = {\n");
		for (int i = 0; i < 8; i++) {
			SecureRandom sk3 = new SecureRandom();
			for (int j = 0; j < 4; j++) {
				m = sk3.nextInt(2);
				m1 = sk3.nextInt(2);
				disp_rec("0x");
				StringBuilder str3 = new StringBuilder();
				if (m == 0)
					str3.append((char)(97 + (sk3.nextInt(6))));
				if (m == 1)
					str3.append((char)(48 + (sk3.nextInt(10))));
				if (m1 == 0)
					str3.append((char)(97 + (sk3.nextInt(6))));
				if (m1 == 1)
					str3.append((char)(48 + (sk3.nextInt(10))));
				str3.append(",");
				if (i == 7 && j == 3)
					str3.setLength(str3.length() - 1);
				disp_rec(str3.toString());
			}
			disp_rec("\n");
		}
		disp_rec("};\n");
		
		disp_rec("unsigned char Blwfsh_key[] = {\n");
		for (int i = 0; i < 6; i++) {
			SecureRandom sk2 = new SecureRandom();
			for (int j = 0; j < 4; j++) {
				m = sk2.nextInt(2);
				m1 = sk2.nextInt(2);
				disp_rec("0x");
				StringBuilder str2 = new StringBuilder();
				if (m == 0)
					str2.append((char)(97 + (sk2.nextInt(6))));
				if (m == 1)
					str2.append((char)(48 + (sk2.nextInt(10))));
				if (m1 == 0)
					str2.append((char)(97 + (sk2.nextInt(6))));
				if (m1 == 1)
					str2.append((char)(48 + (sk2.nextInt(10))));
				str2.append(",");
				if (i == 5 && j == 3)
					str2.setLength(str2.length() - 1);
				disp_rec(str2.toString());
			}
			disp_rec("\n");
		}
		disp_rec("};\n");
		
		disp_rec("uint8_t serp_key[32] = {\n");
		for (int i = 0; i < 8; i++) {
			SecureRandom sk4 = new SecureRandom();
			for (int j = 0; j < 4; j++) {
				m = sk4.nextInt(2);
				m1 = sk4.nextInt(2);
				disp_rec("0x");
				StringBuilder str4 = new StringBuilder();
				if (m == 0)
					str4.append((char)(97 + (sk4.nextInt(6))));
				if (m == 1)
					str4.append((char)(48 + (sk4.nextInt(10))));
				if (m1 == 0)
					str4.append((char)(97 + (sk4.nextInt(6))));
				if (m1 == 1)
					str4.append((char)(48 + (sk4.nextInt(10))));
				str4.append(",");
				if (i == 7 && j == 3)
					str4.setLength(str4.length() - 1);
				disp_rec(str4.toString());
			}
			disp_rec("\n");
		}
		disp_rec("};\n");
		
	    disp_rec("uint8_t second_AES_key[32] = {\n");
	    for (int i = 0; i < 8; i++) {
	      SecureRandom scrrandsa = new SecureRandom();
	      for (int j = 0; j < 4; j++) {
	        m = scrrandsa.nextInt(2);
	        m1 = scrrandsa.nextInt(2);
	        disp_rec("0x");
	        StringBuilder strfsak = new StringBuilder();
	        if (m == 0)
	          strfsak.append((char)(97 + (scrrandsa.nextInt(6))));
	        if (m == 1)
	          strfsak.append((char)(48 + (scrrandsa.nextInt(10))));
	        if (m1 == 0)
	          strfsak.append((char)(97 + (scrrandsa.nextInt(6))));
	        if (m1 == 1)
	          strfsak.append((char)(48 + (scrrandsa.nextInt(10))));
	        strfsak.append(",");
	        if (i == 7 && j == 3)
	          strfsak.setLength(strfsak.length() - 1);
	        disp_rec(strfsak.toString());
	      }
	      disp_rec("\n");
	    }
	    disp_rec("};");
    }
    
	static Color back_grey_cl = new Color(27, 29, 29);
	static Color forg_blue_cl = new Color(77, 198, 232);
	static Color forg_white_cl = new Color(239, 239, 239);
	private static void customize_button(JButton btn) {
		btn.setBackground(back_grey_cl);
	      btn.setForeground(forg_blue_cl);
		  Border line = new LineBorder(forg_blue_cl);
		  Border margin = new EmptyBorder(5, 15, 5, 15);
		  Border compound = new CompoundBorder(line, margin);
		  btn.setBorder(compound);
		}
	
	  public static void main(String[] args){
		  /*
		  byte[] enc = encrypt(parseBytes("0123456789ABCDEF"), parseBytes("133457799BBCDFF1"));
	      System.out.println("\tEncrypted: " + hex(enc));
	      byte[] dec = decrypt(enc, parseBytes("133457799BBCDFF1"));
	      System.out.println("\tDecrypted: " + hex(dec));  
	      */
		  StringBuilder slt = new StringBuilder();
	  	  SecureRandom number = new SecureRandom();
	  	  for (int i = 0; i < 64; i++) {
	  		  slt.append((char)(65 + (number.nextInt(26))));
	  	  }
	  	  SALTVALUE = slt.toString();
	  	  	SecureRandom numb = new SecureRandom();
	  	  	for (int i = 0; i < 16; i++) {
	  		  	iv[i]= (byte) numb.nextInt(256); 
	  	  	}

	  	  	/*
	  	  	for (int i = 0; i < 16; i++) {
	  		  	System.out.println(iv[i]);
	  	  	}
	  	  	*/
	  	  	String fonts[] = GraphicsEnvironment.getLocalGraphicsEnvironment().getAvailableFontFamilyNames();
		    String sizes[] = new String [92];
        	s = 14;
        	
		    for(int i = 0; i < 92; i++) {
		    	sizes[i] = String.valueOf(i+8);
		    }
		    
		    JFrame frame = new JFrame("Twinkle DES + AES edition with key generator");
		    JComboBox fd = new JComboBox(fonts);
		    JComboBox ff = new JComboBox(sizes);
		    JButton sel = new JButton("Apply");
		    JLabel label0 = new JLabel("|  Font ");
		    JLabel label1 = new JLabel("  Font size ");
		    X = fonts[2];

	        JPanel panel = new JPanel();
	        mb = new JMenuBar();
	        m = new JMenu("File");
	        m1 = new JMenu("Action");
	        o = new JMenuItem("Open");
	        sv = new JMenuItem("Save As...");
	        c = new JMenuItem("Clear Pane");
	        JButton genr = new JButton("Generate keys for Midbar");
	        q = new JMenuItem("Quit");
	        gk = new JMenuItem("Generate encryption key");
	        sk = new JMenuItem("Select encryption key");
	        customize_button(genr);
	        customize_button(sel);
	        fd.setBackground(back_grey_cl);
	        fd.setForeground(forg_blue_cl);
	        ff.setBackground(back_grey_cl);
	        ff.setForeground(forg_blue_cl);
	        mb.setBackground(back_grey_cl);
	        m.setForeground(forg_blue_cl);
	        m1.setForeground(forg_blue_cl);
	        label0.setForeground(forg_blue_cl);
	        label1.setForeground(forg_blue_cl);
	        o.setBackground(back_grey_cl);
	        sv.setBackground(back_grey_cl);
	        c.setBackground(back_grey_cl);
	        gk.setBackground(back_grey_cl);
	        sk.setBackground(back_grey_cl);
	        q.setBackground(back_grey_cl);
	        o.setForeground(forg_blue_cl);
	        sv.setForeground(forg_blue_cl);
	        c.setForeground(forg_blue_cl);
	        gk.setForeground(forg_blue_cl);
	        sk.setForeground(forg_blue_cl);
	        q.setForeground(forg_blue_cl);
	        m.add(o);
	        m.add(sv);
	        m1.add(c);
	        m.add(gk);
	        m.add(sk);
	        m.add(q);
	        mb.add(m);
	        mb.add(m1);
	        mb.add(genr);
	        frame.setJMenuBar(mb);  
		    mb.add(label0);  
		    mb.add(fd);
		    mb.add(label1);  
		    mb.add(ff);
		    mb.add(sel);
		    
		    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);  
	        Container cp = frame.getContentPane();  
	        pane = new JTextPane();
	        Color frgr = new Color(238, 238, 238);
	        Color bclr = new Color(18, 18, 18);
	        pane.setForeground(frgr);
	        pane.setBackground(bclr);
	        pane.setCaretColor(forg_white_cl);
	        SimpleAttributeSet attributeSet = new SimpleAttributeSet();  
	        StyleConstants.setFontFamily(attributeSet, X);
	        StyleConstants.setFontSize(attributeSet, 16); 
	        
	        // Set the attributes before adding text  
	        pane.setCharacterAttributes(attributeSet, true);
	        JScrollPane scrollPane = new JScrollPane(pane);  
	        cp.add(scrollPane, BorderLayout.CENTER);   
		    frame.setSize(760, 990);  
	        frame.setVisible(true);  
	        
		    sel.addActionListener(e ->
	        {
	        	X = fonts[fd.getSelectedIndex()];
	        	s = Integer.parseInt(sizes[ff.getSelectedIndex()]);
	        	cf();      	
	        });
	        
	        c.addActionListener(e ->
	        {
	        	cl(); 
	        });
	        
	        genr.addActionListener(e ->
	        {
	        	Color bbclr = new Color(36, 36, 36);
	        	pane.setBackground(bbclr);
	        	gen_keys(); 
	        });
	        
	        q.addActionListener(e ->
	        {
	        	System.exit(0); 
	        });
	        
	        o.addActionListener(e ->
	        {
	        	final JFrame iFRAME = new JFrame();
	        	iFRAME.setAlwaysOnTop(true);
	        	iFRAME.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
	        	iFRAME.setLocationRelativeTo(null);
	        	iFRAME.requestFocus();

	        	JFileChooser jfc = new JFileChooser();
	        	jfc.setDialogTitle("Open a record");  
	        	int returnValue = jfc.showOpenDialog(iFRAME);
	        	iFRAME.dispose();
	        	if (returnValue == JFileChooser.APPROVE_OPTION) {
	        	    File selectedFile = jfc.getSelectedFile();
	        	    cl();
	        	    // Display selected file in console
	        	    //System.out.println(selectedFile.getAbsolutePath());
	        	    try {
	        	        String result = null;
	        	        DataInputStream reader = new DataInputStream(new FileInputStream(selectedFile.getAbsolutePath()));
	        	        int nBytesToRead = reader.available();
	        	        if(nBytesToRead > 0) {
	        	            byte[] bytes = new byte[nBytesToRead];
	        	            reader.read(bytes);
	        	            result = new String(bytes);
	        	        }
	        	        String[] prts = result.split(",");
	        	        div = "";
	            	    char[] tdec0 = prts[0].toCharArray();
	            	    int td_len0 = tdec0.length;
                        int crr0 = 0;
                       while(crr0 < td_len0) {
                        	dec_ivs(tdec0, crr0);
                        	crr0 += 16;
                        }
                       //System.out.println(div);
                       for (int i = 0; i < div.length(); i++){
                           if (div.charAt(i) < '!'){
                               div = div.substring(0, i) + div.substring(i + 1);
                               i--;
                           }
                       }
                       /*
                       char[] test = div.toCharArray();
                       for (int i = 0; i < test.length; i++) {
                    	   System.out.println((int) test[i]);
                       }
                       */
                       String[] ivs = div.split(",");
                       div = "";
                       for (int i = 0; i< 16; i++) {
                    	   Integer q = Integer.parseInt(ivs[i]);
                    	   iv[i] = q.byteValue();
                       }
                       /*
                       for (int i = 0; i< 16; i++) {
                    	   System.out.println(iv[i]);
                       }
                       */
	        	        div = "";
	            	    char[] tdec2 = prts[1].toCharArray();
	            	    int td_len2 = tdec2.length;
	            	    int crr2 = 0;
	            	    while(crr2 < td_len2) {
	            	    	dec_ivs(tdec2, crr2);
                       		crr2 += 16;
	            	    }
	            	    SALTVALUE = div;
	            	    div = "";
                       //System.out.println(prts[1]);
                       
	            	    char[] tdec1 = decrypt_AES(prts[2]).toCharArray();
	            	    int td_len1 = tdec1.length;
                        int crr1 = 0;
                       while(crr1 < td_len1) {
                        	dec_str(tdec1, crr1);
                        	crr1 += 16;
                        }
                       
	                } catch (IOException r) {
	                    System.out.println("An error occurred.");
	                    r.printStackTrace();
	                  }
	        	    SwingUtilities.updateComponentTreeUI(frame);
	        	}
	        });
	        
	        gk.addActionListener(e ->
	        {
	        	generate_key();
	        });
	        
	        sk.addActionListener(e ->
	        {
	        	final JFrame iFRAME = new JFrame();
	        	iFRAME.setAlwaysOnTop(true);
	        	iFRAME.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
	        	iFRAME.setLocationRelativeTo(null);
	        	iFRAME.requestFocus();

	        	JFileChooser jfc = new JFileChooser();
	        	int returnValue = jfc.showOpenDialog(iFRAME);
	        	iFRAME.dispose();
	        	if (returnValue == JFileChooser.APPROVE_OPTION) {
	        	    File selectedFile = jfc.getSelectedFile();
	        	    // Display selected file in console
	        	    //System.out.println(selectedFile.getAbsolutePath());
	        	    try {
	        	        String result = null;

	        	        DataInputStream reader = new DataInputStream(new FileInputStream(selectedFile.getAbsolutePath()));
	        	        int nBytesToRead = reader.available();
	        	        if(nBytesToRead > 0) {
	        	            byte[] bytes = new byte[nBytesToRead];
	        	            reader.read(bytes);
	        	            result = new String(bytes);
	        	        }
	        	        //System.out.println(result);
	        	        String[] e_keys = result.split(",");
	        	        ck = e_keys[0];
	        	        SECRET_KEY = e_keys[1];
	                } catch (IOException r) {
	                    System.out.println("An error occurred.");
	                    r.printStackTrace();
	                  }
	        	    SwingUtilities.updateComponentTreeUI(frame);
	        	}
	        });
	        
	        sv.addActionListener(e ->
	        {
	        	JFrame parentFrame = new JFrame();
	        	 
	        	JFileChooser fileChooser = new JFileChooser();
	        	fileChooser.setDialogTitle("Save a record");   
	        	 
	        	int userSelection = fileChooser.showSaveDialog(parentFrame);
	        	 
	        	if (userSelection == JFileChooser.APPROVE_OPTION) {
	        	    File fileToSave = fileChooser.getSelectedFile();
	        	    //System.out.println("Save as file: " + fileToSave.getAbsolutePath());
	        	    stf = "";
	            	try {
	        	  	  	StringBuilder ivst = new StringBuilder();
	        	  	  	for (int i = 0; i < 16; i++) {
	        	  		  ivst.append(iv[i]);
	        	  		  if (i < 15)
	        	  			ivst.append(",");
	        	  		}
	        	  	  //System.out.println(ivst.toString());
	        	  	  String ir = "";
	            		String str = ivst.toString();
	            		char[] ch = str.toCharArray();
	            		for(int i=0;i<ch.length;i++){ 
	            			if((int)ch[i] != 0) {
	            			int b = ((int)ch[i])/16;
	            			int s = ((int)ch[i])%16;
	  	            	  	Integer intObject = Integer.valueOf(Forward_S_Box[b][s]);
	  	            	  	ir += (String.format("%02x", intObject));
	            			}
	            			else {
	      	            	  Integer c = Integer.valueOf(Forward_S_Box[0][0]);
	    	            	  ir += (String.format("%02x", c));
	            			}

	            		}
	                    while(ir.length()%8 != 0){
	                        ir += "63";
	                        }
	                        //System.out.println(ir);
	                        //System.out.println("Length of a String is: " + ir.length());
	                        char[] iarr = new char[ir.length()];
	                        
	                        // Copy character by character into array
	                        for (int i = 0; i < ir.length(); i++) {
	                        	iarr[i] = ir.charAt(i);
	                        	//System.out.println(iarr[i]);
	                        }
	                  
	                        // Printing content of array
	                        /*for (char c : iarr) {
	                            System.out.println(c);
	                        }
	                        */
	                        int al = iarr.length;
	                        int curr = 0;
	                        while(curr < al) {
	                        	ctostr(iarr, curr);
	                        	curr += 8;
	                        }
	                        String eiv = stf;
	                        stf = "";
	            		String ir2 = "";
	            		String str2 = SALTVALUE;
	            		char[] ch2 = str2.toCharArray();
	            		for(int i=0;i<ch2.length;i++){ 
	            			if((int)ch2[i] != 0) {
	            			int b = ((int)ch2[i])/16;
	            			int s = ((int)ch2[i])%16;
	  	            	  	Integer intObject = Integer.valueOf(Forward_S_Box[b][s]);
	  	            	  	ir2 += (String.format("%02x", intObject));
	            			}
	            			else {
	      	            	  Integer c = Integer.valueOf(Forward_S_Box[0][0]);
	    	            	  ir2 += (String.format("%02x", c));
	            			}

	            		}
	                    while(ir2.length()%8 != 0){
	                        ir2 += "63";
	                        }
	                        //System.out.println(ir);
	                        //System.out.println("Length of a String is: " + ir.length());
	                        char[] iarr2 = new char[ir2.length()];
	                        
	                        // Copy character by character into array
	                        for (int i = 0; i < ir2.length(); i++) {
	                        	iarr2[i] = ir2.charAt(i);
	                        	//System.out.println(iarr[i]);
	                        }
	                  
	                        // Printing content of array
	                        /*for (char c : iarr) {
	                            System.out.println(c);
	                        }
	                        */
	                        int al2 = iarr2.length;
	                        int curr2 = 0;
	                        while(curr2 < al2) {
	                        	ctostr(iarr2, curr2);
	                        	curr2 += 8;
	                        }
	                        String enc_slt = stf;
	                        stf = "";
	            		String ir1 = "";
	            		String str1 = pane.getText();
	            		char[] ch1 = str1.toCharArray();
	            		for(int i=0;i<ch1.length;i++){ 
	            			if((int)ch1[i] != 0) {
	            			int b = ((int)ch1[i])/16;
	            			int s = ((int)ch1[i])%16;
	  	            	  	Integer intObject = Integer.valueOf(Forward_S_Box[b][s]);
	  	            	  	ir1 += (String.format("%02x", intObject));
	            			}
	            			else {
	      	            	  Integer c = Integer.valueOf(Forward_S_Box[0][0]);
	    	            	  ir1 += (String.format("%02x", c));
	            			}

	            		}
	                    while(ir1.length()%8 != 0){
	                        ir1 += "63";
	                        }
	                        //System.out.println(ir);
	                        //System.out.println("Length of a String is: " + ir.length());
	                        char[] iarr1 = new char[ir1.length()];
	                        
	                        // Copy character by character into array
	                        for (int i = 0; i < ir1.length(); i++) {
	                        	iarr1[i] = ir1.charAt(i);
	                        	//System.out.println(iarr[i]);
	                        }
	                  
	                        // Printing content of array
	                        /*for (char c : iarr) {
	                            System.out.println(c);
	                        }
	                        */
	                        int al1 = iarr1.length;
	                        int curr1 = 0;
	                        while(curr1 < al1) {
	                        	ctostr(iarr1, curr1);
	                        	curr1 += 8;
	                        }
	            		FileWriter myWriter = new FileWriter(fileToSave.getAbsolutePath());
	                    myWriter.write(eiv + "," + enc_slt + "," +encrypt_AES(stf)); // replace it later and remove this comment
	                    myWriter.close();
	                    //System.out.println("Successfully wrote to the file.");
	          	  	  	SecureRandom numb1 = new SecureRandom();
	          	  	  	for (int i = 0; i < 16; i++) {
	        	  		  	iv[i]= (byte) numb1.nextInt(256); 
	          	  	  	}
	                  } catch (IOException q) {
	                    System.out.println("An error occurred.");
	                    q.printStackTrace();
	                  }
	        	}

	        });

	    }

}