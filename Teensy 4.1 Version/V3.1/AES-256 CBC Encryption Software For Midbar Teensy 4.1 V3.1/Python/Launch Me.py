"""
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
Credit:
https://www.pexels.com/photo/gray-and-black-hive-printed-textile-691710/
https://github.com/nishantprj/custom_tkinter_login
"""
import tkinter as tk
from tkinter import *
import customtkinter
from PIL import ImageTk, Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import string
import numpy as np
import os
import time
import hmac
import hashlib
import secrets
from tkinter import messagebox
import textwrap
import random

customtkinter.set_appearance_mode("dark")  # Modes: system (default), light, dark
customtkinter.set_default_color_theme("blue")  # Themes: blue (default), dark-blue, green

string_for_data = ""
dec_tag = ""
array_for_CBC_mode = bytearray(16)
back_aes_key = bytearray(32)
decract = 0

aes_key = bytearray([
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
])

def back_aes_k():
    global back_aes_key
    back_aes_key = bytearray(aes_key)

def rest_aes_k():
    global aes_key
    aes_key = bytearray(back_aes_key)

def incr_aes_key():
    global aes_key
    i = 15
    while i >= 0:
        if aes_key[i] == 255:
            aes_key[i] = 0
            i -= 1
        else:
            aes_key[i] += 1
            break

def encrypt_iv_for_aes(iv):
    global array_for_CBC_mode
    array_for_CBC_mode = bytearray(iv)
    encrypt_with_aes(bytearray(iv))

def encrypt_with_aes(to_be_encrypted):
    global string_for_data
    global decract
    to_be_encrypted = bytearray(to_be_encrypted)  # Convert to mutable bytearray
    if decract > 0:
        for i in range(16):
            to_be_encrypted[i] ^= array_for_CBC_mode[i]
            
    cipher = AES.new(aes_key, AES.MODE_ECB)
    encrypted_data = cipher.encrypt(pad(to_be_encrypted, AES.block_size))
    incr_aes_key()
    if decract > 0:
        for i in range(16):
            if i < 16:
                array_for_CBC_mode[i] = int(encrypted_data[i])
    
    for i in range(16):
        if encrypted_data[i] < 16:
            string_for_data += "0"
        string_for_data += hex(encrypted_data[i])[2:]
    
    decract += 11
    
def decrypt_string_with_aes_in_cbc(ct):
    global decract
    global array_for_CBC_mode
    global string_for_data
    back_aes_k()
    clear_variables()
    ct_bytes = bytes.fromhex(ct)
    ext = 0
    decract = -1
    while len(ct) > ext:
        split_for_decr(ct_bytes, ext)
        ext += 16
        decract += 10

    rest_aes_k()

def split_for_decr(ct, p):
    global decract
    global array_for_CBC_mode
    global string_for_data
    global dec_tag

    res = bytearray(16)
    prev_res = bytearray(16)
    br = False

    for i in range(0, 16):
        if i + p > len(ct) - 1:
            br = True
            break
        res[i] = ct[i + p]

    for i in range(0, 16):
        if i + p - 16 > len(ct) - 1:
            break  # Skip if index is out of bounds
        prev_res[i] = ct[i + p - 16]

    if not br:
        if decract > 16:
            array_for_CBC_mode = prev_res[:]

        cipher_text = res
        ret_text = bytearray(16)

        cipher = AES.new(bytes(aes_key), AES.MODE_ECB)
        ret_text = bytearray(cipher.decrypt(bytes(cipher_text)))

        incr_aes_key()

        if decract > 2:
            for i in range(16):
                ret_text[i] ^= array_for_CBC_mode[i]
            if decract < 22:
                dec_tag += ''.join(format(byte, '02x') for byte in ret_text)
            if decract > 21:
                for byte in ret_text:
                    if byte > 0:
                        string_for_data += chr(byte)
                    
        if decract == -1:
            array_for_CBC_mode = ret_text[:]

        decract += 1

def clear_variables():
    global string_for_data
    global dec_tag
    global decract
    string_for_data = ""
    dec_tag = ""
    decract = 0

def encr_str_with_aes():
    global string_for_data
    global decract
    back_aes_k()
    string_for_data = ""
    decract = 0
    
    iv = [secrets.randbelow(256) for _ in range(16)]  # Initialization vector
    encrypt_iv_for_aes(iv)

def encrypt_string_with_aes_in_cbc(input_string, tag):
    global string_for_data
    global decract
    back_aes_k()
    string_for_data = ""
    decract = 0
    iv = [secrets.randbelow(256) for _ in range(16)]  # Initialization vector
    encrypt_iv_for_aes(iv)
    encrypt_hash_with_aes_in_cbc(tag)
    padded_length = (len(input_string) + 15) // 16 * 16
    padded_string = input_string.ljust(padded_length, '\x00')
    byte_arrays = [bytearray(padded_string[i:i+16], 'utf-8') for i in range(0, len(padded_string), 16)]
    
    for i, byte_array in enumerate(byte_arrays):
        encrypt_with_aes(byte_array)
    
    rest_aes_k()
    
def encrypt_hash_with_aes_in_cbc(tag):
    byte_array = bytearray.fromhex(tag)
    array1 = byte_array[:16]
    array2 = byte_array[16:32]
    encrypt_with_aes(array1)
    encrypt_with_aes(array2)
    
def encrypt():
    key_value = key_entry.get()  # Retrieve the text from the key entry
    hashed_key = hashlib.sha512(key_value.encode()).hexdigest()
    #print("Hashed Password:", hashed_key)    
    # Split the hashed password into two halves
    first_half = hashed_key[:64]
    hmac_key = bytes.fromhex(first_half)
    message = input_entry.get().encode('utf-8')
    tag = hmac.new(hmac_key, message, hashlib.sha256).hexdigest()
    second_half = hashed_key[64:]
    # Update the aes_key with the first half
    global aes_key
    aes_key = bytearray.fromhex(second_half)
    encrypt_string_with_aes_in_cbc(input_entry.get(), tag)  # Retrieve the input text
    output_entry.configure(state='normal')
    output_entry.delete(0, 'end')
    output_entry.insert(0, string_for_data)
    output_entry.configure(state='readonly')

def decrypt():
    key_value = key_entry.get()  # Retrieve the text from the key entry
    hashed_key = hashlib.sha512(key_value.encode()).hexdigest()
    #print("Hashed Password:", hashed_key)    
    # Split the hashed password into two halves
    first_half = hashed_key[:64]
    hmac_key = bytes.fromhex(first_half)
    second_half = hashed_key[64:]
    # Update the aes_key with the first half
    global aes_key
    aes_key = bytearray.fromhex(second_half)
    decrypt_string_with_aes_in_cbc(input_entry.get())  # Retrieve the input text
    message = string_for_data.encode('utf-8')
    tag = hmac.new(hmac_key, message, hashlib.sha256).hexdigest()
    if tag == dec_tag:
        messagebox.showinfo("Midbar | מדבר", "Integrity Verified Successfully!")
    else:
        messagebox.showinfo("Midbar | מדבר", "Integrity Verification Failed!!!")
    output_entry.configure(state='normal')
    output_entry.delete(0, 'end')
    output_entry.insert(0, string_for_data)
    output_entry.configure(state='readonly')

app = customtkinter.CTk()  # creating custom tkinter window
app.geometry("900x480")
app.title("Midbar | מדבר")
img1 = ImageTk.PhotoImage(Image.open("./assets/pattern.jpg"))
l1 = customtkinter.CTkLabel(master=app, image=img1)
l1.pack()

# creating custom frame
frame = customtkinter.CTkFrame(master=l1, width=500, height=220, corner_radius=15)
frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

input_label = customtkinter.CTkLabel(master=frame, text="AES-256 CBC Encryption Software For Midbar Teensy 4.1 V3.1", width=500, font=('Segoe UI Semibold', 16))
input_label.place(x=0, y=5)

input_label = customtkinter.CTkLabel(master=frame, text="Input", width=50, font=('Segoe UI Semibold', 16))
input_label.place(x=40, y=55)

global input_entry
input_entry = customtkinter.CTkEntry(master=frame, width=300, font=('Segoe UI Semibold', 16))
input_entry.place(x=100, y=55)

key_label = customtkinter.CTkLabel(master=frame, text="Key", width=50, font=('Segoe UI Semibold', 16))
key_label.place(x=40, y=90)

global key_entry
key_entry = customtkinter.CTkEntry(master=frame, width=300, font=('Segoe UI Semibold', 16), show="*")
key_entry.place(x=100, y=90)

output_label = customtkinter.CTkLabel(master=frame, text="Output", width=50, font=('Segoe UI Semibold', 16))
output_label.place(x=40, y=125)

global output_entry
output_entry = customtkinter.CTkEntry(master=frame, width=300, font=('Segoe UI Semibold', 16), state='readonly')
output_entry.place(x=100, y=125)

# Buttons positioned under the entries
encrypt_button = customtkinter.CTkButton(master=frame, width=94, text="Encrypt", corner_radius=6, command=encrypt)
encrypt_button.place(x=100, y=170)

decrypt_button = customtkinter.CTkButton(master=frame, width=94, text="Decrypt", corner_radius=6, command=decrypt)
decrypt_button.place(x=306, y=170)

app.mainloop()