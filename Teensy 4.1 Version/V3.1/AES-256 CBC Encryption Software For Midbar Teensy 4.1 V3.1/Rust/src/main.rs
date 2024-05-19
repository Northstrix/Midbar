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
use druid::widget::{Align, Button, Flex, Label, TextBox};
use druid::{AppLauncher, Color, Data, Lens, Widget, WidgetExt, WindowDesc};

use rand::{RngCore, thread_rng};
use aes::Aes256;
use aes::cipher::{
    BlockDecrypt, BlockEncrypt, KeyInit
};

use hmac::{Hmac, Mac, NewMac};
use sha2::{Sha512, Sha256, Digest}; 
use lazy_static::lazy_static;
use generic_array::GenericArray;
use std::sync::Mutex;
use hex::FromHex;

const WINDOW_WIDTH: f64 = 726.0;
const WINDOW_HEIGHT: f64 = 637.0;
const CONTAINER_WIDTH: f64 = 500.0;
const FIELD_WIDTH: f64 = 440.0;
const CONTAINER_HEIGHT: f64 = 427.0;
const BACKGROUND_COLOR: Color = Color::grey8(238);
const CONTAINER_COLOR: Color = Color::rgb8(36, 36, 36);

lazy_static! {
    static ref STRING_FOR_DATA: Mutex<String> = Mutex::new(String::new());
    static ref DEC_TAG: Mutex<String> = Mutex::new(String::new());
    static ref DECRACT: Mutex<i32> = Mutex::new(0);
    static ref STRING_FOR_CBC_MODE: Mutex<String> = Mutex::new(String::new());
}

#[derive(Clone, Data, Lens)]
struct AppState {
    input_text: String,
    key_text: String,
    output_text: String,
    info_text: String,
}

impl AppState {
    fn new() -> Self {
        AppState {
            input_text: String::new(),
            key_text: String::new(),
            output_text: String::new(),
            info_text: String::new(),
        }
    }
}

fn incr_aes_key(mut encryption_key: Vec<u8>) -> Vec<u8> {
    let mut i = 15;
    while i > 0 {
        if encryption_key[i] == 255 {
            encryption_key[i] = 0;
            i -= 1;
        } else {
            encryption_key[i] += 1;
            break;
        }
    }
    encryption_key
}

fn clear_variables() {
    let mut string_for_data = STRING_FOR_DATA.lock().unwrap();
    let mut dec_tag = DEC_TAG.lock().unwrap();
    let mut decract = DECRACT.lock().unwrap();
    let mut string_for_cbc_mode = STRING_FOR_CBC_MODE.lock().unwrap();

    *string_for_data = String::new();
    *dec_tag = String::new();
    *decract = 0;
    *string_for_cbc_mode = String::new();
}

fn encrypt_string_with_aes_in_cbc(input_string: String, tag: String, mut encryption_key: Vec<u8>) {
    clear_variables();
    let mut rng = thread_rng();
    let mut iv = [0u8; 16];
    rng.fill_bytes(&mut iv);

    encrypt_iv_for_aes(&iv, &encryption_key);
    encryption_key = incr_aes_key(encryption_key.clone());

    let byte_array = hex::decode(tag).unwrap();
    let array1 = &byte_array[..16];
    let array2 = &byte_array[16..32];

    encrypt_with_aes(array1, &encryption_key);
    encryption_key = incr_aes_key(encryption_key.clone());
    encrypt_with_aes(array2, &encryption_key);
    encryption_key = incr_aes_key(encryption_key.clone());

    let input_bytes: Vec<u8> = input_string.as_bytes().to_vec();
    let padded_length = ((input_bytes.len() + 15) / 16) * 16;
    let mut padded_bytes = input_bytes.clone();
    padded_bytes.resize(padded_length, 0);

    let byte_arrays: Vec<Vec<u8>> = (0..padded_bytes.len())
        .step_by(16)
        .map(|i| padded_bytes[i..i + 16].to_vec())
        .collect();

    for byte_array in byte_arrays.iter() {
        encrypt_with_aes(byte_array, &encryption_key);
        encryption_key = incr_aes_key(encryption_key.clone());
    }
}

fn encrypt_iv_for_aes(iv: &[u8], encryption_key: &[u8]) {
    let hex_iv = hex::encode(iv);
    {
        let mut string_for_cbc_mode = STRING_FOR_CBC_MODE.lock().unwrap();
        *string_for_cbc_mode = String::from(hex_iv);
        //println!("IV: {}", *string_for_cbc_mode);
    }
    encrypt_with_aes(iv, encryption_key);
}

fn encrypt_with_aes(to_be_encrypted: &[u8], encryption_key: &[u8]) {
    // Create a mutable copy of the input slice
    let mut to_be_encrypted = to_be_encrypted.to_vec();

    //print_hex_string("Plaintext block", &to_be_encrypted);
    //print_hex_string("Encryption key", &encryption_key);
    
    {
        let mut string_for_cbc_mode = STRING_FOR_CBC_MODE.lock().unwrap();
        // Convert the hex string to Vec<u8>
        let array_for_cbc_mode = Vec::from_hex(&*string_for_cbc_mode).expect("Invalid hex in STRING_FOR_CBC_MODE");
        

            let mut decract = DECRACT.lock().unwrap();
            if *decract > 0 {
                for i in 0..16 {
                    to_be_encrypted[i] ^= array_for_cbc_mode[i];
                }
            }
            //print_hex_string("Unencrypted block", &to_be_encrypted);
            let cipher = Aes256::new(GenericArray::from_slice(&encryption_key));
            //let mut array_for_ciphertext = GenericArray::from_slice(&to_be_encrypted);
            let mut array_for_cipher  = GenericArray::from([42u8; 16]);
            array_for_cipher.copy_from_slice(to_be_encrypted.as_slice());
            cipher.encrypt_block(&mut array_for_cipher);
            let hex_string_cipher = hex::encode(array_for_cipher.as_slice());
            //println!("Encrypted block: {}", hex_string_cipher);
            if *decract > 0 {
                *string_for_cbc_mode = String::from(hex_string_cipher.clone());
            }
            let mut string_for_data = STRING_FOR_DATA.lock().unwrap();
            string_for_data.push_str(&hex_string_cipher);
            *decract += 11;
    }
}

fn decrypt_string_with_aes_in_cbc(ct: String, mut decryption_key: Vec<u8>) {
    clear_variables();
    let ct_bytes = hex::decode(ct).expect("Invalid hexadecimal string");
    let mut decract = -1;
    for chunk in ct_bytes.chunks(16) {
        //println!("{:?} {}", chunk, decract);
        decrypt_block(chunk, decryption_key.clone(), decract);
        decryption_key = incr_aes_key(decryption_key.clone());
        decract += 11;
    }
}

fn decrypt_block(block_for_cipher: &[u8], decryption_key: Vec<u8>, mut decract: i32) {
    //println!("block_for_cipher: {:?}", block_for_cipher);
    //println!("decryption_key: {:?}", decryption_key);
    //println!("decract: {}", decract);
    // Create a mutable copy of the input slice
    let mut block_for_cipher = block_for_cipher.to_vec();

    //print_hex_string("Plaintext block", &block_for_cipher);
    //print_hex_string("Encryption key", &encryption_key);
    
    {
        let mut string_for_cbc_mode = STRING_FOR_CBC_MODE.lock().unwrap();
        let array_for_cbc_mode = Vec::from_hex(&*string_for_cbc_mode).expect("Invalid hex in STRING_FOR_CBC_MODE");
        
            //print_hex_string("Enncrypted block", &block_for_cipher);
            let cipher = Aes256::new(GenericArray::from_slice(&decryption_key));
            //let mut array_for_ciphertext = GenericArray::from_slice(&block_for_cipher);
            let mut array_for_cipher  = GenericArray::from([42u8; 16]);
            array_for_cipher.copy_from_slice(block_for_cipher.as_slice());
            cipher.decrypt_block(&mut array_for_cipher);
            //print_hex_string("Decrypted block (before XOR)", &array_for_cipher);
            if decract == -1 {
                *string_for_cbc_mode = hex::encode(array_for_cipher.as_slice());
            }
            else{
                for i in 0..16 {
                    array_for_cipher[i] ^= array_for_cbc_mode[i];
                }
                if decract > 21{
                    let mut string_for_data = STRING_FOR_DATA.lock().unwrap();
                    for byte in array_for_cipher {
                        if byte > 0 {
                            string_for_data.push(byte as char);
                        }
                    }
                }
                else{
                    let hex_string_cipher = hex::encode(array_for_cipher.as_slice());
                    let mut dec_tag = DEC_TAG.lock().unwrap();
                    dec_tag.push_str(&hex_string_cipher);
                }
                //print_hex_string("Decrypted block", &array_for_cipher);
                if decract > 6 {
                    *string_for_cbc_mode = String::from(hex::encode(block_for_cipher));
                }
            }
    }
}

fn print_hex_string(inscription: &str, data: &[u8]) {
    let hex_string = hex::encode(data);
    println!("{}: {}", inscription, hex_string);
}

fn main() {
    let main_window = WindowDesc::new(build_ui())
        .window_size((WINDOW_WIDTH, WINDOW_HEIGHT))
        .title("Midbar | מדבר");

    AppLauncher::with_window(main_window)
        .launch(AppState::new())
        .expect("Failed to launch application");
}

fn build_ui() -> impl Widget<AppState> {
    let input_label = Label::new("AES-256 CBC Encryption Software For Midbar Teensy 4.1 V3.1")
        .with_text_size(16.0)
        .padding((0.0, 24.0, 0.0, 10.0)); // Add padding: (left, top, right, bottom)

    let input_label_text = Label::new("Input").with_text_size(16.0)
        .padding((0.0, 0.0, 0.0, 6.0));
    let input_entry = TextBox::new()
        .with_placeholder("Paste the input")
        .with_text_size(16.0)
        .lens(AppState::input_text)
        .fix_width(FIELD_WIDTH);

    let key_label_text = Label::new("Key").with_text_size(16.0)
        .padding((0.0, 12.0, 0.0, 6.0));
    let key_entry = TextBox::new()
        .with_placeholder("Enter the key")
        .with_text_size(16.0)
        .lens(AppState::key_text)
        .fix_width(FIELD_WIDTH);

    let output_label_text = Label::new("Output").with_text_size(16.0)
        .padding((0.0, 12.0, 0.0, 6.0));
    let output_entry = TextBox::new()
        .with_placeholder("Output will appear here")
        .with_text_size(16.0)
        .lens(AppState::output_text)
        .fix_width(FIELD_WIDTH);

        let info_label_text = Label::new(|data: &AppState, _: &_| data.info_text.clone())
        .with_text_size(16.0)
        .padding((0.0, 0.0, 0.0, 0.0));

    let custom_button = |text: &str| {
        Button::from_label(
            Label::new(text)
                .with_text_size(16.0)
        )
        .fix_height(36.0)
        .fix_width(96.0)
        .padding((0.0, 16.0, 0.0, 20.0))
        .expand_width()
    };

    let encrypt_button = custom_button("Encrypt").on_click(|_, data: &mut AppState, _| {
        let mut hasher = Sha512::new();
        hasher.update(data.key_text.to_string());
        let result = hasher.finalize();
        let hash_hex = format!("{:x}", result);
        let (first_half, second_half) = hash_hex.split_at(hash_hex.len() / 2);    
        let hmac_key_bytes = Vec::from_hex(first_half).expect("Invalid hex in first half");
        let aes_key_bytes = Vec::from_hex(second_half).expect("Invalid hex in second half");
        let mut mac = Hmac::<Sha256>::new_varkey(&hmac_key_bytes).expect("HMAC can take key of any size");
        mac.update(data.input_text.as_bytes());
        let result = mac.finalize();
        let code_bytes = result.into_bytes();
        encrypt_string_with_aes_in_cbc(data.input_text.clone(), hex::encode(code_bytes), aes_key_bytes);
        {
            let string_for_data = STRING_FOR_DATA.lock().unwrap();
            data.output_text = string_for_data.to_string();
        }
        data.info_text = "".to_string();
    });

    let decrypt_button = custom_button("Decrypt").on_click(|_, data: &mut AppState, _| {
        let mut hasher = Sha512::new();
        hasher.update(data.key_text.to_string());
        let result = hasher.finalize();
        let hash_hex = format!("{:x}", result);
        let (first_half, second_half) = hash_hex.split_at(hash_hex.len() / 2);    
        let hmac_key_bytes = Vec::from_hex(first_half).expect("Invalid hex in first half");
        let aes_key_bytes = Vec::from_hex(second_half).expect("Invalid hex in second half");
        if data.input_text.clone().is_empty() || data.input_text.clone().len() % 32 != 0 {
            data.info_text = "Ciphertext length must be a multiple of 32".to_string();
        } else {
            if hex::decode(data.input_text.clone()).is_err(){
                data.info_text = "The ciphertext must be hex encoded".to_string();
            }
            else{
                data.info_text = "".to_string();
                decrypt_string_with_aes_in_cbc(data.input_text.clone(), aes_key_bytes);
                let string_for_data = STRING_FOR_DATA.lock().unwrap();
                let dec_tag = DEC_TAG.lock().unwrap();
                //println!("(Decrypted) Plaintext: {}", *string_for_data);
                //println!("Decrypted Tag: {}", *dec_tag);
                let mut mac = Hmac::<Sha256>::new_varkey(&hmac_key_bytes).expect("HMAC can take key of any size");
                mac.update(string_for_data.as_bytes());
                let result = mac.finalize();
                let code_bytes = result.into_bytes();
                //println!("Computed Tag: {}", hex::encode(code_bytes));
                data.output_text = string_for_data.to_string();
                if *dec_tag == hex::encode(code_bytes){
                    data.info_text = "Integrity Verified Successfully!".to_string();           
                }
                else{
                    data.info_text = "Integrity Verification Failed!!!".to_string();  
                }
            }
        }
    });

    let container = Flex::column()
        .with_child(input_label)
        .with_spacer(5.0)
        .with_child(
            Flex::column()
                .with_child(input_label_text)
                .with_child(input_entry)
                .with_child(key_label_text)
                .with_child(key_entry)
                .with_child(output_label_text)
                .with_child(output_entry)
                .with_spacer(10.0)
                .with_child(
                    Flex::row()
                        .with_spacer(100.0)
                        .with_flex_child(encrypt_button, 1.0) // Use with_flex_child to ensure proper resizing
                        .with_spacer(10.0)
                        .with_flex_child(decrypt_button, 1.0) // Use with_flex_child to ensure proper resizing
                        .with_spacer(100.0),
                )
                .with_child(info_label_text)
                .with_spacer(24.0),
        )
        .background(CONTAINER_COLOR)
        .rounded(12.0)
        .padding(12.0)
        .fix_size(CONTAINER_WIDTH, CONTAINER_HEIGHT);

    Align::centered(container)
        .background(BACKGROUND_COLOR)
        .fix_size(WINDOW_WIDTH, WINDOW_HEIGHT)
}