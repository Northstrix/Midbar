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
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"image/color"

	"gioui.org/app"
	"gioui.org/font"
	"gioui.org/font/gofont"
	"gioui.org/io/event"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/paint"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

type ButtonStyle struct {
	Text         string
	Color        color.NRGBA
	Font         font.Font
	TextSize     unit.Sp
	Background   color.NRGBA
	CornerRadius unit.Dp
	Inset        layout.Inset
	Clickable    *widget.Clickable
}

var (
	stringForData string
	decTag        string
	decract       int
)

func main() {
	go func() {
		w := app.NewWindow(app.Size(unit.Dp(540), unit.Dp(310)))
		w.Option(
			app.Title("Midbar | מדבר"),
			app.Size(unit.Dp(540), unit.Dp(310)),
		)
		if err := loop(w); err != nil {
			panic(err)
		}
	}()
	app.Main()
}

func loop(w *app.Window) error {
	th := material.NewTheme()
	th.Shaper = text.NewShaper(text.WithCollection(gofont.Collection()))

	// Define custom colors
	foregroundColor := color.NRGBA{R: 0xEE, G: 0xEE, B: 0xEE, A: 0xFF}
	//backgroundColor := color.NRGBA{R: 0x10, G: 0x10, B: 0x10, A: 0xFF}
	buttonbackgroundColor := color.NRGBA{R: 0x1F, G: 0x6A, B: 0xA5, A: 0xFF}
	hintColor := color.NRGBA{R: 0xAA, G: 0xAA, B: 0xAA, A: 0xFF}

	// Declare widgets
	var input, key, output, lbl widget.Editor
	var encryptButton, decryptButton widget.Clickable

	input.SetText("")
	key.SetText("")
	output.SetText("")
	lbl.SetText("")
	events := make(chan event.Event)
	acks := make(chan struct{})

	go func() {
		for {
			ev := w.NextEvent()
			events <- ev
			<-acks
			if _, ok := ev.(app.DestroyEvent); ok {
				return
			}
		}
	}()

	var ops op.Ops

	for {
		select {
		case e := <-events:
			switch e := e.(type) {
			case app.DestroyEvent:
				return e.Err
			case app.FrameEvent:
				gtx := app.NewContext(&ops, e)

				if encryptButton.Clicked(gtx) {
					encryptData(&input, &key, &output, &lbl)
				}
				if decryptButton.Clicked(gtx) {
					decryptData(&input, &key, &output, &lbl)
				}
				// Draw background
				fillColor := color.NRGBA{R: 32, G: 32, B: 32, A: 255}
				paint.Fill(gtx.Ops, fillColor)

				// Layout UI
				layout.Flex{
					Alignment: layout.Middle,
					Axis:      layout.Vertical,
					Spacing:   12,
				}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Inset{
							Top:    unit.Dp(14),
							Bottom: unit.Dp(16),
						}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							lbl := material.Label(th, unit.Sp(16), "AES-256 CBC Encryption Software For Midbar Teensy 4.1 V3.1")
							lbl.Alignment = text.Middle
							lbl.Color = foregroundColor
							return lbl.Layout(gtx)
						})
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						editor := material.Editor(th, &input, "Input")
						editor.Color = foregroundColor
						editor.HintColor = hintColor
						editor.Editor.SingleLine = true
						editor.Editor.Alignment = text.Middle
						return layout.UniformInset(unit.Dp(12)).Layout(gtx, editor.Layout)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						editor := material.Editor(th, &key, "Key")
						editor.Color = foregroundColor
						editor.HintColor = hintColor
						editor.Editor.SingleLine = true
						editor.Editor.Alignment = text.Middle
						return layout.UniformInset(unit.Dp(12)).Layout(gtx, editor.Layout)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						editor := material.Editor(th, &output, "Output")
						editor.Color = foregroundColor
						editor.HintColor = hintColor
						editor.Editor.SingleLine = true
						editor.Editor.Alignment = text.Middle
						editor.Editor.ReadOnly = true
						return layout.UniformInset(unit.Dp(12)).Layout(gtx, editor.Layout)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									btn := material.Button(th, &encryptButton, "Encrypt")
									btn.Color = foregroundColor
									btn.Background = buttonbackgroundColor
									return layout.UniformInset(unit.Dp(12)).Layout(gtx, btn.Layout)
								}),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									btn := material.Button(th, &decryptButton, "Decrypt")
									btn.Color = foregroundColor
									btn.Background = buttonbackgroundColor
									return layout.UniformInset(unit.Dp(12)).Layout(gtx, btn.Layout)
								}),
							)
						})
					}),

					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						editor := material.Editor(th, &lbl, "")
						editor.Color = foregroundColor
						editor.HintColor = hintColor
						editor.Editor.SingleLine = true
						editor.Editor.Alignment = text.Middle
						editor.Editor.ReadOnly = true
						return layout.UniformInset(unit.Dp(12)).Layout(gtx, editor.Layout)
					}),
				)

				e.Frame(gtx.Ops)

				// Reset ops before the next frame
				ops.Reset()
			}
			acks <- struct{}{}
		}
	}
}

func encryptData(input, key, output, lbl *widget.Editor) {
	keyValue := key.Text()
	hashedKey := sha512.Sum512([]byte(keyValue))
	aesKey := hashedKey[32:]
	//fmt.Printf("AES Key (hex): %x\n", aesKey)
	hmacKey := hashedKey[:32]
	//fmt.Printf("HMAC Key (hex): %x\n", hmacKey)
	message := []byte(input.Text())
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(message)
	tag := mac.Sum(nil)
	//fmt.Printf("Tag (hex): %x\n", tag)
	encryptStringWithAESInCBC(input.Text(), tag, aesKey)
	output.SetText(stringForData)
	lbl.SetText("")
}

func encryptAESECB(plaintext, aesKey []byte) []byte {

	// Create the AES cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		panic(err)
	}

	// Encrypt the plaintext using AES-ECB
	ciphertext := make([]byte, len(plaintext))
	block.Encrypt(ciphertext, plaintext)

	// Return the hex-encoded ciphertext
	return ciphertext
}

func decryptAESECB(ciphertext, aesKey []byte) []byte {

	// Create the AES cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		panic(err)
	}

	// Decrypt the ciphertext using AES-ECB
	plaintext := make([]byte, len(ciphertext))
	block.Decrypt(plaintext, ciphertext)

	// Return the plaintext
	return plaintext
}

func encryptStringWithAESInCBC(inputString string, tag, aesKey []byte) {
	//fmt.Printf("Input (ASCII): %s\n", inputString)
	//fmt.Printf("AES Key (hex): %x\n", aesKey)
	//fmt.Printf("Tag (hex): %x\n", tag)
	stringForData = ""
	decract = 0
	iv := make([]byte, 16)
	arrayForCBCMode := make([]byte, 16)

	// Fill the iv array with random bytes
	_, err := rand.Read(iv)
	if err != nil {
		fmt.Println("Error generating random IV:", err)
		return
	}

	//fmt.Printf("Randomly Generated IV: %x\n", iv)
	encrypted_iv := encryptAESECB(iv, aesKey)
	//fmt.Printf("Encrypted IV: %x\n", encrypted_iv)
	copy(arrayForCBCMode, iv)
	//fmt.Printf("arrayForCBCMode content: %x\n", arrayForCBCMode)
	stringForData += hex.EncodeToString(encrypted_iv)
	aesKey = incAESKey(aesKey)

	array1 := tag[:16]
	array2 := tag[16:]
	for i := range 16 {
		array1[i] ^= arrayForCBCMode[i]
	}
	//fmt.Printf("Array1 (hex): %x\n", array1)
	ciphertext1 := encryptAESECB(array1, aesKey)
	stringForData += hex.EncodeToString(ciphertext1)
	copy(arrayForCBCMode, ciphertext1)
	aesKey = incAESKey(aesKey)
	for i := range 16 {
		array2[i] ^= arrayForCBCMode[i]
	}
	ciphertext2 := encryptAESECB(array2, aesKey)
	stringForData += hex.EncodeToString(ciphertext2)
	copy(arrayForCBCMode, ciphertext2)
	aesKey = incAESKey(aesKey)

	paddedLength := (len(inputString) + 15) / 16 * 16
	paddedString := inputString + string(make([]byte, paddedLength-len(inputString)))
	byteArrays := make([][]byte, paddedLength/16)
	for i := range byteArrays {
		byteArrays[i] = []byte(paddedString[i*16 : (i+1)*16])
	}
	for _, byteArray := range byteArrays {
		//fmt.Printf("Array (hex): %x\n", byteArray)
		for i := range 16 {
			byteArray[i] ^= arrayForCBCMode[i]
		}
		ciphertext := encryptAESECB(byteArray, aesKey)
		stringForData += hex.EncodeToString(ciphertext)
		copy(arrayForCBCMode, ciphertext)
		aesKey = incAESKey(aesKey)
	}
}

func decryptStringWithAESInCBC(cipherTextHex string, aesKey []byte) {
	clearVariables()
	stringForData = ""
	arrayForCBCMode := make([]byte, 16)
	p := 0
	decract = -1

	cipherText, _ := hex.DecodeString(cipherTextHex)
	for len(cipherText) > p {
		res := make([]byte, 16)
		prevRes := make([]byte, 16)
		br := false
		for i := range res {
			if i+p >= len(cipherText) {
				br = true
				break
			}
			res[i] = cipherText[i+p]
		}
		if len(cipherText)-p >= 16 {
			for i := range prevRes {
				if i+p-16 >= 0 {
					prevRes[i] = cipherText[i+p-16]
				}
			}
		} else {
			copy(prevRes, arrayForCBCMode)
		}
		if !br {
			if decract > 16 {
				copy(arrayForCBCMode, prevRes)
			}
			res = decryptAESECB(res, aesKey)
			aesKey = incAESKey(aesKey)
			if decract > 2 {
				for i := range res {
					res[i] ^= arrayForCBCMode[i]
				}
				if decract < 22 {
					decTag += hex.EncodeToString(res)
				} else {
					stringForData += string(bytes.TrimRight(res, "\x00"))
				}
			}
			if decract == -1 {
				copy(arrayForCBCMode, res)
			}
			decract++
		}

		p += 16
		decract += 10
	}
}

func incAESKey(aesKey []byte) []byte {
	i := 15
	for i >= 0 {
		if aesKey[i] == 255 {
			aesKey[i] = 0
			i--
		} else {
			aesKey[i]++
			break
		}
	}
	return aesKey
}

func clearVariables() {
	decract = 0
	decTag = ""
	stringForData = ""
}

func decryptData(input, key, output, lbl *widget.Editor) {
	keyValue := key.Text()
	hashedKey := sha512.Sum512([]byte(keyValue))
	aesKey := hashedKey[32:]
	//fmt.Printf("AES Key (hex): %x\n", aesKey)
	hmacKey := hashedKey[:32]
	//fmt.Printf("HMAC Key (hex): %x\n", hmacKey)
	decryptStringWithAESInCBC(input.Text(), aesKey)
	message := []byte(stringForData)
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(message)
	tag := mac.Sum(nil)
	//fmt.Println(hex.EncodeToString(tag))
	//fmt.Println(decTag)
	if hex.EncodeToString(tag) == decTag {
		lbl.SetText("Integrity Verified Successfully!")
	} else {
		lbl.SetText("Integrity Verification Failed!!!")
	}
	output.SetText(stringForData)
}
