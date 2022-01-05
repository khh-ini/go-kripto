package main

import (
	"bytes"
	"crypto"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net/http"

	"github.com/gorilla/mux"
)

type JsonPrivateKey struct {
	PublicKey rsa.PublicKey `json:"PublicKey"`
	D         *big.Int      `json:"D"`
	Primes    []*big.Int    `json:"Primes"`
}

type JsonPublicKey struct {
	N *big.Int `json:"N"`
	E int      `json:"E"`
}

type Page struct {
	Title string
	Data  []byte
}

type RSAPage struct {
	Page
	PrivateKey string
	PublicKey  string
	CipherText string
	PlainText  string
	Visibility string
}

type DESPage struct {
	Page
	Key        string
	CipherText string
	PlainText  string
}

var templates = template.Must(template.ParseGlob("template/*.html"))

func RsaGenerateKey() (string, string) {
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	rsaPublicKey := rsaPrivateKey.PublicKey

	jsonPub := &JsonPublicKey{N: rsaPublicKey.N, E: rsaPublicKey.E}
	jsonPri := &JsonPrivateKey{PublicKey: rsaPrivateKey.PublicKey, D: rsaPrivateKey.D, Primes: rsaPrivateKey.Primes}

	pubJson, _ := json.Marshal(jsonPub)
	priJson, _ := json.Marshal(jsonPri)

	return string(pubJson), string(priJson)
}

func RsaEncryptMessage(pub JsonPublicKey, message string) string {
	publicKey := rsa.PublicKey{N: pub.N, E: pub.E}
	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		&publicKey,
		[]byte(message),
		nil)
	if err != nil {
		log.Fatal(err)
	}
	return hex.EncodeToString(encryptedBytes)
}

func RsaDecryptMessage(pri JsonPrivateKey, ciphertext string) string {
	privateKey := rsa.PrivateKey{PublicKey: pri.PublicKey, D: pri.D, Primes: pri.Primes}
	cipherBytes, err := hex.DecodeString(ciphertext)
	if err != nil {
		fmt.Println("Unable to convert hex to byte. ", err)
	}
	decryptedBytes, err := privateKey.Decrypt(nil, cipherBytes, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		panic(err)
	}
	return string(decryptedBytes)
}

func ZeroPadding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(ciphertext, padtext...)
}

func ZeroUnPadding(origData []byte) []byte {
	return bytes.TrimFunc(origData,
		func(r rune) bool {
			return r == rune(0)
		})
}

func DesEncrypt(src, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	src = ZeroPadding(src, bs)
	// src = PKCS5Padding(src, bs)
	if len(src)%bs != 0 {
		return nil, errors.New("Need a multiple of the blocksize")
	}
	out := make([]byte, len(src))
	dst := out
	for len(src) > 0 {
		block.Encrypt(dst, src[:bs])
		src = src[bs:]
		dst = dst[bs:]
	}
	return out, nil
}

func DesDecrypt(src, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(src))
	dst := out
	bs := block.BlockSize()
	if len(src)%bs != 0 {
		return nil, errors.New("crypto/cipher: input not full blocks")
	}
	for len(src) > 0 {
		block.Decrypt(dst, src[:bs])
		src = src[bs:]
		dst = dst[bs:]
	}
	out = ZeroUnPadding(out)
	// out = PKCS5UnPadding(out)
	return out, nil
}

func main() {

	r := mux.NewRouter()
	fs := http.FileServer(http.Dir("assets/"))
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fs))

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data := Page{
			Title: "Home",
		}
		templates.ExecuteTemplate(w, "index.html", data)
	})

	r.HandleFunc("/rsa/", func(w http.ResponseWriter, r *http.Request) {
		data := RSAPage{
			Page:       Page{Title: "RSA"},
			Visibility: "invisible",
		}
		templates.ExecuteTemplate(w, "rsa.html", data)
	})

	r.HandleFunc("/rsa/keyGenerator", func(w http.ResponseWriter, r *http.Request) {
		pubKey, priKey := RsaGenerateKey()

		data := RSAPage{
			Page:       Page{Title: "RSA"},
			PrivateKey: priKey,
			PublicKey:  pubKey,
			Visibility: "visible",
		}

		templates.ExecuteTemplate(w, "rsa.html", data)
	})

	r.HandleFunc("/rsa/Encrypt", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			templates.ExecuteTemplate(w, "rsa.html", nil)
			return
		}

		data := RSAPage{
			Page:       Page{Title: "RSA"},
			PlainText:  r.FormValue("plaintext"),
			Visibility: "invisible",
		}
		var PublicKey JsonPublicKey
		json.Unmarshal([]byte(r.FormValue("publickey")), &PublicKey)
		data.CipherText = RsaEncryptMessage(PublicKey, data.PlainText)

		templates.ExecuteTemplate(w, "rsa.html", data)

	})

	r.HandleFunc("/rsa/Decrypt", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			templates.ExecuteTemplate(w, "rsa.html", nil)
			return
		}

		data := RSAPage{
			Page:       Page{Title: "RSA"},
			Visibility: "invisible",
		}
		var PrivateKey JsonPrivateKey
		json.Unmarshal([]byte(r.FormValue("privatekey")), &PrivateKey)
		data.PlainText = RsaDecryptMessage(PrivateKey, r.FormValue("ciphertext"))

		templates.ExecuteTemplate(w, "rsa.html", data)

	})

	r.HandleFunc("/des/", func(w http.ResponseWriter, r *http.Request) {
		data := DESPage{
			Page: Page{Title: "DES"},
		}
		templates.ExecuteTemplate(w, "des.html", data)
	})

	r.HandleFunc("/des/Encrypt", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			templates.ExecuteTemplate(w, "rsa.html", nil)
			return
		}

		data := DESPage{
			Page: Page{Title: "DES"},
			Key:  r.FormValue("key"),
		}

		PlainText := r.FormValue("plaintext")
		cipherText, err := DesEncrypt([]byte(PlainText), []byte(data.Key))
		if err != nil {
			fmt.Print(err)
		}

		data.CipherText = hex.EncodeToString(cipherText)

		templates.ExecuteTemplate(w, "des.html", data)
	})

	r.HandleFunc("/des/Decrypt", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			templates.ExecuteTemplate(w, "rsa.html", nil)
			return
		}

		data := DESPage{
			Page: Page{Title: "DES"},
			Key:  r.FormValue("key"),
		}

		CipherText, _ := hex.DecodeString(r.FormValue("ciphertext"))
		plaintext, err := DesDecrypt(CipherText, []byte(data.Key))
		if err != nil {
			fmt.Print(err)
		}

		data.PlainText = string(plaintext)

		templates.ExecuteTemplate(w, "des.html", data)
	})

	http.ListenAndServe(":80", r)

}
