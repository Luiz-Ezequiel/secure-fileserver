package main

import (
	"crypto"
	"fmt"
)

type EncryptionHandler interface{
	Encrypt(data []byte, key []byte) ([]byte, error)
	Decrypt(data []byte, key []byte) ([]byte, error)
}

type AESGCMHandler struct {

}

// func (crypt AESGCMHandler) Encrypt(key, text []byte) (cyphertext []byte, err error){

// }

func main(){
	fmt.Println(crypto.SHA1)
}