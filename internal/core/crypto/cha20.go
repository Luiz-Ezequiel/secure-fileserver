package crypto

import (
	"errors"

	"golang.org/x/crypto/chacha20"
)

// AESHandler implementa EncryptionHandler usando AES no modo GCM.
type Cha20Handler struct {
}

func (crypt Cha20Handler) Encrypt(plaintext, key []byte) (ciphertext []byte, err error) {
	// Cria um nonce com 24 bytes para ter quase infinitas possibilidades de nonce
	nonce, err := createNonce(24) 
	if err != nil {
		return nil, err
	}

	// Cria uma subchave com a chave e 16 bytes do nonce e guarda os ultimos 8 bytes para ser o nonce de encriptação
	newKey, err := chacha20.HChaCha20(key, nonce[:16])
	subNonce := nonce[16:]
	if err != nil {
		return nil, err
	}

	// Cria a cifra com a chave fornecida e nonce
	cipher, err := chacha20.NewUnauthenticatedCipher(newKey, subNonce)
	if err != nil {
		return nil, err
	}
	
	// Cria o ciphertext do tamanho do plaintext e encripta usando a cifra
	ciphertext = make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, plaintext)


	return append(nonce, ciphertext...), nil
}

func (crypt Cha20Handler) Decrypt(ciphertext, key []byte) (plaintext []byte, err error){
	// Separa o nonce do texto criptografado
	if len(ciphertext) < 24 {
		return nil, errors.New("ciphertext muito curto")
	}
	nonce := ciphertext[:24] 		 
	ciphertext = ciphertext[24:]

	// Cria uma subchave com a chave e 16 bytes do nonce e guarda os ultimos 8 bytes para ser o nonce de encriptação
	newKey, err := chacha20.HChaCha20(key, nonce[:16])
	subNonce := nonce[16:]
	if err != nil {
		return nil, err
	}

	// Cria a cifra com a chave fornecida e nonce
	cipher, err := chacha20.NewUnauthenticatedCipher(newKey, subNonce)
	if err != nil {
		return nil, err
	}

	// Cria o plaintext do tamanho do cyphertext e dencripta usando a cifra
	plaintext = make([]byte, len(ciphertext))
	cipher.XORKeyStream(plaintext, ciphertext)


	return plaintext, nil

}
