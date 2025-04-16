package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
)

type AESKeyGenerator struct{}

type EDCHKeyPair struct {
	Private *ecdh.PrivateKey
	Public  *ecdh.PublicKey
}

func GenerateKeyPair() (*EDCHKeyPair, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &EDCHKeyPair{
		Private: priv,
		Public: priv.PublicKey(),
	}, nil
}


func DeriveSharedSecret(priv *ecdh.PrivateKey, peerPub *ecdh.PublicKey) ([]byte, error) {
    if priv == nil || peerPub == nil {
        return nil, errors.New("invalid keys")
    }
    return priv.ECDH(peerPub)
}

func (g *AESKeyGenerator) Generate() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

type Cha20KeyGenerator struct{}

func (g *Cha20KeyGenerator) Generate() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

type DESKeyGenerator struct{}

func (g *DESKeyGenerator) Generate() ([]byte, error) {
	key := make([]byte, 8)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}