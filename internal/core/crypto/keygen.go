package crypto

import "crypto/rand"

type AESKeyGenerator struct{}

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