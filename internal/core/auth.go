package core

import (
	"crypto/tls"
	"crypto/x509"
	"os"
)

func LoadServerCertificate(certPath, keyPath string) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(certPath, keyPath)
}

func LoadTrustedRootCert(path string) (*x509.CertPool, error) {
	rootPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(rootPEM)
	return roots, nil
}