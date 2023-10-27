package packager

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/virusdefender/goutils/errors"
	"math/big"
	"os"
	"time"
)

func GenerateRoot() (*rsa.PrivateKey, *x509.Certificate, error) {
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() - 10),
		Subject: pkix.Name{
			CommonName: "Packager Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(30, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generate key")
	}
	rootCertificateBytes, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootPrivateKey.PublicKey, rootPrivateKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "create cert")
	}
	rootCertificate, err := x509.ParseCertificate(rootCertificateBytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "parse cert")
	}
	return rootPrivateKey, rootCertificate, nil
}

func GenerateEnd(commonName string, rootPrivateKey *rsa.PrivateKey, rootCertificate *x509.Certificate) (*rsa.PrivateKey, *x509.Certificate, error) {
	endTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		BasicConstraintsValid: false,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	endPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generate key")
	}

	endCertificateBytes, err := x509.CreateCertificate(rand.Reader, endTemplate, rootCertificate, &endPrivateKey.PublicKey, rootPrivateKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "create cert")
	}
	endCertificate, err := x509.ParseCertificate(endCertificateBytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "parse cert")
	}
	return endPrivateKey, endCertificate, nil
}

func LoadKeyAndCertificateFromFile(keyPath string, certPath string) (*rsa.PrivateKey, *x509.Certificate, error) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "read key")
	}
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "read cert")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "parse key")
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "parse cert")
	}
	return key, cert, nil
}

func DumpKeyAndCertificateToFile(keyPath string, certPath string, key *rsa.PrivateKey, cert *x509.Certificate) error {
	err := os.WriteFile(keyPath, x509.MarshalPKCS1PrivateKey(key), 0600)
	if err != nil {
		return errors.Wrap(err, "write key")
	}
	err = os.WriteFile(certPath, cert.Raw, 0644)
	if err != nil {
		return errors.Wrap(err, "write cert")
	}
	return nil
}
