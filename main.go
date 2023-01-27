package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io/ioutil"
	"math/big"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

func main() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	temp := x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "Ahmad Yunus Afghoni",
			Country:            []string{"ID", "Indonesia"},
			Province:           []string{"Jawa Timur"},
			Organization:       []string{"Ala Cipmta Media"},
			OrganizationalUnit: []string{"Product Dev"},
		},
		Issuer: pkix.Name{
			CommonName:         "Ghonijee",
			Country:            []string{"ID", "Indonesia"},
			Province:           []string{"Jawa Timur"},
			Organization:       []string{"Ala Cipta Media"},
			OrganizationalUnit: []string{"Product Dev"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365 * 5),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		SerialNumber: big.NewInt(1),
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &temp, &temp, &privateKey.PublicKey, privateKey)
	if err != nil {
		panic(err)
	}

	certificate, err := x509.ParseCertificate(derBytes)
	if err != nil {
		panic(err)
	}

	p12Data, err := pkcs12.Encode(rand.Reader, privateKey, certificate, nil, "password")
	if err != nil {
		panic(err)
	}

	err = ioutil.WriteFile("certificate.p12", p12Data, 0644)
	if err != nil {
		panic(err)
	}
}
