## How to signed pdf file with p12 with golang?

1. First, you need to install the gofpdf library. You can do this by running the following command:
```
go get github.com/jung-kurt/gofpdf
```

2. Next, you need to read the P12 certificate and the PDF file that you want to sign. You can do this using the ioutil library:
3. Then, you can use the gofpdf library to create a new PDF document and add the PDF data that you read in step 2 to it:
4. Now you can use the pkcs12 package to parse the P12 certificate and extract the private key and certificate from it:
```
p12Block, _ := pkcs12.ToPEM(p12Data, "password")

var pemData []byte
for {
    var pemBlock *pem.Block
    pemBlock, pemData = pem.Decode(p12Block)
    if pemBlock == nil {
        break
    }
    if pemBlock.Type == "CERTIFICATE" {
        cert, err := x509.ParseCertificate(pemBlock.Bytes)
        if err != nil {
            panic(err)
        }
        // Do something with the certificate
    } else if pemBlock.Type == "PRIVATE KEY" {
        key, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
        if err != nil {
            panic(err)
        }
        // Do something with the private key
    }
}
```
5. Finally, you can use the private key and certificate to sign the PDF document and save it to a file:
```
err = pdf.Sign(key, cert, time.Now(), "path/to/output.pdf")
if err != nil {
    panic(err)
}
```

## how to know who as a signer on pdf with p12 certificate?

1. First, you need to install the gofpdf library. You can do this by running the following command:
```
go get github.com/jung-kurt/gofpdf
```
2. Next, you need to read the PDF file that you want to check the signers for. You can do this using the ioutil library:
```
pdfData, err := ioutil.ReadFile("path/to/input.pdf")
if err != nil {
    panic(err)
}
```
3. Then, you can use the gofpdf library to create a new PDF document and add the PDF data that you read in step 2 to it:
```
pdf := gofpdf.New("P", "mm", "A4", "")
_, err = pdf.AddFont("Arial", "", "arial.json")
if err != nil {
    panic(err)
}

pdf.AddPage()
_, err = pdf.LoadPageContent(bytes.NewReader(pdfData))
if err != nil {
    panic(err)
}
```

4. Now you can use the pdf.GetSignatures function to get a list of all the signatures in the PDF document:
```
signatures, err := pdf.GetSignatures()
if err != nil {
    panic(err)
}
```
You can iterate through the list of signatures and get the signer's name and certificate for each signature:
```
for _, signature := range signatures {
    signerName := signature.Name
    signerCertificate := signature.Certificate
    // Do something with the signer's name and certificate
}
```

## How to check data on certificate p12?

To get the data from a P12 certificate in Go, you can use the pkcs12 package from the crypto/x509 library. Here is an example of how you can do it:

1. First, you need to read the P12 certificate file. You can do this using the ioutil library:
```
p12Data, err := ioutil.ReadFile("path/to/certificate.p12")
if err != nil {
    panic(err)
}
```

2. Then, you can use the pkcs12.ToPEM function to parse the P12 certificate and extract the private key and certificate from it:
```
p12Block, _ := pkcs12.ToPEM(p12Data, "password")

var pemData []byte
for {
    var pemBlock *pem.Block
    pemBlock, pemData = pem.Decode(p12Block)
    if pemBlock == nil {
        break
    }
    if pemBlock.Type == "CERTIFICATE" {
        cert, err := x509.ParseCertificate(pemBlock.Bytes)
        if err != nil {
            panic(err)
        }
        // Do something with the certificate
    } else if pemBlock.Type == "PRIVATE KEY" {
        key, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
        if err != nil {
            panic(err)
        }
        // Do something with the private key
    }
}
```

3. You can then use the x509.Certificate struct to access the data in the certificate. For example, you can get the subject name of the certificate like this:
```
subject := cert.Subject
```

4. The subject variable will be a pkix.Name struct, which has fields for the various components of the subject name (e.g. common name, organization, etc.). You can access these fields like this:
```
commonName := subject.CommonName
organization := subject.Organization
```
You can also get the issuer name of the certificate using the Issuer field of the x509.Certificate struct.


## how to generate certificate p12 with golang?
To generate a P12 certificate in Go, you can use the x509 package from the crypto/x509 library. Here is an example of how you can do it:

1. First, you need to create a private key. You can do this using the ecdsa or rsa package from the crypto library. For example, to create an ECDSA private key:
```
privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
if err != nil {
    panic(err)
}
```
To create an RSA private key:

```
privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
if err != nil {
    panic(err)
}
```
2. Next, you need to create a certificate template. You can do this using the x509.Certificate struct:
```
template := x509.Certificate{
    SerialNumber: big.NewInt(1),
    Subject: pkix.Name{
        CommonName:   "Test Certificate",
        Organization: []string{"Test Inc."},
    },
    NotBefore: time.Now(),
    NotAfter:  time.Now().Add(time.Hour * 24 * 365),

    KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
    ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
    BasicConstraintsValid: true,
}
```
3. You can then use the x509.CreateCertificate function to create a certificate based on the template and the private key:
```
derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
if err != nil {
    panic(err)
}
```
4. Finally, you can use the pkcs12 package to create a P12 certificate from the certificate and private key:
```
p12Data, err := pkcs12.Encode(derBytes, privateKey, "password")
if err != nil {
    panic(err)
}

// Save the P12 certificate to a file
err = ioutil.WriteFile("path/to/certificate.p12", p12Data, 0644)
if err != nil {
    panic(err)
}
```

## how to add certificate key to pdf files?

To add a certificate to a PDF file in Go, you can use the gofpdf library. Here is an example of how you can do it:

1. First, you need to install the gofpdf library. You can do this by running the following command:
```
go get github.com/jung-kurt/gofpdf
```

2. Next, you need to read the PDF file that you want to add the certificate to and the certificate itself. You can do this using the ioutil library:
```
pdfData, err := ioutil.ReadFile("path/to/input.pdf")
if err != nil {
    panic(err)
}

certData, err := ioutil.ReadFile("path/to/certificate.pem")
if err != nil {
    panic(err)
}
```

3. Then, you can use the gofpdf library to create a new PDF document and add the PDF data that you read in step 2 to it:
```
pdf := gofpdf.New("P", "mm", "A4", "")
_, err = pdf.AddFont("Arial", "", "arial.json")
if err != nil {
    panic(err)
}

pdf.AddPage()
_, err = pdf.LoadPageContent(bytes.NewReader(pdfData))
if err != nil {
    panic(err)
}
```
4. You can then use the pdf.AddCertificate function to add the certificate to the PDF document:
```
err = pdf.AddCertificate(certData)
if err != nil {
    panic(err)
}
```

5. Finally, you can save the PDF document to a file:
```
err = pdf.OutputFileAndClose("path/to/output.pdf")
if err != nil {
    panic(err)
}
```

## How to validate pdf file with digital signature and verification certificate key?

To validate a PDF file with a digital signature and a verification certificate in Go, you can use the gofpdf library. Here is an example of how you can do it:

1. First, you need to install the gofpdf library. You can do this by running the following command:
```
go get github.com/jung-kurt/gofpdf
```
2. Next, you need to read the PDF file that you want to validate and the verification certificate. You can do this using the ioutil library:
```
pdfData, err := ioutil.ReadFile("path/to/input.pdf")
if err != nil {
    panic(err)
}

certData, err := ioutil.ReadFile("path/to/certificate.pem")
if err != nil {
    panic(err)
}
```

3. Then, you can use the gofpdf library to create a new PDF document and add the PDF data that you read in step 2 to it:
```
pdf := gofpdf.New("P", "mm", "A4", "")
_, err = pdf.AddFont("Arial", "", "arial.json")
if err != nil {
    panic(err)
}

pdf.AddPage()
_, err = pdf.LoadPageContent(bytes.NewReader(pdfData))
if err != nil {
    panic(err)
}
```

4. You can then use the x509.ParseCertificate function from the crypto/x509 library to parse the verification certificate:
```
cert, err := x509.ParseCertificate(certData)
if err != nil {
    panic(err)
}
```

5. Now you can use the pdf.VerifySignature function to validate the signature in the PDF file:
```

valid, err := pdf.VerifySignature(cert)
if err != nil {
    panic(err)
}

if valid {
    fmt.Println("Signature is valid")
} else {
    fmt.Println("Signature is invalid")
}
```

or you can then use the pdf.GetCertificates function to get a list of all the certificates in the PDF document:
```
certificates, err := pdf.GetCertificates()
if err != nil {
    panic(err)
}

for _, certificateData := range certificates {
    cert, err := x509.ParseCertificate(certificateData)
    if err != nil {
        panic(err)
    }
    // Do something with the certificate
}
```
You can iterate through the list of certificates and use the x509.ParseCertificate function from the crypto/x509 library to parse each certificate.