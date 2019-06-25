package ssl

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type Certificates struct {
	CA         []byte
	CAKey      []byte
	ServerCert []byte
	ServerKey  []byte
	ClientCert []byte
	ClientKey  []byte
}

// TODO: optionally skip certificates if they exist on path and still valid

func GimmeCertificates(opts *Options) (*Certificates, *Files, error) {
	if err := opts.normalize(); err != nil {
		return nil, nil, errors.Wrap(err, "invalid Options")
	}

	var result Certificates

	if err := result.createCA(opts); err != nil {
		return nil, nil, err
	}
	if err := result.createServerCert(opts); err != nil {
		return nil, nil, err
	}
	if err := result.createClientCert(opts); err != nil {
		return nil, nil, err
	}

	if opts.WriteToFiles == nil {
		return &result, nil, nil
	}

	files, err := result.WriteToFiles(opts.WriteToFiles)
	return &result, files, err
}

func x509Template(opts *Options) (*x509.Certificate, error) {
	now := time.Now()
	notBefore := now.Add(-opts.ValidSince)
	notAfter := notBefore.Add(opts.ValidFor)

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}

	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{opts.Org}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		BasicConstraintsValid: true,
	}, nil
}

func (certs *Certificates) createCA(opts *Options) error {
	log.Info("creating CA certificate")

	template, err := x509Template(opts)
	if err != nil {
		return errors.Wrap(err, "could not geterate CA certificate")
	}

	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageCertSign
	template.KeyUsage |= x509.KeyUsageKeyEncipherment
	template.KeyUsage |= x509.KeyUsageKeyAgreement

	rsaKey, err := rsa.GenerateKey(rand.Reader, opts.Bits)
	if err != nil {
		return errors.Wrap(err, "could not generate RSA key pair")
	}

	caKey := x509.MarshalPKCS1PrivateKey(rsaKey)
	certs.CAKey = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: caKey})

	caCert, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		return errors.Wrap(err, "could not generate CA certificate")
	}
	certs.CA = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert})

	return nil
}

func (certs *Certificates) createServerCert(opts *Options) error {
	log.Info("creating server certificate")

	template, err := x509Template(opts)
	if err != nil {
		return errors.Wrap(err, "could not generate server certificate")
	}

	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	for _, host := range opts.Hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}

	keyPair, err := tls.X509KeyPair(certs.CA, certs.CAKey)
	if err != nil {
		return err
	}

	caCert, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return err
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, opts.Bits)
	if err != nil {
		return errors.Wrap(err, "could not generate RSA key pair")
	}

	serverKey := x509.MarshalPKCS1PrivateKey(rsaKey)
	certs.ServerKey = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: serverKey})

	serverCert, err := x509.CreateCertificate(rand.Reader, template, caCert, &rsaKey.PublicKey, keyPair.PrivateKey)
	if err != nil {
		return errors.Wrap(err, "could not generate server certificate")
	}
	certs.ServerCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert})

	return nil
}

func (certs *Certificates) createClientCert(opts *Options) error {
	log.Info("creating client certificate")

	template, err := x509Template(opts)
	if err != nil {
		return errors.Wrap(err, "could not generate client certificate")
	}

	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	template.KeyUsage = x509.KeyUsageDigitalSignature

	keyPair, err := tls.X509KeyPair(certs.CA, certs.CAKey)
	if err != nil {
		return err
	}

	caCert, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return err
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, opts.Bits)
	if err != nil {
		return errors.Wrap(err, "could not generate RSA key pair")
	}

	clientKey := x509.MarshalPKCS1PrivateKey(rsaKey)
	certs.ClientKey = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: clientKey})

	clientCert, err := x509.CreateCertificate(rand.Reader, template, caCert, &rsaKey.PublicKey, keyPair.PrivateKey)
	if err != nil {
		return errors.Wrap(err, "could not generate client certificate")
	}
	certs.ClientCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCert})

	return nil
}
