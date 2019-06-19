package ssl

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
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
	certs.CAKey = x509.MarshalPKCS1PrivateKey(rsaKey)

	certs.CA, err = x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		return errors.Wrap(err, "could not generate CA certificate")
	}

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

	caCert, err := x509.ParseCertificate(certs.CA)
	if err != nil {
		return err
	}

	caKey, err := x509.ParsePKCS1PrivateKey(certs.CAKey)
	if err != nil {
		return err
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, opts.Bits)
	if err != nil {
		return errors.Wrap(err, "could not generate RSA key pair")
	}
	certs.ServerKey = x509.MarshalPKCS1PrivateKey(rsaKey)

	certs.ServerCert, err = x509.CreateCertificate(rand.Reader, template, caCert, &rsaKey.PublicKey, caKey)
	if err != nil {
		return errors.Wrap(err, "could not generate server certificate")
	}

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

	caCert, err := x509.ParseCertificate(certs.CA)
	if err != nil {
		return err
	}

	caKey, err := x509.ParsePKCS1PrivateKey(certs.CAKey)
	if err != nil {
		return err
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, opts.Bits)
	if err != nil {
		return errors.Wrap(err, "could not generate RSA key pair")
	}
	certs.ClientKey = x509.MarshalPKCS1PrivateKey(rsaKey)

	certs.ClientCert, err = x509.CreateCertificate(rand.Reader, template, caCert, &rsaKey.PublicKey, caKey)
	if err != nil {
		return errors.Wrap(err, "could not generate client certificate")
	}

	return nil
}
