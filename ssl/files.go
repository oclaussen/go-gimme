package ssl

import (
	"encoding/pem"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

type Files struct {
	Directory      string
	CAFile         string
	CAKeyFile      string
	ServerCertFile string
	ServerKeyFile  string
	ClientCertFile string
	ClientKeyFile  string
}

func (files *Files) normalize() error {
	if len(files.Directory) == 0 {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		files.Directory = wd
	}
	if len(files.CAFile) == 0 {
		files.CAFile = "ca.pem"
	}
	if !filepath.IsAbs(files.CAFile) {
		files.CAFile = filepath.Join(files.Directory, files.CAFile)
	}
	if len(files.CAKeyFile) == 0 {
		files.CAKeyFile = "ca-key.pem"
	}
	if !filepath.IsAbs(files.CAKeyFile) {
		files.CAKeyFile = filepath.Join(files.Directory, files.CAKeyFile)
	}
	if len(files.ServerCertFile) == 0 {
		files.ServerCertFile = "server.pem"
	}
	if !filepath.IsAbs(files.ServerCertFile) {
		files.ServerCertFile = filepath.Join(files.Directory, files.ServerCertFile)
	}
	if len(files.ServerKeyFile) == 0 {
		files.ServerKeyFile = "server-key.pem"
	}
	if !filepath.IsAbs(files.ServerKeyFile) {
		files.ServerKeyFile = filepath.Join(files.Directory, files.ServerKeyFile)
	}
	if len(files.ClientCertFile) == 0 {
		files.ClientCertFile = "client.pem"
	}
	if !filepath.IsAbs(files.ClientCertFile) {
		files.ClientCertFile = filepath.Join(files.Directory, files.ClientCertFile)
	}
	if len(files.ClientKeyFile) == 0 {
		files.ClientKeyFile = "client-key.pem"
	}
	if !filepath.IsAbs(files.ClientKeyFile) {
		files.ClientKeyFile = filepath.Join(files.Directory, files.ClientKeyFile)
	}
	return nil
}

func (certs *Certificates) WriteToFiles(files *Files) (*Files, error) {
	if err := files.normalize(); err != nil {
		return files, err
	}
	if err := writeCertificate(files.CAFile, certs.CA); err != nil {
		return files, err
	}
	if err := writeKey(files.CAKeyFile, certs.CAKey); err != nil {
		return files, err
	}
	if err := writeCertificate(files.ServerCertFile, certs.ServerCert); err != nil {
		return files, err
	}
	if err := writeKey(files.ServerKeyFile, certs.ServerKey); err != nil {
		return files, err
	}
	if err := writeCertificate(files.ClientCertFile, certs.ClientCert); err != nil {
		return files, err
	}
	if err := writeKey(files.ClientKeyFile, certs.ClientKey); err != nil {
		return files, err
	}
	return files, nil
}

func writeCertificate(path string, content []byte) error {
	file, err := os.Create(path)
	if err != nil {
		return errors.Wrap(err, "could not write to file")
	}
	defer file.Close()
	if err := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: content}); err != nil {
		return err
	}
	return nil
}

func writeKey(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return errors.Wrap(err, "could not write to file")
	}
	defer file.Close()
	if err := pem.Encode(file, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: content}); err != nil {
		return err
	}
	return nil
}
