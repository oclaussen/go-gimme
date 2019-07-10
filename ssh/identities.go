package ssh

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

func GimmeIdentities(opts *Options) []ssh.Signer {
	opts.normalize()

	signers := []ssh.Signer{}
	for _, pattern := range opts.IdentityFileGlobs {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			// Bad glob pattern -> TODO: warn user?
			continue
		}

		for _, file := range matches {
			signer, err := parseIdentityFile(file, !opts.NonInteractive)
			if err != nil {
				// TODO: warn user about unusable key file?
				continue
			}
			signers = append(signers, signer)
		}
	}
	return signers
}

func parseIdentityFile(path string, interactive bool) (ssh.Signer, error) {
	buffer, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.Wrap(err, "unreadable file")
	}

	pemData, _ := pem.Decode(buffer)
	if pemData == nil {
		return nil, errors.New("not a pem file")
	}

	// TODO: sort encrypted files to the end
	if strings.Contains(pemData.Headers["Proc-Type"], "ENCRYPTED") {
		if !interactive {
			return nil, errors.Wrap(err, "can not decrypt key")
		}
		fmt.Printf("Passphrase for %s: ", path)
		passphrase, err := terminal.ReadPassword(syscall.Stdin)
		fmt.Printf("\n")
		if err != nil {
			return nil, err // User skipped?
		}
		signer, err := ssh.ParsePrivateKeyWithPassphrase(buffer, passphrase)
		if err != nil {
			// TODO: might be wrong passphrase - retry a few times
			return nil, errors.Wrap(err, "could not read key")
		}
		return signer, nil
	}

	signer, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil, errors.Wrap(err, "can not read key")
	}
	return signer, nil
}
