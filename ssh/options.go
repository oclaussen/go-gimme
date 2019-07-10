package ssh

import (
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh/terminal"
)

const (
	defaultPort         = 22
	defaultMaxAuthTries = 6
)

type Options struct {
	Host              string
	Port              int
	User              string
	Password          string
	IdentityFileGlobs []string
	MaxAuthTries      int
	NonInteractive    bool
}

func (opts *Options) normalize() {
	// TODO: parse ~/.ssh/config for hints
	userHost := strings.SplitN(opts.Host, "@", 2)
	if len(userHost) > 1 {
		opts.Host = userHost[1]
	}
	if opts.User == "" {
		if len(userHost) > 1 {
			opts.User = userHost[0]
		} else if user, err := user.Current(); err == nil {
			opts.User = user.Username
		}
	}

	host, port, err := net.SplitHostPort(opts.Host)
	if err == nil {
		opts.Host = host
	}
	if opts.Port == 0 {
		if p, convErr := strconv.Atoi(port); err == nil && convErr == nil {
			opts.Port = p
		} else {
			opts.Port = defaultPort
		}
	}

	if len(opts.IdentityFileGlobs) == 0 {
		if user, err := user.Current(); err == nil {
			identityFile := filepath.Join(user.HomeDir, ".ssh", "id_rsa")
			if _, err := os.Stat(identityFile); err == nil {
				opts.IdentityFileGlobs = append(opts.IdentityFileGlobs, identityFile)
			}
			identityFiles := filepath.Join(user.HomeDir, ".ssh", "*")
			opts.IdentityFileGlobs = append(opts.IdentityFileGlobs, identityFiles)
		}
	}

	if opts.MaxAuthTries == 0 {
		opts.MaxAuthTries = defaultMaxAuthTries
	}

	if !opts.NonInteractive {
		opts.NonInteractive = !terminal.IsTerminal(int(os.Stdin.Fd()))
	}
}
