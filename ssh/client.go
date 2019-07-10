package ssh

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
)

func GimmeClient(opts *Options) (*ssh.Client, error) {
	opts.normalize()

	if opts.Host == "" {
		return nil, errors.New("no target host specified")
	}

	// If a password is explicitly given, try that first because it is likely to succeed
	if opts.Password != "" {
		auth := ssh.Password(opts.Password)
		if client, err := tryConnect(auth, opts); err == nil {
			return client, nil
		}
	}

	// If there is an SSH agent running, spent a whole list on that because
	// we don't know yet how many keys might be in there
	if conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		auth := ssh.PublicKeysCallback(agent.NewClient(conn).Signers)
		if client, err := tryConnect(auth, opts); err == nil {
			return client, nil
		}
	}

	// There might be a lot of keys, so we split these up in chunks that
	// hopefully don't exceed the max tries on server side
	signers := GimmeIdentities(opts)
	for i := 0; i < len(signers); i += opts.MaxAuthTries {
		end := min(i+opts.MaxAuthTries, len(signers))
		auth := ssh.PublicKeys(signers[i:end]...)
		if client, err := tryConnect(auth, opts); err == nil {
			return client, nil
		}
	}

	// Add interactive auth as last resort, if possible
	if !opts.NonInteractive {
		auth := ssh.KeyboardInteractive(handleInteractiveChallenge)
		client, err := tryConnect(auth, opts)
		if err == nil {
			return client, nil
		}
	}

	return nil, errors.New("could not connect, all auth methods tried")
}

func tryConnect(auth ssh.AuthMethod, opts *Options) (*ssh.Client, error) {
	return ssh.Dial(
		"tcp",
		net.JoinHostPort(opts.Host, strconv.Itoa(opts.Port)),
		&ssh.ClientConfig{
			User: opts.User,
			Auth: []ssh.AuthMethod{auth},
			HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
				return nil // TODO handle host key callback
			},
		},
	)
}

func handleInteractiveChallenge(user string, instructions string, questions []string, echos []bool) ([]string, error) {
	if user != "" {
		fmt.Printf("%v", user)
	}
	if instructions != "" {
		fmt.Printf("%s", instructions)
	}
	answers := make([]string, len(questions))
	for i, question := range questions {
		fmt.Printf("%s", question)
		answer, err := terminal.ReadPassword(syscall.Stdin)
		if err != nil {
			return answers, err
		}
		fmt.Printf("\n")
		answers[i] = string(answer)
	}
	return answers, nil
}

func min(a int, b int) int {
	if a <= b {
		return a
	}
	return b
}
