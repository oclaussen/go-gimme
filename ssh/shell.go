package ssh

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

func GimmeShell(opts *Options) error {
	client, err := GimmeClient(opts)
	if err != nil {
		return err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	stdin := int(os.Stdin.Fd())
	inState, err := terminal.MakeRaw(stdin)
	if err != nil {
		return err
	}
	defer terminal.Restore(stdin, inState)

	stdout := int(os.Stdout.Fd())
	outState, err := terminal.MakeRaw(stdout)
	if err != nil {
		return err
	}
	defer terminal.Restore(stdout, outState)

	width, height, _ := terminal.GetSize(stdin)
	if err := session.RequestPty("xterm", height, width, ssh.TerminalModes{}); err != nil {
		return err
	}

	resizeChannel := make(chan os.Signal, 1)
	signal.Notify(resizeChannel, syscall.SIGWINCH)
	go func() {
		for range resizeChannel {
			if width, height, err := terminal.GetSize(stdin); err == nil {
				session.WindowChange(height, width)
			}
		}
	}()

	if err := session.Shell(); err != nil {
		return err
	}

	if err := session.Wait(); err != nil {
		return err
	}

	return nil
}
