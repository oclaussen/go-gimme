package ssh

import (
	"fmt"
	"io"
	"os"
	"path"
	"sync"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

type Executor struct {
	client *ssh.Client
	Stderr io.Writer
}

func GimmeExecutor(opts *Options) (*Executor, error) {
	client, err := GimmeClient(opts)
	if err != nil {
		return nil, err
	}
	return &Executor{client: client, Stderr: os.Stderr}, nil
}

func (executor *Executor) Close() error {
	return executor.client.Close()
}

func (executor *Executor) forwardStderr(session *ssh.Session) {
	reader, err := session.StderrPipe()

	if err != nil {
		fmt.Fprintf(executor.Stderr, "error: %v", err)
		return
	}
	if _, err := io.Copy(executor.Stderr, reader); err != nil {
		fmt.Fprintf(executor.Stderr, "error: %v", err)
		return
	}
}

func (executor *Executor) Execute(cmd string) (string, error) {
	session, err := executor.client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	go executor.forwardStderr(session)

	output, err := session.Output(cmd)
	return string(output), err
}

func (executor *Executor) WriteFile(opts *FileOptions) error {
	session, err := executor.client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	go executor.forwardStderr(session)

	errCh := make(chan error, 2)
	wait := sync.WaitGroup{}
	wait.Add(2)

	go func() {
		defer wait.Done()

		writer, err := session.StdinPipe()
		if err != nil {
			errCh <- err
			return
		}
		defer writer.Close()

		if _, err := fmt.Fprintln(writer, fmt.Sprintf("C%#o", opts.Mode.Perm()), opts.Size, path.Base(opts.Path)); err != nil {
			errCh <- err
			return
		}

		if _, err := io.Copy(writer, opts.Reader); err != nil {
			errCh <- err
			return
		}

		if _, err := fmt.Fprint(writer, "\x00"); err != nil {
			errCh <- err
			return
		}
	}()

	go func() {
		defer wait.Done()
		if out, err := session.CombinedOutput(fmt.Sprintf("scp -qt %s", path.Dir(opts.Path))); err != nil {
			errCh <- errors.Wrap(err, string(out))
			return
		}
	}()

	wait.Wait()

	close(errCh)
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}
