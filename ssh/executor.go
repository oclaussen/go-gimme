package ssh

import (
	"fmt"
	"io"
	"path"
	"sync"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

type Executor struct {
	client *ssh.Client
}

func GimmeExecutor(opts *Options) (*Executor, error) {
	client, err := GimmeClient(opts)
	if err != nil {
		return nil, err
	}
	return &Executor{client: client}, nil
}

func (executor *Executor) Close() error {
	return executor.client.Close()
}

func (executor *Executor) Execute(cmd string) (string, error) {
	session, err := executor.client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	output, err := session.CombinedOutput(cmd)
	return string(output), err
}

func (executor *Executor) WriteFile(opts *FileOptions) error {
	session, err := executor.client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

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
