package ssh

import (
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
