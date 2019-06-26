package ssl

import (
	"time"

	"github.com/pkg/errors"
)

type Options struct {
	Hosts        []string
	Bits         int
	Org          string
	ValidSince   time.Duration
	ValidFor     time.Duration
	WriteToFiles *Files
}

func (opts *Options) normalize() error {
	if len(opts.Org) == 0 {
		return errors.New("org is required")
	}

	if len(opts.Hosts) == 0 {
		opts.Hosts = append(opts.Hosts, "localhost", "127.0.0.1")
	}

	if opts.Bits == 0 {
		opts.Bits = 2048
	}
	if opts.ValidSince == 0 {
		opts.ValidSince = 5 * time.Minute
	}
	if opts.ValidFor == 0 {
		opts.ValidFor = 24 * 365 * time.Hour
	}

	if opts.WriteToFiles != nil {
		if err := opts.WriteToFiles.normalize(); err != nil {
			return err
		}
	}

	return nil
}
