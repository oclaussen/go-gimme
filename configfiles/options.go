package configfiles

import (
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type Options struct {
	Name                      string
	Extensions                []string
	FileGlobs                 []string
	UseFileGlobsOnly          bool
	IncludeWorkingDirectories bool
	Filter                    func(*ConfigFile) bool
}

func (opts *Options) normalize() error {
	if len(opts.Name) == 0 && len(opts.FileGlobs) == 0 {
		return errors.New("either Name or FileGlobs are required")
	}

	if len(opts.Name) > 0 && len(opts.Extensions) == 0 {
		if ext := filepath.Ext(opts.Name); len(ext) > 0 {
			opts.Extensions = []string{ext}
			opts.Name = strings.TrimSuffix(opts.Name, ext)
		}
	}

	if opts.UseFileGlobsOnly && len(opts.FileGlobs) == 0 {
		log.Warn("will ignore UseFileGlobsOnly because no FileGlobs were specified")
		opts.UseFileGlobsOnly = false
	}

	if opts.Filter == nil {
		opts.Filter = func(_ *ConfigFile) bool { return true }
	}

	return nil
}
