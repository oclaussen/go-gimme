// +build windows

package configfiles

import (
	"os"
	"os/user"
	"path/filepath"
)

const (
	envProgramData = "PROGRAMDATA"
	envAppData     = "APPDATA"
)

func getUserDirectories(name string) []string {
	user, err := user.Current()
	if err != nil {
		return []string{}
	}
	if user.HomeDir == "" {
		return []string{}
	}
	return []string{
		user.HomeDir,
		filepath.Join(user.HomeDir, "."+name),
	}
}

func getSystemDirectories() []string {
	var directories []string
	if programData := os.Getenv(envProgramData); programData != "" {
		direcories = append(directories, programData)
	}
	if appData := os.Getenv(envAppData); appData != "" {
		directories = append(directories, appData)
	}
	return directories
}
