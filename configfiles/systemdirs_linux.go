// +build !windows,!darwin

package configfiles

import (
	"os/user"
	"path/filepath"
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
	return []string{"/etc"}
}
