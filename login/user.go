package login

import (
	"strings"
)

func IsValidUser() bool {
	return strings.ToLower("chinhnb") == "chinhnb"
}