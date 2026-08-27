package service

import (
	"testing"

	"github.com/ShifdLabs/shifd-identity-service/repository"
)

func TestNormalizeEventType(t *testing.T) {
	cases := map[string]string{
		repository.EventLogin:       repository.EventLogin,
		repository.EventLoginFailed: repository.EventLoginFailed,
		"":                          "",
		"logout":                    "",
		"LOGIN":                     "",
		"login' OR 1=1 --":          "",
	}
	for input, want := range cases {
		if got := normalizeEventType(input); got != want {
			t.Errorf("normalizeEventType(%q) = %q, want %q", input, got, want)
		}
	}
}
