//go:build linux

package bind

import (
	"testing"
)

func TestSetupLinux(t *testing.T) {
	for i, test := range []testStruct{
		{`bind 1.2.3.4 lo`, []string{"1.2.3.4", "127.0.0.1", "::1"}, false},
		{"bind lo {\nexcept 127.0.0.1\n}\n", []string{"::1"}, false},
	} {
		testHelper(t, test, i)
	}
}
