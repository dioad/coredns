//go:build darwin

package bind

import (
	"testing"
)

func TestSetupDarwin(t *testing.T) {
	for i, test := range []testStruct{
		{`bind 1.2.3.4 lo0`, []string{"1.2.3.4", "127.0.0.1", "::1"}, false},
		{"bind lo0 {\nexcept 127.0.0.1\n}\n", []string{"::1"}, false},
	} {
		testHelper(t, test, i)
	}
}
