package bind

import (
	"testing"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
)

type testStruct struct {
	config   string
	expected []string
	failing  bool
}

func testHelper(t *testing.T, test testStruct, i int) {
	t.Helper()

	c := caddy.NewTestController("dns", test.config)
	err := setup(c)
	if err != nil {
		if !test.failing {
			t.Fatalf("Test %d, expected no errors, but got: %v", i, err)
		}
		return
	}
	if test.failing {
		t.Fatalf("Test %d, expected to failed but did not, returned values", i)
	}
	cfg := dnsserver.GetConfig(c)
	if len(cfg.ListenHosts) != len(test.expected) {
		t.Errorf("Test %d : expected the config's ListenHosts size to be %d, was %d", i, len(test.expected), len(cfg.ListenHosts))
		return
	}
	for i, v := range test.expected {
		if got, want := cfg.ListenHosts[i], v; got != want {
			t.Errorf("Test %d : expected the config's ListenHost to be %s, was %s", i, want, got)
		}
	}
}

func TestSetup(t *testing.T) {
	for i, test := range []testStruct{
		{`bind 1.2.3.4`, []string{"1.2.3.4"}, false},
		{`bind`, nil, true},
		{`bind 1.2.3.invalid`, nil, true},
		{`bind 1.2.3.4 ::5`, []string{"1.2.3.4", "::5"}, false},
		{`bind ::1 1.2.3.4 ::5 127.9.9.0`, []string{"::1", "1.2.3.4", "::5", "127.9.9.0"}, false},
		{`bind ::1 1.2.3.4 ::5 127.9.9.0 noone`, nil, true},
	} {
		testHelper(t, test, i)
	}
}
