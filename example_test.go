package ssh_config_test

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/alebeck/ssh_config"
)

func ExampleHost_Matches() {
	pat, _ := ssh_config.NewPattern("test.*.example.com")
	host := &ssh_config.Host{Patterns: []*ssh_config.Pattern{pat}}
	fmt.Println(host.Matches(ssh_config.NewMatchContext("test.stage.example.com", "")))
	fmt.Println(host.Matches(ssh_config.NewMatchContext("othersubdomain.example.com", "")))
	// Output:
	// true
	// false
}

func ExamplePattern() {
	pat, _ := ssh_config.NewPattern("*")
	host := &ssh_config.Host{Patterns: []*ssh_config.Pattern{pat}}
	fmt.Println(host.Matches(ssh_config.NewMatchContext("test.stage.example.com", "")))
	fmt.Println(host.Matches(ssh_config.NewMatchContext("othersubdomain.example.com", "")))
	// Output:
	// true
	// true
}

func ExampleDecode() {
	var config = `
Host *.example.com
  Compression yes
`

	cfg, _ := ssh_config.Decode(strings.NewReader(config))
	ctx := ssh_config.NewMatchContext("test.example.com", "")
	val, _ := cfg.Get("Compression", ctx)
	fmt.Println(val)
	// Output: yes
}

func ExampleDefault() {
	fmt.Println(ssh_config.Default("Port"))
	fmt.Println(ssh_config.Default("UnknownVar"))
	// Output:
	// 22
	//
}

func ExampleUserSettings_ConfigFinder() {
	// This can be used to test SSH config parsing.
	u := ssh_config.UserSettings{}
	u.ConfigFinder(func() string {
		return filepath.Join("testdata", "test_config")
	})
	u.Get("example.com", "Host", "")
}
