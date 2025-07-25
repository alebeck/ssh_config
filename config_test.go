package ssh_config

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func loadFile(t *testing.T, filename string) []byte {
	t.Helper()
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

var files = []string{
	"testdata/config1",
	"testdata/config2",
	"testdata/eol-comments",
}

func TestDecode(t *testing.T) {
	for _, filename := range files {
		data := loadFile(t, filename)
		cfg, err := Decode(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		out := cfg.String()
		if out != string(data) {
			t.Errorf("%s out != data: got:\n%s\nwant:\n%s\n", filename, out, string(data))
		}
	}
}

func testConfigFinder(filename string) func() string {
	return func() string { return filename }
}

func nullConfigFinder() string {
	return ""
}

func TestGet(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/config1"),
	}

	val := us.Get("wap", "User", "")
	if val != "root" {
		t.Errorf("expected to find User root, got %q", val)
	}
}

func TestGetWithDefault(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/config1"),
	}

	val, err := us.GetStrict("wap", "PasswordAuthentication", "")
	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if val != "yes" {
		t.Errorf("expected to get PasswordAuthentication yes, got %q", val)
	}
}

func TestGetAllWithDefault(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/config1"),
	}

	val, err := us.GetAllStrict("wap", "PasswordAuthentication", "")
	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if len(val) != 1 || val[0] != "yes" {
		t.Errorf("expected to get PasswordAuthentication yes, got %q", val)
	}
}

func TestGetIdentities(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/identities"),
	}

	val, err := us.GetAllStrict("hasidentity", "IdentityFile", "")
	if err != nil {
		t.Errorf("expected nil err, got %v", err)
	}
	if len(val) != 1 || val[0] != "file1" {
		t.Errorf(`expected ["file1"], got %v`, val)
	}

	val, err = us.GetAllStrict("has2identity", "IdentityFile", "")
	if err != nil {
		t.Errorf("expected nil err, got %v", err)
	}
	if len(val) != 2 || val[0] != "f1" || val[1] != "f2" {
		t.Errorf(`expected [\"f1\", \"f2\"], got %v`, val)
	}

	val, err = us.GetAllStrict("randomhost", "IdentityFile", "")
	if err != nil {
		t.Errorf("expected nil err, got %v", err)
	}
	if !reflect.DeepEqual(val, defaultProtocol2Identities) {
		t.Errorf("expected default protocol 2 identities %v, got %v", defaultProtocol2Identities, val)
	}
}

func TestGetInvalidPort(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/invalid-port"),
	}

	val, err := us.GetStrict("test.test", "Port", "")
	if err == nil {
		t.Fatalf("expected non-nil err, got nil")
	}
	if val != "" {
		t.Errorf("expected to get '' for val, got %q", val)
	}
	if err.Error() != `ssh_config: strconv.ParseUint: parsing "notanumber": invalid syntax` {
		t.Errorf("wrong error: got %v", err)
	}
}

func TestGetNotFoundNoDefault(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/config1"),
	}

	val, err := us.GetStrict("wap", "CanonicalDomains", "")
	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if val != "" {
		t.Errorf("expected to get CanonicalDomains '', got %q", val)
	}
}

func TestGetAllNotFoundNoDefault(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/config1"),
	}

	val, err := us.GetAllStrict("wap", "CanonicalDomains", "")
	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if len(val) != 0 {
		t.Errorf("expected to get CanonicalDomains '', got %q", val)
	}
}

func TestGetWildcard(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/config3"),
	}

	val := us.Get("bastion.stage.i.us.example.net", "Port", "")
	if val != "22" {
		t.Errorf("expected to find Port 22, got %q", val)
	}

	val = us.Get("bastion.net", "Port", "")
	if val != "25" {
		t.Errorf("expected to find Port 24, got %q", val)
	}

	val = us.Get("10.2.3.4", "Port", "")
	if val != "23" {
		t.Errorf("expected to find Port 23, got %q", val)
	}
	val = us.Get("101.2.3.4", "Port", "")
	if val != "25" {
		t.Errorf("expected to find Port 24, got %q", val)
	}
	val = us.Get("20.20.20.4", "Port", "")
	if val != "24" {
		t.Errorf("expected to find Port 24, got %q", val)
	}
	val = us.Get("20.20.20.20", "Port", "")
	if val != "25" {
		t.Errorf("expected to find Port 25, got %q", val)
	}
}

func TestGetExtraSpaces(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/extraspace"),
	}

	val := us.Get("test.test", "Port", "")
	if val != "1234" {
		t.Errorf("expected to find Port 1234, got %q", val)
	}
}

func TestGetCaseInsensitive(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/config1"),
	}

	val := us.Get("wap", "uSER", "")
	if val != "root" {
		t.Errorf("expected to find User root, got %q", val)
	}
}

func TestGetEmpty(t *testing.T) {
	us := &UserSettings{
		userConfigFinder:   nullConfigFinder,
		systemConfigFinder: nullConfigFinder,
	}
	val, err := us.GetStrict("wap", "User", "")
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if val != "" {
		t.Errorf("expected to get empty string, got %q", val)
	}
}

func TestGetEqsign(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/eqsign"),
	}

	val := us.Get("test.test", "Port", "")
	if val != "1234" {
		t.Errorf("expected to find Port 1234, got %q", val)
	}
	val = us.Get("test.test", "Port2", "")
	if val != "5678" {
		t.Errorf("expected to find Port2 5678, got %q", val)
	}
}

var includeFile = []byte(`
# This host should not exist, so we can use it for test purposes / it won't
# interfere with any other configurations.
Host kevinburke.ssh_config.test.example.com
    Port 4567
`)

func TestInclude(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping fs write in short mode")
	}
	testPath := filepath.Join(homedir(), ".ssh", "kevinburke-ssh-config-test-file")
	err := os.WriteFile(testPath, includeFile, 0644)
	if err != nil {
		t.Skipf("couldn't write SSH config file: %v", err.Error())
	}
	defer os.Remove(testPath)
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/include"),
	}
	val := us.Get("kevinburke.ssh_config.test.example.com", "Port", "")
	if val != "4567" {
		t.Errorf("expected to find Port=4567 in included file, got %q", val)
	}
}

func TestIncludeSystem(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping fs write in short mode")
	}
	testPath := filepath.Join("/", "etc", "ssh", "kevinburke-ssh-config-test-file")
	err := os.WriteFile(testPath, includeFile, 0644)
	if err != nil {
		t.Skipf("couldn't write SSH config file: %v", err.Error())
	}
	defer os.Remove(testPath)
	us := &UserSettings{
		systemConfigFinder: testConfigFinder("testdata/include"),
	}
	val := us.Get("kevinburke.ssh_config.test.example.com", "Port", "")
	if val != "4567" {
		t.Errorf("expected to find Port=4567 in included file, got %q", val)
	}
}

var recursiveIncludeFile = []byte(`
Host kevinburke.ssh_config.test.example.com
	Include kevinburke-ssh-config-recursive-include
`)

func TestIncludeRecursive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping fs write in short mode")
	}
	testPath := filepath.Join(homedir(), ".ssh", "kevinburke-ssh-config-recursive-include")
	err := os.WriteFile(testPath, recursiveIncludeFile, 0644)
	if err != nil {
		t.Skipf("couldn't write SSH config file: %v", err.Error())
	}
	defer os.Remove(testPath)
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/include-recursive"),
	}
	val, err := us.GetStrict("kevinburke.ssh_config.test.example.com", "Port", "")
	if err != ErrDepthExceeded {
		t.Errorf("Recursive include: expected ErrDepthExceeded, got %v", err)
	}
	if val != "" {
		t.Errorf("non-empty string value %s", val)
	}
}

func TestIncludeString(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping fs write in short mode")
	}
	data, err := os.ReadFile("testdata/include")
	if err != nil {
		log.Fatal(err)
	}
	c, err := Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	s := c.String()
	if s != string(data) {
		t.Errorf("mismatch: got %q\nwant %q", s, string(data))
	}
}

var matchTests = []struct {
	in    []string
	alias string
	want  bool
}{
	{[]string{"*"}, "any.test", true},
	{[]string{"a", "b", "*", "c"}, "any.test", true},
	{[]string{"a", "b", "c"}, "any.test", false},
	{[]string{"any.test"}, "any1test", false},
	{[]string{"192.168.0.?"}, "192.168.0.1", true},
	{[]string{"192.168.0.?"}, "192.168.0.10", false},
	{[]string{"*.co.uk"}, "bbc.co.uk", true},
	{[]string{"*.co.uk"}, "subdomain.bbc.co.uk", true},
	{[]string{"*.*.co.uk"}, "bbc.co.uk", false},
	{[]string{"*.*.co.uk"}, "subdomain.bbc.co.uk", true},
	{[]string{"*.example.com", "!*.dialup.example.com", "foo.dialup.example.com"}, "foo.dialup.example.com", false},
	{[]string{"test.*", "!test.host"}, "test.host", false},
}

func TestMatches(t *testing.T) {
	for _, tt := range matchTests {
		patterns := make([]*Pattern, len(tt.in))
		for i := range tt.in {
			pat, err := NewPattern(tt.in[i])
			if err != nil {
				t.Fatalf("error compiling pattern %s: %v", tt.in[i], err)
			}
			patterns[i] = pat
		}
		host := &Host{
			Patterns: patterns,
		}
		got := host.Matches(NewMatchContext(tt.alias, ""))
		if got != tt.want {
			t.Errorf("host(%q).Matches(%q): got %v, want %v", tt.in, tt.alias, got, tt.want)
		}
	}
}

func TestMatchAll(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/match-directive"),
	}
	port, err := us.GetStrict("testhost", "Port", "")

	if err != nil {
		t.Fatal(err)
	}
	if port != "4567" {
		t.Errorf("expected Port to be %q, got %q", "4567", port)
	}
}

func TestMatchCondition(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/match-directive"),
	}

	hn, err := us.GetStrict("testhost", "HostName", "")

	if err != nil {
		t.Fatal(err)
	}
	if hn != "hostname" {
		t.Errorf("expected HostName to be %q, got %q", "hostname", hn)
	}
}

func TestMatchConditionFalse(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/match-directive"),
	}

	hn, err := us.GetStrict("wronghost", "HostName", "")

	if err != nil {
		t.Fatal(err)
	}
	if hn != "" {
		t.Errorf("expected HostName to be %q, got %q", "", hn)
	}
}

func TestMatchUser(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/match-user"),
	}

	hn, err := us.GetStrict("testhost", "HostName", "testuser")

	if err != nil {
		t.Fatal(err)
	}
	if hn != "hostname" {
		t.Errorf("expected HostName to be %q, got %q", "hostname", hn)
	}
}

func TestMatchFinal(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/match-final"),
	}

	port, err := us.GetStrict("testhost", "Port", "")

	if err != nil {
		t.Fatal(err)
	}
	if port != "4567" {
		t.Errorf("expected Port to be %q, got %q", "4567", port)
	}
}

func TestMatchFinalAlreadySet(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/match-final"),
	}

	port, err := us.GetStrict("testhost2", "Port", "")

	if err != nil {
		t.Fatal(err)
	}
	if port != "1234" {
		t.Errorf("expected Port to be %q, got %q", "1234", port)
	}
}

func TestMatchFinalWithCriterion(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/match-final"),
	}

	port, err := us.GetStrict("testhost3", "Port", "")

	if err != nil {
		t.Fatal(err)
	}
	if port != "3333" {
		t.Errorf("expected Port to be %q, got %q", "3333", port)
	}
}

func TestIndexInRange(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/config4"),
	}

	user, err := us.GetStrict("wap", "User", "")
	if err != nil {
		t.Fatal(err)
	}
	if user != "root" {
		t.Errorf("expected User to be %q, got %q", "root", user)
	}
}

func TestDosLinesEndingsDecode(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/dos-lines"),
	}

	user, err := us.GetStrict("wap", "User", "")
	if err != nil {
		t.Fatal(err)
	}

	if user != "root" {
		t.Errorf("expected User to be %q, got %q", "root", user)
	}

	host, err := us.GetStrict("wap2", "HostName", "")
	if err != nil {
		t.Fatal(err)
	}

	if host != "8.8.8.8" {
		t.Errorf("expected HostName to be %q, got %q", "8.8.8.8", host)
	}
}

func TestNoTrailingNewline(t *testing.T) {
	us := &UserSettings{
		userConfigFinder:   testConfigFinder("testdata/config-no-ending-newline"),
		systemConfigFinder: nullConfigFinder,
	}

	port, err := us.GetStrict("example", "Port", "")
	if err != nil {
		t.Fatal(err)
	}

	if port != "4242" {
		t.Errorf("wrong port: got %q want 4242", port)
	}
}

func TestCustomFinder(t *testing.T) {
	us := &UserSettings{}
	us.ConfigFinder(func() string {
		return "testdata/config1"
	})

	val := us.Get("wap", "User", "")
	if val != "root" {
		t.Errorf("expected to find User root, got %q", val)
	}
}

func TestModifierPlus(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/modifiers"),
	}

	def := Default("Ciphers")
	c, err := us.GetStrict("plus", "Ciphers", "")

	if err != nil {
		t.Fatal(err)
	}
	if def+",a,b" != c {
		t.Errorf("expected Ciphers to be %q, got %q", def+",a,b", c)
	}
}

func TestModifierMinus(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/modifiers"),
	}

	def := Default("Ciphers")
	if !strings.Contains(def, "aes128-cbc") || !strings.Contains(def, "aes192-cbc") {
		t.Errorf("expected default Ciphers to contain aes128-cbc or aes192-cbc, got %q", def)
	}

	c, err := us.GetStrict("minus", "Ciphers", "")

	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(c, "aes128-cbc") || strings.Contains(c, "aes192-cbc") {
		t.Errorf("expected Ciphers not to contain aes128-cbc or aes192-cbc, got %q", c)
	}
}

func TestModifierCaret(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/modifiers"),
	}

	def := Default("Ciphers")
	if !strings.Contains(def, "aes192-cbc") {
		t.Errorf("expected default Ciphers to contain aes192-cbc, got %q", def)
	}
	if strings.Contains(def, "dummy") {
		t.Errorf("expected default Ciphers not to contain %q, got %q", "dummy", def)
	}
	c, err := us.GetStrict("caret", "Ciphers", "")

	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c, "aes192-cbc") {
		t.Errorf("expected Ciphers to start with %q, got %q", "aes192-cbc", c)
	}
	if strings.Contains(c, "dummy") {
		t.Errorf("expected Ciphers not to contain %q, got %q", "dummy", c)
	}
}
