// Package ssh_config provides tools for manipulating SSH config files.
//
// Importantly, this parser attempts to preserve comments in a given file, so
// you can manipulate a `ssh_config` file from a program, if your heart desires.
//
// The Get() and GetStrict() functions will attempt to read values from
// $HOME/.ssh/config, falling back to /etc/ssh/ssh_config. The first argument is
// the host name to match on ("example.com"), and the second argument is the key
// you want to retrieve ("Port"). The keywords are case insensitive.
//
//	port := ssh_config.Get("myhost", "Port")
//
// You can also manipulate an SSH config file and then print it or write it back
// to disk.
//
//	f, _ := os.Open(filepath.Join(os.Getenv("HOME"), ".ssh", "config"))
//	cfg, _ := ssh_config.Decode(f)
//	for _, host := range cfg.Blocks {
//		fmt.Println("patterns:", host.Patterns)
//		for _, node := range host.Nodes {
//			fmt.Println(node.String())
//		}
//	}
//
//	// Write the cfg back to disk:
//	fmt.Println(cfg.String())
package ssh_config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	osuser "os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
)

const version = "1.3"

var _ = version

// modifiableKeys is a list of keys that can specify comma-separated values modifiable by "+", "-", "^".
var modifiableKeys = []string{"Ciphers", "MACs", "HostKeyAlgorithms", "KexAlgorithms"}

type configFinder func() string

// UserSettings checks ~/.ssh and /etc/ssh for configuration files. The config
// files are parsed and cached the first time Get() or GetStrict() is called.
type UserSettings struct {
	IgnoreErrors       bool
	customConfig       *Config
	customConfigFinder configFinder
	systemConfig       *Config
	systemConfigFinder configFinder
	userConfig         *Config
	userConfigFinder   configFinder
	loadConfigs        sync.Once
	onceErr            error
}

func homedir() string {
	user, err := osuser.Current()
	if err == nil {
		return user.HomeDir
	} else {
		return os.Getenv("HOME")
	}
}

func localUser() string {
	user, err := osuser.Current()
	if err == nil {
		return user.Username
	} else {
		return ""
	}
}

func userConfigFinder() string {
	return filepath.Join(homedir(), ".ssh", "config")
}

// MakeDefaultUserSettings creates a new UserSettings instance with default settings.
func MakeDefaultUserSettings() *UserSettings {
	return &UserSettings{
		IgnoreErrors:       false,
		systemConfigFinder: systemConfigFinder,
		userConfigFinder:   userConfigFinder,
	}
}

// DefaultUserSettings is the default UserSettings and is used by Get and
// GetStrict. It checks both $HOME/.ssh/config and /etc/ssh/ssh_config for keys,
// and it will return parse errors (if any) instead of swallowing them.
var DefaultUserSettings = MakeDefaultUserSettings()

func systemConfigFinder() string {
	return filepath.Join("/", "etc", "ssh", "ssh_config")
}

// handleModifiers handles "+", "-", and "^" modifiers for some comma-separated values.
func handleModifiers(v, key string) string {
	if !(strings.HasPrefix(v, "+") || strings.HasPrefix(v, "-") ||
		strings.HasPrefix(v, "^")) {
		return v
	}

	cur := strings.Split(v[1:], ",")
	def := strings.Split(Default(key), ",")
	var out []string

	switch v[0] {
	case '+':
		out = append(def, cur...)
	case '-':
		out = make([]string, 0, len(def))
		for _, a := range def {
			if !slices.Contains(cur, a) {
				out = append(out, a)
			}
		}
	case '^':
		out = make([]string, 0, len(def)+len(cur))
		for _, a := range cur {
			if slices.Contains(def, a) {
				out = append(out, a)
			}
		}
		for _, a := range def {
			if !slices.Contains(out, a) {
				out = append(out, a)
			}
		}
	}

	return strings.Join(out, ",")
}

func findVal(c *Config, key string, ctx *MatchContext) (string, error) {
	if c == nil {
		return "", nil
	}
	val, err := c.Get(key, ctx)
	if err != nil || val == "" {
		return "", err
	}

	// check for special symbols within algorithm specifications
	if slices.Contains(modifiableKeys, key) {
		val = handleModifiers(val, key)
	}

	if err := validate(key, val); err != nil {
		return "", err
	}
	return val, nil
}

func findAll(c *Config, key string, ctx *MatchContext) ([]string, error) {
	if c == nil {
		return nil, nil
	}
	return c.GetAll(key, ctx)
}

// Get finds the first value for key within a declaration that matches the
// alias. Get returns the empty string if no value was found, or if IgnoreErrors
// is false and we could not parse the configuration file. Use GetStrict to
// disambiguate the latter cases.
//
// The match for key is case insensitive.
//
// Get is a wrapper around DefaultUserSettings.Get.
func Get(alias, key, user string) string {
	return DefaultUserSettings.Get(alias, key, user)
}

// GetAll retrieves zero or more directives for key for the given alias. GetAll
// returns nil if no value was found, or if IgnoreErrors is false and we could
// not parse the configuration file. Use GetAllStrict to disambiguate the
// latter cases.
//
// In most cases you want to use Get or GetStrict, which returns a single value.
// However, a subset of ssh configuration values (IdentityFile, for example)
// allow you to specify multiple directives.
//
// The match for key is case insensitive.
//
// GetAll is a wrapper around DefaultUserSettings.GetAll.
func GetAll(alias, key, user string) []string {
	return DefaultUserSettings.GetAll(alias, key, user)
}

// GetStrict finds the first value for key within a declaration that matches the
// alias. If key has a default value and no matching configuration is found, the
// default will be returned. For more information on default values and the way
// patterns are matched, see the manpage for ssh_config.
//
// The returned error will be non-nil if and only if a user's configuration file
// or the system configuration file could not be parsed, and u.IgnoreErrors is
// false.
//
// GetStrict is a wrapper around DefaultUserSettings.GetStrict.
func GetStrict(alias, key, user string) (string, error) {
	return DefaultUserSettings.GetStrict(alias, key, user)
}

// GetAllStrict retrieves zero or more directives for key for the given alias.
//
// In most cases you want to use Get or GetStrict, which returns a single value.
// However, a subset of ssh configuration values (IdentityFile, for example)
// allow you to specify multiple directives.
//
// The returned error will be non-nil if and only if a user's configuration file
// or the system configuration file could not be parsed, and u.IgnoreErrors is
// false.
//
// GetAllStrict is a wrapper around DefaultUserSettings.GetAllStrict.
func GetAllStrict(alias, key, user string) ([]string, error) {
	return DefaultUserSettings.GetAllStrict(alias, key, user)
}

// Get finds the first value for key within a declaration that matches the
// alias. Get returns the empty string if no value was found, or if IgnoreErrors
// is false and we could not parse the configuration file. Use GetStrict to
// disambiguate the latter cases.
//
// The match for key is case insensitive.
func (u *UserSettings) Get(alias, key, user string) string {
	val, err := u.GetStrict(alias, key, user)
	if err != nil {
		return ""
	}
	return val
}

// GetAll retrieves zero or more directives for key for the given alias. GetAll
// returns nil if no value was found, or if IgnoreErrors is false and we could
// not parse the configuration file. Use GetStrict to disambiguate the latter
// cases.
//
// The match for key is case insensitive.
func (u *UserSettings) GetAll(alias, key, user string) []string {
	val, _ := u.GetAllStrict(alias, key, user)
	return val
}

// GetStrict finds the first value for key within a declaration that matches the
// alias. If key has a default value and no matching configuration is found, the
// default will be returned. For more information on default values and the way
// patterns are matched, see the manpage for ssh_config.
//
// error will be non-nil if and only if a user's configuration file or the
// system configuration file could not be parsed, and u.IgnoreErrors is false.
func (u *UserSettings) GetStrict(alias, key, user string) (string, error) {
	u.doLoadConfigs()
	//lint:ignore S1002 I prefer it this way
	if u.onceErr != nil && u.IgnoreErrors == false {
		return "", u.onceErr
	}

	ctx := NewMatchContext(alias, user)

	// TODO this is getting repetitive
	if u.customConfig != nil {
		val, err := findVal(u.customConfig, key, ctx)
		if err != nil || val != "" {
			return val, err
		}
	}
	val, err := findVal(u.userConfig, key, ctx)
	if err != nil || val != "" {
		return val, err
	}
	val2, err2 := findVal(u.systemConfig, key, ctx)
	if err2 != nil || val2 != "" {
		return val2, err2
	}

	// No value found until now, so check final blocks
	val3, err3 := ctx.matchFinal(key)
	if err3 != nil || val3 != "" {
		return val3, err3
	}

	return Default(key), nil
}

// GetAllStrict retrieves zero or more directives for key for the given alias.
// If key has a default value and no matching configuration is found, the
// default will be returned. For more information on default values and the way
// patterns are matched, see the manpage for ssh_config.
//
// The returned error will be non-nil if and only if a user's configuration file
// or the system configuration file could not be parsed, and u.IgnoreErrors is
// false.
func (u *UserSettings) GetAllStrict(alias, key, user string) ([]string, error) {
	u.doLoadConfigs()
	//lint:ignore S1002 I prefer it this way
	if u.onceErr != nil && u.IgnoreErrors == false {
		return nil, u.onceErr
	}

	ctx := NewMatchContext(alias, user)

	if u.customConfig != nil {
		val, err := findAll(u.customConfig, key, ctx)
		if err != nil || val != nil {
			return val, err
		}
	}
	val, err := findAll(u.userConfig, key, ctx)
	if err != nil || val != nil {
		return val, err
	}
	val2, err2 := findAll(u.systemConfig, key, ctx)
	if err2 != nil || val2 != nil {
		return val2, err2
	}

	// No value found until now, so check final blocks
	val3, err3 := ctx.matchFinalAll(key)
	if err3 != nil || val3 != nil {
		return val3, err3
	}

	if def := Default(key); def != "" {
		return []string{def}, nil
	}

	if key == "IdentityFile" {
		return defaultProtocol2Identities, nil
	}

	return []string{}, nil
}

// ConfigFinder will invoke f to try to find a ssh config file in a custom
// location on disk, instead of in /etc/ssh or $HOME/.ssh. f should return the
// name of a file containing SSH configuration.
//
// ConfigFinder must be invoked before any calls to Get or GetStrict and panics
// if f is nil. Most users should not need to use this function.
func (u *UserSettings) ConfigFinder(f func() string) {
	if f == nil {
		panic("cannot call ConfigFinder with nil function")
	}
	u.customConfigFinder = f
}

func (u *UserSettings) doLoadConfigs() {
	u.loadConfigs.Do(func() {
		var filename string
		var err error
		if u.customConfigFinder != nil {
			filename = u.customConfigFinder()
			u.customConfig, err = parseFile(filename)
			// IsNotExist should be returned because a user specified this
			// function - not existing likely means they made an error
			if err != nil {
				u.onceErr = err
			}
			return
		}
		if u.userConfigFinder == nil {
			filename = userConfigFinder()
		} else {
			filename = u.userConfigFinder()
		}
		u.userConfig, err = parseFile(filename)
		//lint:ignore S1002 I prefer it this way
		if err != nil && os.IsNotExist(err) == false {
			u.onceErr = err
			return
		}
		if u.systemConfigFinder == nil {
			filename = systemConfigFinder()
		} else {
			filename = u.systemConfigFinder()
		}
		u.systemConfig, err = parseFile(filename)
		//lint:ignore S1002 I prefer it this way
		if err != nil && os.IsNotExist(err) == false {
			u.onceErr = err
			return
		}
	})
}

func parseFile(filename string) (*Config, error) {
	return parseWithDepth(filename, 0)
}

func parseWithDepth(filename string, depth uint8) (*Config, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return decodeBytes(b, isSystem(filename), depth)
}

func isSystem(filename string) bool {
	// TODO: not sure this is the best way to detect a system repo
	return strings.HasPrefix(filepath.Clean(filename), "/etc/ssh")
}

// Decode reads r into a Config, or returns an error if r could not be parsed as
// an SSH config file.
func Decode(r io.Reader) (*Config, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return decodeBytes(b, false, 0)
}

// DecodeBytes reads b into a Config, or returns an error if r could not be
// parsed as an SSH config file.
func DecodeBytes(b []byte) (*Config, error) {
	return decodeBytes(b, false, 0)
}

func decodeBytes(b []byte, system bool, depth uint8) (c *Config, err error) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(runtime.Error); ok {
				panic(r)
			}
			if e, ok := r.(error); ok && e == ErrDepthExceeded {
				err = e
				return
			}
			err = errors.New(r.(string))
		}
	}()

	c = parseSSH(lexSSH(b), system, depth)
	return c, err
}

// Config represents an SSH config file.
type Config struct {
	// A list of blocks to match against. The file begins with an implicit
	// "Host *" declaration matching all hosts.
	Blocks   []Block
	depth    uint8
	position Position
}

// MatchContext holds information about previously matched values,
// to be used for Match block matching.
type MatchContext struct {
	// Remote target user
	User string
	// Final host name
	Host string
	// Local user
	LocalUser string
	// Original Host, a.k.a. alias
	OriginalHost string
	// Final blocks to parse after matching
	FinalBlocks []Block
}

func NewMatchContext(alias, user string) *MatchContext {
	return &MatchContext{
		User:         user,  // initial
		Host:         alias, // initial
		LocalUser:    localUser(),
		OriginalHost: alias,
	}
}

func (ctx *MatchContext) matchFinal(key string) (string, error) {
	for _, block := range ctx.FinalBlocks {
		if !block.Matches(ctx) {
			continue
		}
		found, err := handleBlock(block, key, nil)
		if err != nil {
			return "", err
		}
		if found != "" {
			return found, nil
		}
	}
	return "", nil
}

func (ctx *MatchContext) matchFinalAll(key string) (all []string, err error) {
	for _, block := range ctx.FinalBlocks {
		if !block.Matches(ctx) {
			continue
		}
		all, err = handleBlockAll(block, all, key, nil)
		if err != nil {
			return nil, err
		}
	}
	return all, nil
}

func handleBlock(block Block, key string, ctx *MatchContext) (string, error) {
	lowerKey := strings.ToLower(key)

	for _, node := range block.GetNodes() {
		switch t := node.(type) {
		case *Empty:
			continue
		case *KV:
			// "keys are case insensitive" per the spec
			lkey := strings.ToLower(t.Key)
			if lkey == "match" {
				panic("can't handle Match directives")
			}
			if lkey == lowerKey {
				return t.Value, nil
			}
			// Add values to context
			if ctx != nil {
				switch lkey {
				case "user":
					ctx.User = t.Value
				case "hostname":
					ctx.Host = t.Value
				}
			}
		case *Include:
			val := t.Get(key, ctx)
			if val != "" {
				return val, nil
			}
		default:
			return "", fmt.Errorf("unknown Node type %v", t)
		}
	}
	return "", nil
}

func handleBlockAll(block Block, all []string, key string, ctx *MatchContext) ([]string, error) {
	lowerKey := strings.ToLower(key)

	for _, node := range block.GetNodes() {
		switch t := node.(type) {
		case *Empty:
			continue
		case *KV:
			// "keys are case insensitive" per the spec
			lkey := strings.ToLower(t.Key)
			if lkey == "match" {
				panic("can't handle Match directives")
			}
			if lkey == lowerKey {
				all = append(all, t.Value)
			}
			// Add values to context
			if ctx != nil {
				switch lkey {
				case "user":
					ctx.User = t.Value
				case "hostname":
					ctx.Host = t.Value
				}
			}
		case *Include:
			val, _ := t.GetAll(key, ctx)
			if len(val) > 0 {
				all = append(all, val...)
			}
		default:
			return nil, fmt.Errorf("unknown Node type %v", t)
		}
	}
	return all, nil
}

// Get finds the first value in the configuration that matches the alias and
// contains key. Get returns the empty string if no value was found, or if the
// Config contains an invalid conditional Include value.
//
// The match for key is case insensitive.
func (c *Config) Get(key string, ctx *MatchContext) (string, error) {
	for _, block := range c.Blocks {
		if block.IsFinal() {
			ctx.FinalBlocks = append(ctx.FinalBlocks, block)
			continue
		}
		if !block.Matches(ctx) {
			continue
		}
		found, err := handleBlock(block, key, ctx)
		if err != nil {
			return "", err
		}
		if found != "" {
			return found, nil
		}
	}

	return "", nil
}

// GetAll returns all values in the configuration that match the alias and
// contains key, or nil if none are present.
func (c *Config) GetAll(key string, ctx *MatchContext) ([]string, error) {
	all := []string(nil)
	var err error
	for _, block := range c.Blocks {
		if block.IsFinal() {
			ctx.FinalBlocks = append(ctx.FinalBlocks, block)
			continue
		}
		if !block.Matches(ctx) {
			continue
		}
		all, err = handleBlockAll(block, all, key, ctx)
		if err != nil {
			return nil, err
		}
	}
	return all, nil
}

// String returns a string representation of the Config file.
func (c Config) String() string {
	return marshal(c).String()
}

func (c Config) MarshalText() ([]byte, error) {
	return marshal(c).Bytes(), nil
}

func marshal(c Config) *bytes.Buffer {
	var buf bytes.Buffer
	for i := range c.Blocks {
		buf.WriteString(c.Blocks[i].String())
	}
	return &buf
}

// Pattern is a pattern in a Host declaration. Patterns are read-only values;
// create a new one with NewPattern().
type Pattern struct {
	str   string // Its appearance in the file, not the value that gets compiled.
	regex *regexp.Regexp
	not   bool // True if this is a negated match
}

// String prints the string representation of the pattern.
func (p Pattern) String() string {
	return p.str
}

// Copied from regexp.go with * and ? removed.
var specialBytes = []byte(`\.+()|[]{}^$`)

func special(b byte) bool {
	return bytes.IndexByte(specialBytes, b) >= 0
}

// NewPattern creates a new Pattern for matching hosts. NewPattern("*") creates
// a Pattern that matches all hosts.
//
// From the manpage, a pattern consists of zero or more non-whitespace
// characters, `*' (a wildcard that matches zero or more characters), or `?' (a
// wildcard that matches exactly one character). For example, to specify a set
// of declarations for any host in the ".co.uk" set of domains, the following
// pattern could be used:
//
//	Host *.co.uk
//
// The following pattern would match any host in the 192.168.0.[0-9] network range:
//
//	Host 192.168.0.?
func NewPattern(s string) (*Pattern, error) {
	if s == "" {
		return nil, errors.New("ssh_config: empty pattern")
	}
	negated := false
	if s[0] == '!' {
		negated = true
		s = s[1:]
	}
	var buf bytes.Buffer
	buf.WriteByte('^')
	for i := 0; i < len(s); i++ {
		// A byte loop is correct because all metacharacters are ASCII.
		switch b := s[i]; b {
		case '*':
			buf.WriteString(".*")
		case '?':
			buf.WriteString(".?")
		default:
			// borrowing from QuoteMeta here.
			if special(b) {
				buf.WriteByte('\\')
			}
			buf.WriteByte(b)
		}
	}
	buf.WriteByte('$')
	r, err := regexp.Compile(buf.String())
	if err != nil {
		return nil, err
	}
	return &Pattern{str: s, regex: r, not: negated}, nil
}

// Block describes either a Host or Match directive, which must
// implement a Matches and a String method.
type Block interface {
	// GetNodes returns the nodes belonging to the Block
	GetNodes() []Node
	// SetNodes sets the nodes belonging to the Block
	SetNodes(nodes []Node)
	// Matches returns true if the Block matches the passed MatchContext
	Matches(ctx *MatchContext) bool
	// String prints the Block as it would appear in a config file
	String() string
	// IsFinal indicates whether this match block is final
	IsFinal() bool
}

type BlockData struct {
	// A Node is either a key/value pair or a comment line.
	Nodes []Node
	// EOLComment is the comment (if any) terminating the Host line.
	EOLComment string
	// Whitespace if any between the Host declaration and a trailing comment.
	spaceBeforeComment string

	hasEquals    bool
	leadingSpace int // TODO: handle spaces vs tabs here.
	// The file starts with an implicit "Host *" declaration.
	implicit bool
	// Final indicates whether this match block is final
	Final bool
}

// Host describes a Host directive and the keywords that follow it.
type Host struct {
	// A list of host patterns that should match this host.
	Patterns []*Pattern
	*BlockData
}

func (h *Host) GetNodes() []Node {
	return h.Nodes
}

func (h *Host) SetNodes(nodes []Node) {
	h.Nodes = nodes
}

func (h *Host) IsFinal() bool {
	return h.Final
}

// Matches returns true if the Host matches for the given alias. For
// a description of the rules that provide a match, see the manpage for
// ssh_config.
func (h *Host) Matches(ctx *MatchContext) bool {
	found := false
	for i := range h.Patterns {
		if h.Patterns[i].regex.MatchString(ctx.OriginalHost) {
			if h.Patterns[i].not {
				// Negated match. "A pattern entry may be negated by prefixing
				// it with an exclamation mark (`!'). If a negated entry is
				// matched, then the Host entry is ignored, regardless of
				// whether any other patterns on the line match. Negated matches
				// are therefore useful to provide exceptions for wildcard
				// matches."
				return false
			}
			found = true
		}
	}
	return found
}

// String prints h as it would appear in a config file. Minor tweaks may be
// present in the whitespace in the printed file.
func (h *Host) String() string {
	var buf strings.Builder
	//lint:ignore S1002 I prefer to write it this way
	if h.implicit == false {
		buf.WriteString(strings.Repeat(" ", int(h.leadingSpace)))
		buf.WriteString("Host")
		if h.hasEquals {
			buf.WriteString(" = ")
		} else {
			buf.WriteString(" ")
		}
		for i, pat := range h.Patterns {
			buf.WriteString(pat.String())
			if i < len(h.Patterns)-1 {
				buf.WriteString(" ")
			}
		}
		buf.WriteString(h.spaceBeforeComment)
		if h.EOLComment != "" {
			buf.WriteByte('#')
			buf.WriteString(h.EOLComment)
		}
		buf.WriteByte('\n')
	}
	for i := range h.Nodes {
		buf.WriteString(h.Nodes[i].String())
		buf.WriteByte('\n')
	}
	return buf.String()
}

type Match struct {
	// Patterns is a map of key -> Pattern entries, e.g. "Address" -> Pattern("127.0.0.*")
	Patterns map[string]*Pattern
	*BlockData
}

func (m *Match) GetNodes() []Node {
	return m.Nodes
}

func (m *Match) SetNodes(nodes []Node) {
	m.Nodes = nodes
}

func (m *Match) Matches(ctx *MatchContext) bool {
	// All patterns have to match to make the block apply.
	// If a context value is empty, the pattern is considered no match.
	for k, p := range m.Patterns {
		var comp string
		switch k {
		case "host":
			comp = ctx.Host
		case "user":
			comp = ctx.User
		case "originalhost":
			comp = ctx.OriginalHost
		case "localuser":
			comp = ctx.LocalUser
		default:
			panic("unknown Match directive key: " + k)
		}
		if comp == "" || p.not == p.regex.MatchString(comp) {
			return false
		}
	}
	return true
}

func (m *Match) String() string {
	panic("Match does not support String() serialization for now")
}

func (m *Match) IsFinal() bool {
	return m.Final
}

// Node represents a line in a Config.
type Node interface {
	Pos() Position
	String() string
}

// KV is a line in the config file that contains a key, a value, and possibly
// a comment.
type KV struct {
	Key   string
	Value string
	// Whitespace after the value but before any comment
	spaceAfterValue string
	Comment         string
	hasEquals       bool
	leadingSpace    int // Space before the key. TODO handle spaces vs tabs.
	position        Position
}

// Pos returns k's Position.
func (k *KV) Pos() Position {
	return k.position
}

// String prints k as it was parsed in the config file.
func (k *KV) String() string {
	if k == nil {
		return ""
	}
	equals := " "
	if k.hasEquals {
		equals = " = "
	}
	line := strings.Repeat(" ", int(k.leadingSpace)) + k.Key + equals + k.Value + k.spaceAfterValue
	if k.Comment != "" {
		line += "#" + k.Comment
	}
	return line
}

// Empty is a line in the config file that contains only whitespace or comments.
type Empty struct {
	Comment      string
	leadingSpace int // TODO handle spaces vs tabs.
	position     Position
}

// Pos returns e's Position.
func (e *Empty) Pos() Position {
	return e.position
}

// String prints e as it was parsed in the config file.
func (e *Empty) String() string {
	if e == nil {
		return ""
	}
	if e.Comment == "" {
		return ""
	}
	return fmt.Sprintf("%s#%s", strings.Repeat(" ", int(e.leadingSpace)), e.Comment)
}

// Include holds the result of an Include directive, including the config files
// that have been parsed as part of that directive. At most 5 levels of Include
// statements will be parsed.
type Include struct {
	// Comment is the contents of any comment at the end of the Include
	// statement.
	Comment string
	// an include directive can include several different files, and wildcards
	directives []string

	mu sync.Mutex
	// 1:1 mapping between matches and keys in files array; matches preserves
	// ordering
	matches []string
	// actual filenames are listed here
	files        map[string]*Config
	leadingSpace int
	position     Position
	depth        uint8
	hasEquals    bool
}

const maxRecurseDepth = 5

// ErrDepthExceeded is returned if too many Include directives are parsed.
// Usually this indicates a recursive loop (an Include directive pointing to the
// file it contains).
var ErrDepthExceeded = errors.New("ssh_config: max recurse depth exceeded")

func removeDups(arr []string) []string {
	// Use map to record duplicates as we find them.
	encountered := make(map[string]bool, len(arr))
	result := make([]string, 0)

	for v := range arr {
		//lint:ignore S1002 I prefer it this way
		if encountered[arr[v]] == false {
			encountered[arr[v]] = true
			result = append(result, arr[v])
		}
	}
	return result
}

// NewInclude creates a new Include with a list of file globs to include.
// Configuration files are parsed greedily (e.g. as soon as this function runs).
// Any error encountered while parsing nested configuration files will be
// returned.
func NewInclude(directives []string, hasEquals bool, pos Position, comment string, system bool, depth uint8) (*Include, error) {
	if depth > maxRecurseDepth {
		return nil, ErrDepthExceeded
	}
	inc := &Include{
		Comment:      comment,
		directives:   directives,
		files:        make(map[string]*Config),
		position:     pos,
		leadingSpace: pos.Col - 1,
		depth:        depth,
		hasEquals:    hasEquals,
	}
	// no need for inc.mu.Lock() since nothing else can access this inc
	matches := make([]string, 0)
	for i := range directives {
		var path string
		if filepath.IsAbs(directives[i]) {
			path = directives[i]
		} else if system {
			path = filepath.Join("/etc/ssh", directives[i])
		} else {
			path = filepath.Join(homedir(), ".ssh", directives[i])
		}
		theseMatches, err := filepath.Glob(path)
		if err != nil {
			return nil, err
		}
		matches = append(matches, theseMatches...)
	}
	matches = removeDups(matches)
	inc.matches = matches
	for i := range matches {
		config, err := parseWithDepth(matches[i], depth)
		if err != nil {
			return nil, err
		}
		inc.files[matches[i]] = config
	}
	return inc, nil
}

// Pos returns the position of the Include directive in the larger file.
func (i *Include) Pos() Position {
	return i.position
}

// Get finds the first value in the Include statement matching the alias and the
// given key.
func (inc *Include) Get(key string, ctx *MatchContext) string {
	inc.mu.Lock()
	defer inc.mu.Unlock()
	// TODO: we search files in any order which is not correct
	for i := range inc.matches {
		cfg := inc.files[inc.matches[i]]
		if cfg == nil {
			panic("nil cfg")
		}
		val, err := cfg.Get(key, ctx)
		if err == nil && val != "" {
			return val
		}
	}
	return ""
}

// GetAll finds all values in the Include statement matching the alias and the
// given key.
func (inc *Include) GetAll(key string, ctx *MatchContext) ([]string, error) {
	inc.mu.Lock()
	defer inc.mu.Unlock()
	var vals []string

	// TODO: we search files in any order which is not correct
	for i := range inc.matches {
		cfg := inc.files[inc.matches[i]]
		if cfg == nil {
			panic("nil cfg")
		}
		val, err := cfg.GetAll(key, ctx)
		if err == nil && len(val) != 0 {
			// In theory if SupportsMultiple was false for this key we could
			// stop looking here. But the caller has asked us to find all
			// instances of the keyword (and could use Get() if they wanted) so
			// let's keep looking.
			vals = append(vals, val...)
		}
	}
	return vals, nil
}

// String prints out a string representation of this Include directive. Note
// included Config files are not printed as part of this representation.
func (inc *Include) String() string {
	equals := " "
	if inc.hasEquals {
		equals = " = "
	}
	line := fmt.Sprintf("%sInclude%s%s", strings.Repeat(" ", int(inc.leadingSpace)), equals, strings.Join(inc.directives, " "))
	if inc.Comment != "" {
		line += " #" + inc.Comment
	}
	return line
}

var matchAll *Pattern

func init() {
	var err error
	matchAll, err = NewPattern("*")
	if err != nil {
		panic(err)
	}
}

func newConfig() *Config {
	return &Config{
		Blocks: []Block{
			&Host{
				Patterns: []*Pattern{matchAll},
				BlockData: &BlockData{
					implicit: true,
					Nodes:    make([]Node, 0),
				},
			},
		},
		depth: 0,
	}
}
