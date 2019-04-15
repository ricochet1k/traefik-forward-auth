package tfa

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/thomseddon/traefik-forward-auth/internal/provider"
)

type Config struct {
	LogLevel  string `long:"log-level" default:"warn" description:"Log level: trace, debug, info, warn, error, fatal, panic"`
	LogFormat string `long:"log-format" default:"text" description:"Log format: text, json, pretty"`

	AuthHost       string             `long:"auth-host" description:"Host for central auth login"`
	ConfigFile     string             `long:"config-file" description:"Config File"`
	CookieDomains  CookieDomains      `long:"cookie-domains" description:"Comma separated list of cookie domains"`
	CookieInsecure bool               `long:"cookie-insecure" description:"Use secure cookies"`
	CookieName     string             `long:"cookie-name" default:"_forward_auth" description:"Cookie Name"`
	CSRFCookieName string             `long:"csrf-cookie-name" default:"_forward_auth_csrf" description:"CSRF Cookie Name"`
	DefaultAction  string             `long:"default-action" default:"allow" description:"Default Action"`
	Domains        CommaSeparatedList `long:"domains" description:"Comma separated list of email domains to allow"`
	LifetimeString int                `long:"lifetime" default:"43200" description:"Lifetime in seconds"`
	Path           string             `long:"path" default:"_oauth" description:"Callback URL Path"`
	SecretString   string             `long:"secret" description:"*Secret used for signing (required)"`
	Whitelist      CommaSeparatedList `long:"whitelist" description:"Comma separated list of email addresses to allow"`

	Providers provider.Providers
	Rules		map[string]*Rule `long:"rule"`

	Secret   []byte
	Lifetime time.Duration

	Prompt string `long:"prompt" description:"DEPRECATED - Use providers.google.prompt"`
	// TODO: Need to mimick the default behaviour of bool flags
	CookieSecure string `long:"cookie-secure" default:"true" description:"DEPRECATED - Use \"cookie-insecure\""`

	flags     []string
	usingToml bool
}

type CommaSeparatedList []string

type Rule struct {
	Action   string
	Rule     string
	Provider string
}

func NewRule() *Rule {
	return &Rule{
		Action: "auth",
		Provider: "google", // TODO: Use default provider
	}
}

var config Config

// TODO:
// - parse ini
// - parse env vars
// - parse env var file
// - support multiple config files
// - maintain backwards compat

func NewGlobalConfig() Config {
	return NewGlobalConfigWithArgs(os.Args[1:])
}

func NewGlobalConfigWithArgs(args []string) Config {
	config = Config{}
	config.Rules = map[string]*Rule{}


	config.parseFlags(args)

	// Struct defaults
	config.Providers.Google.Build()

	// Transformations
	config.Path = fmt.Sprintf("/%s", config.Path)
	config.Secret = []byte(config.SecretString)
	config.Lifetime = time.Second * time.Duration(config.LifetimeString)

	// TODO: Backwards compatability
	// "secret" used to be "cookie-secret"

	return config
}

func (c *Config) parseFlags(args []string) {
	parser := flags.NewParser(c, flags.Default)
	parser.UnknownOptionHandler = c.parseUnknownFlag

	if _, err := parser.ParseArgs(args); err != nil {
		flagsErr, ok := err.(*flags.Error)
		if ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			fmt.Printf("%+v", err)
			os.Exit(1)
		}
	}

	fmt.Println("\n\nDONE")
	for _, rule := range c.Rules {
		fmt.Printf("%#v\n\n", rule)
	}
}

func (c *Config) parseUnknownFlag(option string, arg flags.SplitArgument, args []string) ([]string, error) {
	// Parse rules in the format "rule.<name>.<param>"
	parts := strings.Split(option, ".")
	popped := false
	if len(parts) == 3 && parts[0] == "rule" {
		// Get rule by name
		var rule *Rule
		var ok bool
		if rule, ok = c.Rules[parts[1]]; !ok {
			rule = NewRule()
			c.Rules[parts[1]] = rule
		}

		// Get value, or pop the next arg
		var val string
		if val, ok = arg.Value(); !ok {
			val = args[0]
			popped = true
		}

		// Add param value to rule
		switch(parts[2]) {
		case "action":
			if val != "auth" && val != "allow" {
				return args, errors.New("Invalid rule action, must be \"auth\" or \"allow\"")
			}
			fmt.Println("Adding action")
			rule.Action = val
		case "rule":
			rule.Rule = val
		case "provider":
			// TODO: validation?
			rule.Provider = val
		default:
			return args, errors.New("Inavlid route param, must be \"action\", \"rule\" or \"provider\"")
		}
	}

	if popped {
		return args[1:], nil
	}

	return args, nil
}

func (c *Config) Checks() {
	// Check for show stopper errors
	if len(c.Secret) == 0 {
		log.Fatal("\"secret\" option must be set.")
	}

	if c.Providers.Google.ClientId == "" || c.Providers.Google.ClientSecret == "" {
		log.Fatal("google.providers.client-id, google.providers.client-secret must be set")
	}
}

func (c Config) Serialise() string {
	jsonConf, _ := json.Marshal(c)
	return string(jsonConf)
}

func (c *CommaSeparatedList) UnmarshalFlag(value string) error {
	*c = strings.Split(value, ",")
	return nil
}

func (c *CommaSeparatedList) MarshalFlag() (string, error) {
	return strings.Join(*c, ","), nil
}

func (r *Rule) UnmarshalFlag(value string) error {
	// Format is "action:rule"
	parts := strings.SplitN(value, ":", 2)

	if len(parts) != 2 {
		return errors.New("Invalid rule format, should be \"action:rule\"")
	}

	if parts[0] != "auth" && parts[0] != "allow" {
		return errors.New("Invalid rule action, must be \"auth\" or \"allow\"")
	}

	// Parse rule
	*r = Rule{
		Action: parts[0],
		Rule:   parts[1],
	}

	return nil
}

func (r *Rule) MarshalFlag() (string, error) {
	// TODO: format correctly
	return fmt.Sprintf("%+v", *r), nil
}
