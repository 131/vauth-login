// Command vauth-login authenticates to Vault and writes the token to stdout.
package main

import (
	"fmt"
	"os"
	"regexp"
	"runtime/debug"
	"strings"

	vauthlogin "github.com/131/vauth-login"
)

const usage = `Usage: vauth-login [--renew]
       vauth-login version

Authenticate to Vault and print the token. --renew forces a fresh login.
Login/connect aliases are also accepted.
`

// version is set by the release build (-ldflags "-X main.version=v1.2.3");
// otherwise the module version recorded by go install is used.
var version string

func buildVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "(devel)"
}

var flagPattern = regexp.MustCompile(`^--?([a-zA-Z_0-9/:-]+)(?:=(.*))?$`)

// parseArgs splits positional arguments from --flags (nyks/process/parseArgs).
func parseArgs(argv []string) ([]string, map[string]string) {
	var args []string
	dict := map[string]string{}
	for i, arg := range argv {
		if arg == "--" {
			args = append(args, argv[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") {
			args = append(args, arg)
			continue
		}
		if match := flagPattern.FindStringSubmatch(arg); match != nil {
			value := "true"
			if strings.Contains(arg, "=") {
				value = match[2]
			}
			dict[match[1]] = value
		}
	}
	return args, dict
}

func truthy(value string, ok bool) bool {
	if !ok {
		return false
	}
	switch strings.ToLower(value) {
	case "", "false", "0":
		return false
	}
	return true
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(argv []string) error {
	args, dict := parseArgs(argv)
	if _, ok := dict["help"]; ok {
		fmt.Fprint(os.Stdout, usage)
		return nil
	}
	command := "login"
	if len(args) > 0 {
		command = args[0]
	}
	if _, ok := dict["version"]; ok {
		command = "version"
	}
	if command == "version" {
		fmt.Println(buildVersion())
		return nil
	}
	if command == "help" {
		fmt.Fprint(os.Stdout, usage)
		return nil
	}
	if command != "login" && command != "connect" {
		return fmt.Errorf("Invalid command key '%s'", command)
	}
	if len(args) > 1 {
		return fmt.Errorf("Unexpected positional arguments")
	}
	for key := range dict {
		if key != "renew" {
			return fmt.Errorf("Unknown flag --%s", key)
		}
	}
	vauthlogin.Version = buildVersion()
	v, err := vauthlogin.New()
	if err != nil {
		return err
	}
	renew := truthy(dict["renew"], dict["renew"] != "")
	token, err := v.Connect(renew)
	if err != nil {
		return err
	}
	if token == "" {
		return fmt.Errorf("Could not login to vault: no authentication method available")
	}
	_, err = fmt.Fprint(os.Stdout, token)
	return err
}
