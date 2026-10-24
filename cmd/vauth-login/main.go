// Command vauth-login authenticates to Vault and writes the token to stdout.
package main

import (
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	vauthlogin "github.com/131/vauth-login"
)

const usage = "Usage: vauth-login [--renew] [--version] [--help]\n"

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

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(argv []string) error {
	var renew, help, showVersion bool
	for _, arg := range argv {
		switch arg {
		case "--renew":
			renew = true
		case "--help":
			help = true
		case "--version":
			showVersion = true
		default:
			return fmt.Errorf("%s", strings.TrimSpace(usage))
		}
	}
	if help {
		_, err := fmt.Fprint(os.Stdout, usage)
		return err
	}
	if showVersion {
		_, err := fmt.Fprintln(os.Stdout, strings.TrimPrefix(buildVersion(), "v"))
		return err
	}
	vauthlogin.Version = buildVersion()
	v, err := vauthlogin.New()
	if err != nil {
		return err
	}
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
