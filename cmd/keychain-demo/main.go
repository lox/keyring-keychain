// Command keychain-demo is a small CLI for exercising the keyring-keychain
// provider, including Touch ID protected items.
//
//	echo -n hunter2 | go run ./cmd/keychain-demo set llamas
//	go run ./cmd/keychain-demo get llamas
//
//	echo -n hunter2 | go run ./cmd/keychain-demo -touchid set llamas
//	go run ./cmd/keychain-demo get llamas   # prompts Touch ID
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	keychain "github.com/lox/keyring-keychain"
	"github.com/lox/keyring/v2"
)

const usage = `Usage: %s [flags] <command>

Commands:
  set <key>    store a secret read from stdin
  get <key>    print a secret to stdout
  ls           list keys
  rm <key>     remove a key
  available    report whether Touch ID is available

Flags:
`

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("keychain-demo", flag.ContinueOnError)
	var (
		service = fs.String("service", "keyring-keychain-demo", "keychain service name")
		name    = fs.String("keychain", "", "custom keychain name (default: the login keychain)")
		touchID = fs.Bool("touchid", false, "protect items with Touch ID (Secure Enclave)")
		reason  = fs.String("reason", "", "reason shown in the Touch ID prompt")
		policy  = fs.String("policy", "userpresence", "touch id policy: userpresence, biometry, or biometry-current")
		trust   = fs.Bool("trust", true, "trust this binary to read its items without an ACL prompt")
		debug   = fs.Bool("debug", false, "enable keyring debug logging")
	)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), usage, fs.Name())
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return errors.New("missing command")
	}

	cmd, rest := fs.Arg(0), fs.Args()[1:]

	if cmd == "available" {
		fmt.Println(keychain.TouchIDAvailable())
		return nil
	}

	keyring.Debug = *debug

	opts := []keychain.Option{keychain.TrustApplication(*trust)}
	if *name != "" {
		opts = append(opts, keychain.Name(*name))
	}
	if *touchID {
		p, err := parsePolicy(*policy)
		if err != nil {
			return err
		}
		opts = append(opts, keychain.TouchID(keychain.TouchIDConfig{Reason: *reason, Policy: p}))
	}

	ring, err := keyring.Open(ctx,
		keyring.WithServiceName(*service),
		keyring.WithProvider(keychain.Provider(opts...)),
	)
	if err != nil {
		return fmt.Errorf("opening keyring: %w", err)
	}
	defer func() {
		if closer, ok := ring.(io.Closer); ok {
			_ = closer.Close()
		}
	}()

	switch cmd {
	case "set":
		key, err := requireKey(rest)
		if err != nil {
			return err
		}
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("reading secret from stdin: %w", err)
		}
		return ring.Set(ctx, keychain.Item{
			Key:   key,
			Data:  data,
			Label: fmt.Sprintf("%s.%s", *service, key),
		})
	case "get":
		key, err := requireKey(rest)
		if err != nil {
			return err
		}
		item, err := ring.Get(ctx, key)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(item.Data)
		return err
	case "ls":
		keys, err := ring.Keys(ctx)
		if err != nil {
			return err
		}
		sort.Strings(keys)
		for _, key := range keys {
			fmt.Println(key)
		}
		return nil
	case "rm":
		key, err := requireKey(rest)
		if err != nil {
			return err
		}
		return ring.Remove(ctx, key)
	default:
		fs.Usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func requireKey(args []string) (string, error) {
	if len(args) != 1 {
		return "", errors.New("expected exactly one <key> argument")
	}
	return args[0], nil
}

func parsePolicy(s string) (keychain.TouchIDPolicy, error) {
	switch s {
	case "userpresence":
		return keychain.TouchIDPolicyUserPresence, nil
	case "biometry":
		return keychain.TouchIDPolicyBiometryAny, nil
	case "biometry-current":
		return keychain.TouchIDPolicyBiometryCurrentSet, nil
	default:
		return 0, fmt.Errorf("unknown policy %q (want userpresence, biometry, or biometry-current)", s)
	}
}
