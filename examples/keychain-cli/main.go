package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	keychain "github.com/lox/keyring-keychain"
	"github.com/lox/keyring/v2"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("keychain-cli", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	service := flags.String("service", "keyring-keychain-example", "keychain service name")
	dataProtection := flags.Bool("data-protection", false, "use the macOS data-protection keychain")
	userPresence := flags.Bool("user-presence", false, "require Touch ID or device password for reads")
	biometry := flags.Bool("biometry-current-set", false, "require the current Touch ID enrollment for reads")
	reuse := flags.Duration("reuse", 0, "reuse recent authentication, for example 30s")
	flags.Usage = func() {
		_, _ = fmt.Fprintln(flags.Output(), "usage: keychain-cli [flags] set <key> <value>")
		_, _ = fmt.Fprintln(flags.Output(), "       keychain-cli [flags] get <key>")
		_, _ = fmt.Fprintln(flags.Output(), "       keychain-cli [flags] remove <key>")
		_, _ = fmt.Fprintln(flags.Output(), "       keychain-cli [flags] keys")
		_, _ = fmt.Fprintln(flags.Output())
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	opts := []keychain.Option{}
	if *dataProtection {
		opts = append(opts, keychain.DataProtection())
	}
	if *userPresence {
		opts = append(opts, keychain.RequireUserPresence())
	}
	if *biometry {
		opts = append(opts, keychain.RequireBiometryCurrentSet())
	}
	if *reuse > 0 {
		opts = append(opts, keychain.AuthenticationReuse(*reuse))
	}

	ring, err := keyring.Open(ctx,
		keyring.WithServiceName(*service),
		keyring.WithProvider(keychain.Provider(opts...)),
	)
	if err != nil {
		return err
	}
	defer closeRing(ring)

	rest := flags.Args()
	if len(rest) == 0 {
		flags.Usage()
		return errors.New("missing command")
	}

	switch rest[0] {
	case "set":
		if len(rest) != 3 {
			return errors.New("usage: set <key> <value>")
		}
		return ring.Set(ctx, keyring.Item{Key: rest[1], Data: []byte(rest[2]), Label: rest[1]})
	case "get":
		if len(rest) != 2 {
			return errors.New("usage: get <key>")
		}
		item, err := ring.Get(ctx, rest[1])
		if err != nil {
			return err
		}
		fmt.Println(string(item.Data))
	case "remove":
		if len(rest) != 2 {
			return errors.New("usage: remove <key>")
		}
		return ring.Remove(ctx, rest[1])
	case "keys":
		if len(rest) != 1 {
			return errors.New("usage: keys")
		}
		keys, err := ring.Keys(ctx)
		if err != nil {
			return err
		}
		for _, key := range keys {
			fmt.Println(key)
		}
	default:
		return fmt.Errorf("unknown command %q", rest[0])
	}

	return nil
}

func closeRing(ring keyring.Keyring) {
	closer, ok := ring.(io.Closer)
	if ok {
		_ = closer.Close()
	}
}
