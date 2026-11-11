package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/deepak-muley/k8s-cluster-posture/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		var exit *cli.ExitError
		if errors.As(err, &exit) {
			if exit.Error() != "" {
				fmt.Fprintln(os.Stderr, exit.Error())
			}
			os.Exit(exit.Code)
		}
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(2)
	}
}
