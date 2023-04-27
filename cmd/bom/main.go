package main

import (
	"os"

	zlog "github.com/rs/zerolog/log"
	"stackerbuild.io/stacker-bom/pkg/cli"
	"stackerbuild.io/stacker-bom/pkg/log"
)

func main() {
	log.SetLevel(log.InfoLevel)

	if err := cli.NewRootCmd().Execute(); err != nil {
		zlog.Error().Err(err).Msg("action failed")
		os.Exit(1)
	}
}
