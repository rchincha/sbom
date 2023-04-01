package cli

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"stackerbuild.io/stacker-bom/pkg/fs"
)

/*
discover -o <>
*/

func DiscoverCmd() *cobra.Command {
	author := ""
	organization := ""
	output := ""

	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Discover all installed packages from well-known locations",
		Long:  "Discover all installed packages from well-known locations",
		Run: func(cmd *cobra.Command, args []string) {
			if Verbose {
				zerolog.SetGlobalLevel(zerolog.DebugLevel)
			}

			if err := fs.Discover(author, organization, output); err != nil {
				log.Error().Err(err).Msg("discover failed")
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVarP(&output, "output-file", "o", "", "output SBOM file")
	_ = cmd.MarkFlagRequired("output-file")

	return cmd
}
