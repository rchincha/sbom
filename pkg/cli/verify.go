package cli

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"stackerbuild.io/stacker-bom/pkg/fs"
)

/*
stacker-bom verify --input <bom-file> --inventory <inventory-file>
*/

func VerifyCmd() *cobra.Command {
	input := ""
	inventory := ""
	missing := ""

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a filesystem layout against a SBOM file",
		Long:  "Verify a filesystem layout against a SBOM file",
		Run: func(cmd *cobra.Command, args []string) {
			if Verbose {
				zerolog.SetGlobalLevel(zerolog.DebugLevel)
			}

			if err := fs.Verify(input, inventory, missing); err != nil {
				log.Error().Err(err).Msg("verify failed")
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVarP(&input, "input", "i", "", "input SBOM file")
	_ = cmd.MarkFlagRequired("input")
	cmd.Flags().StringVarP(&inventory, "inventory", "t", "", "input inventory file")
	_ = cmd.MarkFlagRequired("inventory")
	cmd.Flags().StringVarP(&missing, "missing", "m", "", "a output SBOM file with missing entries")

	return cmd
}
