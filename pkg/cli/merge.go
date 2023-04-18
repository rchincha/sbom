package cli

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"stackerbuild.io/stacker-bom/pkg/bom"
)

/*
stacker-bom merge --dir <bom-dir> --output <merged bom-file> --name <doc-name>
*/

func MergeCmd() *cobra.Command {
	dir := ""
	output := ""
	name := ""

	cmd := &cobra.Command{
		Use:   "merge",
		Short: "Merge SBOM files",
		Long:  "Merge SBOM files",
		Run: func(cmd *cobra.Command, args []string) {
			if Verbose {
				zerolog.SetGlobalLevel(zerolog.DebugLevel)
			}

			if err := bom.MergeDocuments(dir, name, Author, Organization, output); err != nil {
				log.Error().Err(err).Msg("merge failed")
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVarP(&dir, "dir", "d", "", "directory containing SBOM files")
	_ = cmd.MarkFlagRequired("dir")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output SBOM file")
	_ = cmd.MarkFlagRequired("output")
	cmd.Flags().StringVarP(&name, "name", "n", "", "document name of output SBOM file")
	_ = cmd.MarkFlagRequired("name")

	return cmd
}
