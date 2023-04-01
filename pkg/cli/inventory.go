package cli

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"stackerbuild.io/stacker-bom/pkg/fs"
)

// inventory -d <input-dir> -o <output-file.
func InventoryCmd() *cobra.Command {
	dir := ""
	output := ""
	exclude := []string{}

	cmd := &cobra.Command{
		Use:   "inventory",
		Short: "Inventory a filesystem recursively",
		Long:  "Inventory a filesystem recursively",
		Run: func(cmd *cobra.Command, args []string) {
			if Verbose {
				zerolog.SetGlobalLevel(zerolog.DebugLevel)
			}

			if err := fs.GenerateInventory(dir, exclude, output); err != nil {
				log.Error().Err(err).Msg("verify failed")
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVarP(&dir, "dir", "d", "/", "root directory to begin inventory")
	cmd.Flags().StringVarP(&output, "output-file", "o", "", "output inventory file")
	_ = cmd.MarkFlagRequired("output-file")
	cmd.Flags().StringSliceVarP(&exclude, "exclude-dir", "x",
		[]string{"/proc", "/sys", "/dev"}, "directories excluded for inventory")

	return cmd
}
