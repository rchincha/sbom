package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"stackerbuild.io/stacker-bom/pkg/buildgen"
)

//nolint:gochecknoglobals
var (
	Binary       = "stacker-bom"
	Author       string
	Organization string
	License      string
	Verbose      bool
)

func NewRootCmd() *cobra.Command {
	showVersion := false

	cmd := &cobra.Command{
		Use:   Binary,
		Short: Binary,
		Long:  Binary,
		Run: func(cmd *cobra.Command, args []string) {
			if showVersion {
				var version string
				if buildgen.ReleaseTag != "" {
					version = buildgen.ReleaseTag
					fmt.Printf("%s\n", version)
				} else {
					version = buildgen.Commit
					fmt.Printf("%s\n", version)
				}
				fmt.Printf("%s", version)
				os.Exit(0)
			}

			_ = cmd.Usage()
		},
	}

	cmd.AddCommand(InventoryCmd())
	cmd.AddCommand(DiscoverCmd())
	cmd.AddCommand(BuildCmd())
	cmd.AddCommand(GenerateCmd())
	cmd.AddCommand(VerifyCmd())
	cmd.AddCommand(MergeCmd())
	cmd.Flags().BoolVarP(&showVersion, "version", "v", false, "show the version and exit")
	cmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "", false, "verbose output")
	cmd.Flags().StringVarP(&Author, "author", "", "", "set author of this SBOM document")
	cmd.Flags().StringVarP(&Organization, "organization", "", "", "set organization of this SBOM document")

	return cmd
}
