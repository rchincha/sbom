package cli

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"stackerbuild.io/stacker-bom/pkg/fs"
)

/*
build --name <doc> --pkgname <pkg> --pkgversion <version> --license <license> \
--dir dir1 --dir dir2 ... \
--file file1 --file file2 ... \
-o <output-file>.
*/
func BuildCmd() *cobra.Command {
	output := ""
	name := ""
	pkgname := ""
	pkgversion := ""
	dirs := []string{}
	files := []string{}

	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build a SBOM from project dir(s)/file(s) on the filesystem",
		Long:  "Build a SBOM from project dir(s)/file(s) on the filesystem",
		Run: func(cmd *cobra.Command, args []string) {
			if Verbose {
				zerolog.SetGlobalLevel(zerolog.DebugLevel)
			}

			log.Info().Interface("dirs", dirs).Msg("dir")

			if err := fs.BuildPackage(dirs, files, output, name,
				Author, Organization, License, pkgname, pkgversion,
			); err != nil {
				log.Error().Err(err).Msg("build failed")
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringSliceVarP(&dirs, "dir", "d", []string{},
		"dir(s) to be included in this package (arg can be used multiple times)")
	cmd.Flags().StringSliceVarP(&files, "file", "f", []string{},
		"file(s) to be included in this package (arg can be used multiple times)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file")
	_ = cmd.MarkFlagRequired("output")
	cmd.Flags().StringVarP(&License, "license", "", "", "set license of this SBOM document")
	cmd.Flags().StringVarP(&pkgname, "pkgname", "", "", "set package name of this SBOM document")
	cmd.Flags().StringVarP(&name, "name", "", "", "set name of this SBOM document")
	cmd.Flags().StringVarP(&pkgversion, "pkgversion", "", "", "set package version of this SBOM document")

	return cmd
}
