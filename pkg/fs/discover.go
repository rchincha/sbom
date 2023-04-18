package fs

import (
	"github.com/rs/zerolog/log"
	"stackerbuild.io/stacker-bom/pkg/bom"
	"stackerbuild.io/stacker-bom/pkg/distro"
)

// Discover everything from a filesystem.
func Discover(author, organization, output string) error {
	doc := bom.NewDocument(author, organization)

	if err := distro.InstalledPackages(doc); err != nil {
		log.Error().Err(err).Msg("unable to check installed packages")

		return err
	}

	if err := bom.WriteDocument(doc, output); err != nil {
		log.Error().Err(err).Str("path", output).Msg("unable to write output")

		return err
	}

	return nil
}
