package distro

import (
	"fmt"

	"github.com/gabriel-vasile/mimetype"
	"github.com/rs/zerolog/log"
	"sigs.k8s.io/bom/pkg/spdx"
	"stackerbuild.io/stacker-bom/errors"
	"stackerbuild.io/stacker-bom/pkg/distro/deb"
)

type Distro interface {
	InstalledPackages() (*spdx.Document, error)
}

func InstalledPackages(doc *spdx.Document) error {
	err := deb.InstalledPackages(doc)
	if err != nil {
		log.Error().Err(err).Msg("unable to get installed packages")

		return err
	}

	return nil
}

func ParsePackage(input, output, author, organization, license string) error {
	mtype, err := mimetype.DetectFile(input)
	if err != nil {
		log.Error().Err(err).Msg("failed to detect mime-type")

		return err
	}

	log.Info().Str("path", input).Str("mime-type", mtype.String()).Msg("mime-type detected")

	switch mtype.String() {
	case "application/vnd.debian.binary-package":
		return deb.ParsePackage(input, output, author, organization, license)
	default:
		return fmt.Errorf("%w: mime-type %s", errors.ErrUnsupported, mtype.String())
	}
}
