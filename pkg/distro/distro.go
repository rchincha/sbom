package distro

import (
	"fmt"

	"github.com/gabriel-vasile/mimetype"
	"github.com/rs/zerolog/log"
	"sigs.k8s.io/bom/pkg/spdx"
	"stackerbuild.io/stacker-bom/errors"
	"stackerbuild.io/stacker-bom/pkg/distro/apk"
	"stackerbuild.io/stacker-bom/pkg/distro/deb"
	"stackerbuild.io/stacker-bom/pkg/distro/rpm"
)

type Distro interface {
	InstalledPackages() (*spdx.Document, error)
}

func InstalledPackages(doc *spdx.Document) error {
	deberr := deb.InstalledPackages(doc)
	if deberr != nil {
		log.Error().Err(deberr).Msg("deb: unable to get installed packages")
	}

	rpmerr := rpm.InstalledPackages(doc)
	if rpmerr != nil {
		log.Error().Err(rpmerr).Msg("rpm: unable to get installed packages")
	}

	apkerr := apk.InstalledPackages(doc)
	if apkerr != nil {
		log.Error().Err(apkerr).Msg("apk: unable to get installed packages")
	}

	if deberr != nil && rpmerr != nil && apkerr != nil {
		return errors.ErrNotFound
	}

	return nil
}

func ParsePackage(input, author, organization, license, output string) error {
	mtype, err := mimetype.DetectFile(input)
	if err != nil {
		log.Error().Err(err).Msg("failed to detect mime-type")

		return err
	}

	log.Info().Str("path", input).Str("mime-type", mtype.String()).Msg("mime-type detected")

	switch mtype.String() {
	case "application/vnd.debian.binary-package":
		return deb.ParsePackage(input, output, author, organization, license)
	case "application/x-rpm":
		return rpm.ParsePackage(input, output, author, organization, license)
	case "application/gzip": // best effort
		return apk.ParsePackage(input, output, author, organization, license)
	default:
		return fmt.Errorf("%w: mime-type %s", errors.ErrUnsupported, mtype.String())
	}
}
