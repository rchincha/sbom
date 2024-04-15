package fs

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog/log"
	"sigs.k8s.io/bom/pkg/spdx"
	"stackerbuild.io/stacker-bom/errors"
	"stackerbuild.io/stacker-bom/pkg/bom"
)

func checkBOM(input, pathEntry string) error {
	doc, err := spdx.OpenDoc(input)
	if err != nil {
		log.Error().Err(err).Str("path", input).Msg("unable to open SBOM")

		return err
	}

	if doc == nil {
		log.Error().Str("path", input).Msg("invalid SBOM document")

		return fmt.Errorf("%w: %s", errors.ErrInvalidDoc, input)
	}

	for _, pkg := range doc.Packages {
		for _, file := range pkg.Files() {
			symlink, err := filepath.EvalSymlinks(file.Name)
			if err != nil {
				log.Error().Err(err).Str("path", file.Name).Str("package", pkg.Name).Msg("unable to resolve symlink")

				return err
			}

			if file.Name != pathEntry && symlink != pathEntry {
				continue
			}

			file.Entity.Opts = &spdx.ObjectOptions{}

			if err := file.ReadSourceFile(file.Name); err != nil {
				log.Error().Err(err).Str("path", file.Name).Msg("doesn't match entry in SBOM document")

				return err
			}

			log.Info().Str("file", pathEntry).Str("package", pkg.Name).Str("version", pkg.Version).Msg("package found for file")

			return nil
		}
	}

	for _, file := range doc.Files {
		symlink, err := filepath.EvalSymlinks(file.Name)
		if err != nil {
			log.Error().Err(err).Str("path", file.Name).Msg("unable to resolve symlink")

			return err
		}

		if file.FileName != pathEntry && file.FileName != symlink {
			continue
		}

		file.Entity.Opts = &spdx.ObjectOptions{}

		if err := file.ReadSourceFile(file.FileName); err != nil {
			log.Error().Err(err).Str("path", file.FileName).Msg("doesn't match entry in SBOM document")

			return err
		}

		log.Info().Str("file", pathEntry).Msg("standalone file found")

		return nil
	}

	return fmt.Errorf("%w: %s", errors.ErrNotFound, pathEntry)
}

func Verify(input, inventory, missing string) error {
	inv, err := ReadInventory(inventory)
	if err != nil {
		log.Error().Err(err).Str("path", inventory).Msg("unable to open inventory")

		return err
	}

	mdoc := bom.NewDocument("", "")
	mdoc.Name = "missing-files-document"

	var mdocMtx sync.Mutex

	var mcount atomic.Uint64

	backlog := 1024
	tpool := NewThreadPool(runtime.NumCPU(), backlog)

	for _, entry := range inv.Entries {
		mode, err := strconv.ParseInt(entry.Mode, 8, 32)
		if err != nil {
			log.Error().Err(err).Str("path", entry.Path).Str("mode", entry.Mode).Msg("unable to parse file mode")

			return err
		}

		if !os.FileMode(mode).IsRegular() {
			continue
		}

		tpool.Add(
			func(entry Entry) func() error {
				taskfn := func() error {
					if err := checkBOM(input, entry.Path); err != nil {
						log.Error().Err(err).Str("path", entry.Path).Interface("entry", entry).Msg("inventory verify failed")

						mcount.Add(1)

						sfile := spdx.NewFile()
						sfile.SetEntity(
							&spdx.Entity{
								Name:     entry.Path,
								Checksum: map[string]string{"SHA256": strings.Split(entry.Checksum, ":")[1]},
							},
						)

						mdocMtx.Lock()
						err := mdoc.AddFile(sfile)
						mdocMtx.Unlock()

						if err != nil {
							log.Error().Err(err).Msg("unable to add file to package")

							return err
						}
					}

					return nil
				}

				return taskfn
			}(entry),
		)
	}

	// finish with the threadpool
	if err := tpool.Done(); err != nil {
		log.Error().Err(err).Msg("threadpool failed")

		return err
	}

	count := mcount.Load()

	if count != 0 {
		if missing != "" {
			if err := bom.WriteDocument(mdoc, missing); err != nil {
				log.Error().Err(err).Str("path", missing).Msg("unable to writing missing entries")

				return err
			}
		}

		return fmt.Errorf("%w: %d entries missing", errors.ErrIncomplete, count)
	}

	return nil
}
