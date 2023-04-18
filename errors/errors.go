package errors

import "errors"

var (
	ErrNotFound    = errors.New("not found")
	ErrInvalidDoc  = errors.New("invalid sbom document")
	ErrIncomplete  = errors.New("incomplete sbom document")
	ErrUnsupported = errors.New("unsupported")
)
