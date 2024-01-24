package dtoerr

import "errors"

var (
	NoIdProvided = errors.New("no ID provided")
	InvalidId    = errors.New("invalid ID")
	InvalidDTO   = errors.New("invalid DTO data, see above error for details")
)
