package dtoerr

import "ruehrstaat-backend/errors"

var ErrPackageDTO = errors.NewPackage("DTO", "DTO")

var (
	NoIdProvided = errors.New(2001, *ErrPackageDTO, 400, "", "no ID provided")
	InvalidId    = errors.New(1001, *ErrPackageDTO, 400, "", "invalid ID")
	InvalidDTO   = errors.NewWithInternalMessage(1002, *ErrPackageDTO, 400, "", "Given data is invalid", "Invalid DTO data, in sentry see above error for additional details.")
)
