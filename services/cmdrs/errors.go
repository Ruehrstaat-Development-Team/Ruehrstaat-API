package cmdrs

import "ruehrstaat-backend/errors"

var ErrPackageCmdrs = errors.NewPackage("Cmdrs", "CMD")

// codes
// 1xxx - invalid something
// 2xxx - not found
// 3xxx - already done / exists
// 4xxx - forbidden
// 5xxx - server error

// 9xxx - other
// 9999 - unknown error

var (
	ErrInternalServerError = errors.NewWithInternalMessage(5010, *ErrPackageCmdrs, 500, "", "Internal Server Error", "In sentry there might be a more detailed error above")
)
