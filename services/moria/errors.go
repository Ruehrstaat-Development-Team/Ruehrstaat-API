package moria

import "ruehrstaat-backend/errors"

var moriaErrPackage = errors.NewPackage("Moria", "moria")

var (
	ErrMoriaUrlEmpty       = errors.New(1051, *moriaErrPackage, 400, "", "Moria URL is empty")
	ErrMoriaInitTokenEmpty = errors.New(1052, *moriaErrPackage, 400, "", "Moria init token is empty")

	ErrMoriaDisabled = errors.New(1059, *moriaErrPackage, 400, "", "Moria is disabled")
)
