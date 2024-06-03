package carrier

import "ruehrstaat-backend/errors"

var ErrPackageCarrier = errors.NewPackage("Carrier", "C")

// codes
// 1xxx - invalid something
// 2xxx - not found
// 3xxx - already done / exists
// 4xxx - forbidden
// 5xxx - server error

// 9xxx - other
// 9999 - unknown error

var (
	ErrBadRequest             = errors.NewWithInternalMessage(1001, *ErrPackageCarrier, 400, "", "Bad Request", "In sentry there might be a more detailed error above")
	ErrInvalidUserId          = errors.New(1002, *ErrPackageCarrier, 400, "", "Invalid User ID")
	ErrInvalidDockingAccess   = errors.New(1003, *ErrPackageCarrier, 400, "", "Invalid Docking Access")
	ErrInvalidCarrierId       = errors.New(1004, *ErrPackageCarrier, 400, "", "Invalid Carrier ID")
	ErrInvalidCategory        = errors.New(1005, *ErrPackageCarrier, 400, "", "Invalid Category")
	ErrInvalidCarrierServices = errors.New(1006, *ErrPackageCarrier, 400, "", "Invalid Carrier Services")

	ErrCarrierNotFound        = errors.New(2001, *ErrPackageCarrier, 404, "", "Carrier not found")
	ErrCarrierServiceNotFound = errors.New(2002, *ErrPackageCarrier, 404, "", "Carrier Service not found")

	ErrCarrierAlreadyExists = errors.New(3001, *ErrPackageCarrier, 409, "", "Carrier with same name or callsign already exists")

	ErrForbidden    = errors.New(4000, *ErrPackageCarrier, 403, "", "Forbidden")
	ErrUnauthorized = errors.New(4001, *ErrPackageCarrier, 401, "", "Unauthorized")

	ErrInternalServerError = errors.NewWithInternalMessage(5001, *ErrPackageCarrier, 500, "", "Internal Server Error", "In sentry there might be a more detailed error above")
)
