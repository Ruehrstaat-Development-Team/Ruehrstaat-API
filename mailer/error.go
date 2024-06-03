package mailer

import "ruehrstaat-backend/errors"

var ErrPackageMailer = errors.NewPackage("Mailer", "Mail")

var (
	ErrFailedToSendEmail = errors.New(5001, *ErrPackageMailer, 500, "", "Failed to send email")
)
