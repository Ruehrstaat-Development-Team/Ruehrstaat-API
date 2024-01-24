package mails

type Mail interface {
	GetSubject(locale string) string
	GetBody(locale string) string
	GetName() string
}
