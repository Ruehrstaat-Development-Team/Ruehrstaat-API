package mails

import (
	"os"

	"github.com/google/uuid"
)

type PasswordResetMail struct {
	UserID   uuid.UUID
	Totp     bool
	Email    string
	Nickname string
	Token    string
}

func (m PasswordResetMail) GetSubject(locale string) string {
	switch locale {
	case "de":
		return "Setze dein Ruehrstaat-Passwort zurück"
	default:
		return "Reset your Ruehrstaat password"
	}
}

func (m PasswordResetMail) GetBody(locale string) string {
	link := os.Getenv("FRONTEND_URL") + "/reset-password/" + m.UserID.String() + "?reset=" + m.Token + "&totp=" + (map[bool]string{true: "true", false: "false"}[m.Totp])
	switch locale {
	case "de":
		return "Um dein Passwort zurückzusetzen, klicke bitte auf den folgenden Button: \n<a href=\"" + link + "\">Jetzt zurücksetzen!</a>\n\nFalls dieser nicht geht, versuche diesen Link:\n<a href=\"" + link + "\">" + link + "</a>\nWichtig: Dieser Link läuft nach 1 Stunde ab!"
	default:
		return "To reset your password, please click the following button: \n<a href=\"" + link + "\">Reset now!</a>\n\nIf this does not work, try this link:\n<a href=\"" + link + "\">" + link + "</a>\nImportant: This link expires after 1 hour!"
	}
}

func (m PasswordResetMail) GetName() string {
	return m.Nickname
}
